from __future__ import annotations

import json
import math
import os
import re
import time
from collections.abc import Callable
from typing import Any
from urllib import error, request

from ..models import AiBehavior, AiConfigStatus, AnalysisResult, StructuredVerdict
from ..runtime_paths import env_files
from . import ai_metrics, evidence_value
from .agent_tools import AGENT_TOOLS, execute_tool
from .detector import detect_events_with_coverage
from .rules import rule_objects
from .sanitizer import sanitize_records, sanitize_text, slim_records
from .threat_intel import AI_CONTEXT_INDICATOR_LIMIT, cached_report

# 研判质量优先于耗时：以下三个上限都可通过环境变量放宽，默认值给足余量，
# 避免「证据还没读完、结论还没写完就被掐断」——准确的结论比快速返回更重要。
DEFAULT_TOOL_ROUNDS = 4
DEFAULT_OUTPUT_TOKENS = 4096
DEFAULT_TIMEOUT_SECONDS = 300

# 每轮研判先确定性执行的工具（AGENTS.md §7：确定类型 → 取统计 → 查事件 → 取证 → 建时间线）
AUTO_TOOL_PLAN: tuple[tuple[str, dict[str, Any]], ...] = (
    ("log_metadata", {}),
    ("log_statistics", {}),
    ("query_events", {"limit": 10}),
    ("timeline", {"limit": 15}),
)

IP_PATTERN = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
RECORD_PATTERN = re.compile(r"\brecord-\d+\b")

SYSTEM_PROMPT = """你是安全日志分析专家；只依据本次日志、事件、脱敏证据研判可疑行为。
边界：不得执行系统操作；不得攻击/扫描/利用/修改系统。
证据规则：禁止编造日志中不存在的 IP/账户/时间/行为；无法确认时必须明确说明无法确认。规则未命中不等于正常；未覆盖也不得当正常。
数量规则：records/events 都可能是分层样本，不得用样本条数代替总体；总量以 metadata/statistics/*_note 为准。缺证据时调用只读工具，尤其 query_records；证据不足就留空。
引用规则：behaviors[].evidence_ids 只填真实 evidence_id（evidence-* 或 evidence-record-*）。tool_results 是确定性工具结果，可作事实；terminal_chains 只是辅助视图。
输出要短：summary/analysis 写结论和依据，避免复述字段；behaviors 最多 5 项，evidence/recommendations 各最多 5 条。
只返回 JSON，字段和层级固定，不得自创字段：
{"has_suspicious_behavior":true,"risk_level":"high","confidence":0.9,"summary":"","behaviors":[{"type":"","name":"","confidence":0.9,"evidence":[],"evidence_ids":[],"analysis":""}],"recommendations":[],"structured":{"event_time":"","attack_source_ip":"","target_asset":"","involved_account":"","abnormal_behavior":"","related_logs":[],"attack_type":"","risk_level":"high","judgment_basis":"","success_indicator":"","recommended_actions":[]}}
structured 必须含 11 键：event_time / attack_source_ip / target_asset / involved_account / abnormal_behavior / related_logs / attack_type / risk_level / judgment_basis / success_indicator / recommended_actions；未知用空串或空数组。"""


def _setting(name: str, default: str = "") -> str:
    value = os.getenv(name)
    if value:
        return value
    for env_path in env_files():
        if not env_path.exists():
            continue
        for line in env_path.read_text(encoding="utf-8").splitlines():
            if line.strip().startswith(f"{name}="):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    return default


# 当前请求的记录规模，用于按日志大小自适应超时与工具轮次。
# 只影响「超时给多长」这一件事，多请求并发时最多是给得宽一点，不会影响结果正确性。
_ACTIVE_RECORD_COUNT = 0
# 当前请求的事件数量：为 0 表示这份日志没有命中任何线索，用于把工具轮次收到 1。
_ACTIVE_EVENT_COUNT = 0


def _effective_timeout() -> float:
    """按日志规模自适应单次请求超时。

    未显式配置 AI_TIMEOUT_SECONDS 时，超大日志自动放宽——证据越多，
    模型读完并写出结论需要的轮次与时间越长，按固定秒数掐断会牺牲准确性。
    """

    configured = _setting("AI_TIMEOUT_SECONDS", "").strip()
    if configured:
        return float(configured)
    if _ACTIVE_RECORD_COUNT >= LARGE_LOG_RECORDS:
        return DEFAULT_TIMEOUT_SECONDS * 2
    return DEFAULT_TIMEOUT_SECONDS


def _effective_tool_rounds() -> int:
    """工具轮次同样按规模自适应；显式配置优先。

    分档的出发点是**成本与收益对称**：
    - 没有命中任何事件、覆盖也完整时，模型手上没有需要深挖的线索，
      再给它追加工具调用只会把整份上下文重复发送若干遍——直接收在 1 轮；
    - 有事件但不多时按默认轮次；
    - 大日志（事件与记录都多）才放宽到默认的 2 倍。
    """

    configured = _setting("AI_MAX_TOOL_ROUNDS", "").strip()
    if configured:
        try:
            value = int(configured)
        except ValueError:
            value = 0
        if value > 0:
            return value
    if not _ACTIVE_EVENT_COUNT:
        return CLEAN_LOG_TOOL_ROUNDS
    if _ACTIVE_RECORD_COUNT >= LARGE_LOG_RECORDS:
        return DEFAULT_TOOL_ROUNDS * 2
    return DEFAULT_TOOL_ROUNDS


def _int_setting(name: str, default: int) -> int:
    """读取正整数配置；非法值或非正值回退默认值，避免 0/负数把上限变成「立即中断」。"""

    try:
        value = int(_setting(name, str(default)).strip())
    except ValueError:
        return default
    return value if value > 0 else default


# 采样上限：日志越大给得越多，但有上限，避免把上下文撑爆
SAMPLE_LIMIT_DEFAULT = 200
SAMPLE_LIMIT_LARGE = 500
# 轻量模式的记录样本配额：无事件且覆盖完整时只需「看一眼整体形态」，
# 配额再大也只是重复同样的判断；需要细节由模型调 query_records 取。
LIGHT_SAMPLE_LIMIT = 60
# 已经有规则事件时，事件证据是主要研判材料，普通记录只保留少量形态样本。
EVENT_RECORD_SAMPLE_LIMIT = 80
# 上下文中的原文只用于快速判断；完整原文通过 query_evidence / query_records 按需取得。
AI_RAW_TEXT_LIMIT = 640
LARGE_LOG_RECORDS = 20000
# 无事件时的轮次上限：没有线索就没有深挖的必要，收在 1 轮避免整份上下文重复发送
CLEAN_LOG_TOOL_ROUNDS = 1
# 首轮 user 消息超过该体积才做「历史摘要占位」替换：小上下文重发成本本来就低，
# 替换反而可能让模型丢细节，因此只对大块头动手。
_HISTORY_SHRINK_THRESHOLD = 20_000
# 分层维度：覆盖面优先（来源 → 目标 → 账号 → 结果码 → 动作 → 路径 / 进程 / 文件 / 域名）
# 事件上下文上限：曾把全部事件塞进上下文，域控导出 3955 个事件 → 上下文 14.5 MB
# ≈ 798 万 tokens，被服务端以「maximum context length is 1048576 tokens」拒绝（HTTP 400）。
# 因此与记录样本同理：按维度分层抽取代表性子集，并在 note 里写明总数与补查方式。
EVENT_SAMPLE_LIMIT = 80
EVENT_EVIDENCE_ITEM_LIMIT = 5
EVENT_EVIDENCE_LIMIT = 8
EVENT_TIMELINE_LIMIT = 5
RISK_SCORE_LIMIT = 50
AI_CONTEXT_MAX_BYTES_DEFAULT = 2_000_000
EVENT_STRATA_FIELDS = ("rule_id", "risk_level", "type", "source_ip")

#: 「高风险」档位。用于两处：攻击链端点的判定，以及「高风险事件是否被抽样丢掉」的计数
#: （P4 ④：压缩不得静默丢掉高风险证据）。
HIGH_RISK_LEVELS = frozenset({"critical", "high"})

#: 高风险事件的证据召回底线（P4 ④）。低于它说明压缩把高风险证据漏掉了，
#: 触发一次自动降级（补回被抽掉的高风险事件）。
#: 0.9 而不是 1.0：允许丢掉一成，是因为把每个高风险事件都塞回来会在
#: 「高风险事件数远大于抽样上限」时把上下文撑爆；留一点余量让降级仍受预算约束。
EVIDENCE_RECALL_FLOOR = 0.9

#: 自动降级后的事件数硬上限。降级是「更完整的档位」，不是「不设上限」——
#: 没有这个上限，降级逻辑本身就成了绕过预算守卫的后门。
EVENT_SAMPLE_HARD_MAX = 200

SAMPLE_STRATA_FIELDS = (
    "source_ip",
    "target_asset",
    "username",
    "status",
    "action",
    "url",
    "process_image",
    "target_filename",
    "query_name",
)


def _sample_limit(record_count: int) -> int:
    return SAMPLE_LIMIT_LARGE if record_count >= LARGE_LOG_RECORDS else SAMPLE_LIMIT_DEFAULT


def _round_robin(buckets: dict[str, list[int]], take: int) -> list[int]:
    """从各分组轮流取，保证「每种形态都露一面」，不被某个高频分组占满。"""

    cursors = dict.fromkeys(buckets, 0)
    picked: list[int] = []
    while len(picked) < take:
        advanced = False
        for key, indexes in buckets.items():
            cursor = cursors[key]
            if cursor >= len(indexes):
                continue
            picked.append(indexes[cursor])
            cursors[key] = cursor + 1
            advanced = True
            if len(picked) >= take:
                break
        if not advanced:
            break
    return picked


def _stratified_sample(
    records: list[dict[str, str | None]], limit: int
) -> list[dict[str, str | None]]:
    """按实体 / 状态码 / 路径 / 进程等维度分层抽样。

    直接 `records[:30]` 是没有代表性的：日志按时间聚簇，前 30 条很可能全来自同一个
    来源、同一类结果，模型据此「泛化」必然是偏的。这里按多个维度分别分组后轮流取，
    维度本身也轮转，让样本覆盖各种形态。
    """

    if len(records) <= limit:
        return records
    picked: list[dict[str, str | None]] = []
    picked_indexes: set[int] = set()
    per_field = max(1, limit // 4)
    for field in SAMPLE_STRATA_FIELDS:
        buckets: dict[str, list[int]] = {}
        for index, record in enumerate(records):
            value = record.get(field)
            if value:
                buckets.setdefault(str(value), []).append(index)
        if len(buckets) < 2:
            continue
        for index in _round_robin(buckets, per_field):
            if index in picked_indexes:
                continue
            picked_indexes.add(index)
            picked.append(records[index])
            if len(picked) >= limit:
                return picked
    # 补足到上限：按原顺序兜底，保持结果可复现
    for index, record in enumerate(records):
        if len(picked) >= limit:
            break
        if index not in picked_indexes:
            picked_indexes.add(index)
            picked.append(record)
    return picked


_RECORD_DIVERSITY_FIELDS = (
    "source_ip",
    "target_ip",
    "username",
    "user",
    "url",
    "path",
    "method",
    "status",
    "process",
    "host",
    "event_type",
)


def _information_gain_sample(
    records: list[dict[str, str | None]], limit: int
) -> list[dict[str, str | None]]:
    """在已有分层样本中优先保留能补充新信息的记录。

    这是成本控制，不参与规则命中或 AI 结论。每条记录只按稳定的结构化字段
    计算增量；原文不参与评分，避免把同一请求的不同文本细节误当成互补证据。
    最后恢复原始顺序，保持 prompt 前缀稳定并利于缓存命中。
    """

    if len(records) <= limit:
        return records

    selected: list[int] = []
    seen_values: dict[str, set[str]] = {field: set() for field in _RECORD_DIVERSITY_FIELDS}
    remaining = set(range(len(records)))
    while remaining and len(selected) < limit:
        best_index = min(
            remaining,
            key=lambda index: (
                -sum(
                    bool(record_value := records[index].get(field))
                    and str(record_value) not in seen_values[field]
                    for field in _RECORD_DIVERSITY_FIELDS
                ),
                index,
            ),
        )
        selected.append(best_index)
        remaining.remove(best_index)
        for field in _RECORD_DIVERSITY_FIELDS:
            value = records[best_index].get(field)
            if value:
                seen_values[field].add(str(value))

    return [records[index] for index in sorted(selected)]


def _sample_event_indexes(events: list[Any], limit: int) -> list[int]:
    """按规则 / 风险等级 / 类型 / 来源分层抽取事件下标。

    单一维度抽样会让某个高频规则占满配额（域控导出里同一规则就有上千条），
    因此逐个维度轮流取，保证「每条规则、每类风险都有代表」。
    """

    picked: list[int] = []
    seen: set[int] = set()
    per_field = max(1, limit // len(EVENT_STRATA_FIELDS))
    for field in EVENT_STRATA_FIELDS:
        buckets: dict[str, list[int]] = {}
        for index, event in enumerate(events):
            value = getattr(event, field, None)
            if value:
                buckets.setdefault(str(value), []).append(index)
        if len(buckets) < 2:
            continue
        for index in _round_robin(buckets, per_field):
            if index in seen:
                continue
            seen.add(index)
            picked.append(index)
            if len(picked) >= limit:
                return picked[:limit]
    for index in range(len(events)):
        if len(picked) >= limit:
            break
        if index not in seen:
            seen.add(index)
            picked.append(index)
    return picked[:limit]


#: 事件价值评分（P4 ①）。`_event_value_facts` 一次算好全部事件的事实，
#: 因为「同实体的不同规则命中数」「同实体的时间排序」都需要组内信息。
def _event_group_key(event: Any) -> str:
    """事件归组键。与 `analytics.build_attack_chains` 的归组口径一致：
    优先来源 IP，其次目标资产（主机侧日志没有来源 IP），最后退回规则。
    """

    return (
        event.source_ip
        or event.target_asset
        or f"rule:{event.rule_id or event.type}"
    )


def _event_value_facts(result: AnalysisResult) -> list[evidence_value.EventFacts]:
    """为每个事件算好评分所需的事实。返回顺序与 `result.events` 一一对应。"""

    groups: dict[str, list[Any]] = {}
    for event in result.events:
        groups.setdefault(_event_group_key(event), []).append(event)

    # 规则来源（builtin / sigma）是「来源可靠性」的唯一依据。一次建表，
    # 避免对每个事件都做一次 O(584) 的规则查找。
    sources = {rule.id: rule.source for rule in rule_objects()}

    facts: list[evidence_value.EventFacts] = []
    for event in result.events:
        group = groups[_event_group_key(event)]
        distinct_rules = {item.rule_id for item in group if item.rule_id}
        facts.append(
            evidence_value.EventFacts(
                risk_level=event.risk_level,
                rule_source=sources.get(event.rule_id) if event.rule_id else None,
                distinct_rules_on_entity=max(1, len(distinct_rules)),
                novelty=evidence_value.novelty_rank(
                    event.first_seen, [item.first_seen for item in group]
                ),
                entity_share=evidence_value.entity_correlation(
                    len(event.source_files or []), len(group)
                ),
            )
        )
    return facts


def _chain_endpoint_keys(result: AnalysisResult) -> set[tuple[str | None, str | None, str | None]]:
    """攻击链**首节点与末节点**的标识集合（P4 ②）。

    复用 `analytics.build_attack_chains`，而不是另立一套「关键节点」定义——
    链的首节点是初始访问、末节点是最后成功的行为，两端才是研判的关键，
    中间节点可以靠 `query_evidence` 按需取。

    标识用 (来源 IP, 规则 ID, 首次出现) 三元组：`AttackChainStage` **不带事件 ID、
    也没有 target_asset**，这三项是链与事件上都有的字段。

    **只认 ≥2 个阶段的链**。单阶段链的 `stages[0]` 与 `stages[-1]` 是同一条，
    若也算端点，则每一个孤立事件都会被标成「关键节点」——实测在单实体小日志上
    「关键节点」覆盖率接近 100%，这个标记就完全失去了区分能力。
    一条链至少要有一个「起点」和一个「后续」，端点才有意义。
    """

    from .analytics import build_attack_chains

    keys: set[tuple[str | None, str | None, str | None]] = set()
    for chain in build_attack_chains(result.events, result.entities):
        if len(chain.stages) < 2:
            continue
        for stage in (chain.stages[0], chain.stages[-1]):
            keys.add((stage.source_ip, stage.rule_id, stage.first_seen))
    return keys


def _event_key(event: Any) -> tuple[str | None, str | None, str | None]:
    return (event.source_ip, event.rule_id, event.first_seen)


def _evidence_depth(facts: evidence_value.EventFacts, *, key_node: bool) -> int:
    """按基准档位 + 评分微调算出证据深度（P4 ①②）。

    评分只做 **±1 微调**，不按评分从 0 重新映射深度。原因是风险是本项目的主信号
    （AGENTS.md §8），重新映射会让 critical 事件在其余分量偏低时掉到比 high 还少，
    风险单调性被打破。微调则保留了原行为在「中性评分」下的取值，因此对既有日志
    不产生成本回退。

    攻击链端点（② 的关键节点）**不被降级**——`max(depth, base)`，即关键证据不因
    价值微调而被采样掉。刻意**不**给它全局满额：实测那样会让一条 `low` 端点的
    证据条数超过 `high` 非端点事件，既与「风险是主信号」冲突，又是纯成本上涨。
    端点的价值在于「不被削减」，不在于「拿到比高风险更多的预算」。
    """

    base = _event_evidence_depth(facts.risk_level)
    depth = base + evidence_value.depth_adjustment(score_event_total(facts))
    if key_node:
        depth = max(depth, base)
    return max(1, min(EVENT_EVIDENCE_ITEM_LIMIT, depth))


def score_event_total(facts: evidence_value.EventFacts) -> float:
    return evidence_value.score_event(facts).total


def _records_time_range(records: list[dict[str, str | None]]) -> str:
    """记录的时间跨度，形如 `2026-09-29T09:00:00~2026-09-29T09:30:00`（P4 ⑤）。

    取**全量**记录而非样本：样本的时间跨度天然更窄，用它会让模型低估日志跨度。
    完全没有时间戳时返回 `unknown`——**不猜一个范围出来**（AGENTS.md §16）。
    """

    stamps = sorted(
        str(record.get("timestamp_iso") or record.get("timestamp"))
        for record in records
        if record.get("timestamp_iso") or record.get("timestamp")
    )
    if not stamps:
        return "unknown"
    return f"{stamps[0]}~{stamps[-1]}"


def _event_context(
    event: Any,
    depth: int,
    *,
    value_note: str | None = None,
    value_total: float | None = None,
    key_node: bool = False,
) -> dict[str, Any]:
    """单个事件的上下文形态：证据与时间线都要限条，否则大日志下会成倍膨胀。

    两处去重/分档，都是为了「一份原文只发一次、且按价值付成本」：

    1. `evidence` 与 `evidence_items[].raw` 是同一批原文（构造事件时 evidence 就是取 raw 填的），
       两边都发等于同一段文本进上下文两遍——实测 80 个事件里 306 条 evidence 有 293 条是
       完全重复的 raw。这里只保留 items 窗口之外的那些原文，信息一条不少、体积少约 2 成。
    2. 证据深度由调用方按**价值评分**算好传入（P4 ①），不再是静态查风险表：
       一条位于攻击链起点、被多条规则交叉印证的 medium 事件，比一条孤立的 medium
       命中更值得花预算。评分依据随 `value_score` 一并下发，让「为什么这条只给 1 条证据」
       有答案可查。**证据条目数减少不等于丢证据**：模型需要时可按 `rule_id`
       调 `query_evidence` 取全量（`evidence_count` 给出真实总数）。
    """

    items = event.evidence_items[:depth]
    item_raws = {_compact_context_text(item.raw) for item in items}
    extra_evidence = [
        text
        for text in (
            _compact_context_text(value) for value in event.evidence[:EVENT_EVIDENCE_LIMIT]
        )
        if text not in item_raws
    ]
    return {
        "type": event.type,
        "name": event.name,
        "risk_level": event.risk_level,
        "source_ip": event.source_ip,
        "target_asset": event.target_asset,
        "first_seen": event.first_seen,
        "last_seen": event.last_seen,
        "count": event.count,
        "rule_id": event.rule_id,
        "evidence_count": len(event.evidence_items),
        "evidence": extra_evidence,
        "evidence_items": [
            {
                "id": item.id,
                "record_id": item.record_id,
                "timestamp": item.timestamp,
                "source_file": item.source_file,
                "source_ip": item.source_ip,
                "destination_ip": item.destination_ip,
                "username": item.username,
                "url": item.url,
                "raw": _compact_context_text(item.raw),
            }
            for item in items
        ],
        "timeline": [
            _compact_context_text(item, 240)
            for item in event.timeline[:EVENT_TIMELINE_LIMIT]
        ],
        "summary": _compact_context_text(event.summary, 360),
        "source_files": event.source_files,
        "correlation_basis": event.correlation_basis,
        # 评分依据与「关键节点」标记随事件下发：说明里说得出「为什么这条只给了 N 条证据」。
        # `value_score` 给人看（逐项依据），`value_total` 给预算削减排序用（机器读）。
        # 这两个键**只用于解释与预算分配，不参与研判判定**。
        **({"value_score": value_note, "value_total": value_total} if value_note else {}),
        **({"chain_node": "attack_chain_endpoint"} if key_node else {}),
    }


# 事件证据深度按风险分档：高风险保留完整证据，低风险只留定位线索
_EVENT_EVIDENCE_DEPTH = {
    "critical": EVENT_EVIDENCE_ITEM_LIMIT,
    "high": EVENT_EVIDENCE_ITEM_LIMIT,
    "medium": 3,
    "low": 2,
    "info": 1,
}


def _event_evidence_depth(risk_level: str | None) -> int:
    return _EVENT_EVIDENCE_DEPTH.get(str(risk_level or "").lower(), 2)


def _compact_context_text(value: Any, limit: int = AI_RAW_TEXT_LIMIT) -> str:
    """压缩上下文中的原文，保留首尾以兼顾请求头和结果字段。"""

    text = sanitize_text(str(value or ""))
    if len(text) <= limit:
        return text
    head = max(1, limit - 160)
    return f"{text[:head]}…[已截断]{text[-150:]}"


def _compact_sample_records(
    records: list[dict[str, str | None]], log_type: str | None
) -> list[dict[str, str | None]]:
    """裁剪样本字段和原文；完整记录仍由 query_records/query_evidence 提供。"""

    compacted = slim_records(records, log_type)
    for record in compacted:
        for key in ("raw", "message", "detail"):
            if key in record:
                record[key] = _compact_context_text(record[key])
    return compacted


def _keep_top_value(events: list[dict[str, Any]], keep: int) -> list[dict[str, Any]]:
    """按价值保留前 `keep` 条事件，并**恢复原顺序**（P4 ③）。

    原先按列表位置砍尾巴：砍掉的是哪条取决于分层抽样的顺序，与价值无关——
    一次削减可能正好砍掉唯一的 critical 事件。改为按
    `(是否攻击链端点, value_total)` 排序后取前 N，**关键节点优先保留**。

    恢复原顺序而不是按分数排：同一份日志重复研判时，上下文必须逐字稳定，
    否则 prompt cache 前缀每次都失效（P3-05 §3.8 的缓存收益会被吃掉）。

    **「硬保留」不等于无条件保留**：预算削减是硬上限，突破它会被服务端直接拒绝
    （HTTP 400），那才是真的一条证据都看不到。因此关键节点只是**优先级最高**，
    在极小预算下仍可能被截断——此时 `context_budget_note` 会写明发生过削减。
    """

    if len(events) <= keep:
        return events
    ranked = sorted(
        range(len(events)),
        key=lambda index: (
            events[index].get("chain_node") == "attack_chain_endpoint",
            float(events[index].get("value_total") or 0.0),
        ),
        reverse=True,
    )
    chosen = sorted(ranked[:keep])
    return [events[index] for index in chosen]


def _fit_context_budget(context: dict[str, Any]) -> dict[str, Any]:
    """限制发送给模型的上下文体积，避免不同模型因上下文上限差异直接返回 400。

    注意：调用方必须在挂载**全部**字段之后再调用本函数。`tool_results` 曾在此之后
    才被挂上，导致这部分体积既不参与削减、也不计入硬上限（等于绕过预算）。
    """

    budget = _int_setting("AI_CONTEXT_MAX_BYTES", AI_CONTEXT_MAX_BYTES_DEFAULT)
    def size_bytes(value: dict[str, Any]) -> int:
        return len(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))

    original_size = size_bytes(context)
    if original_size <= budget:
        return context

    reduced = False
    # 说明字段也要占预算，先为它预留空间，避免「缩减后追加说明」再次超限。
    # 预留量按预算比例给（下限 512）：固定 420 在中文说明下并不总是够，会导致
    # 追加 note 之后重新越界——下面的最终循环是兜底，但不该让兜底频繁触发。
    note_reserve = max(512, min(budget // 20, 4096))
    while size_bytes(context) > max(0, budget - note_reserve):
        changed = False
        # events 走价值排序削减，其余两块是记录样本、按位置削减即可
        # （记录样本没有价值评分，位置就是它的抽样口径）。
        events = context.get("events")
        if isinstance(events, list) and len(events) > 10:
            context["events"] = _keep_top_value(events, max(10, len(events) // 2))
            changed = True
            reduced = True
        for key, minimum in (
            ("records_sample", 40),
            ("uncovered_records_sample", 40),
        ):
            values = context.get(key)
            if isinstance(values, list) and len(values) > minimum:
                context[key] = values[: max(minimum, len(values) // 2)]
                changed = True
                reduced = True
        if not changed:
            break

    final_size = size_bytes(context)
    note = (
        f"上下文原始大小约 {original_size} 字节，当前约 {final_size} 字节，"
        f"预算为 {budget} 字节。由于模型上下文兼容性，已自动缩减部分事件或记录样本；"
        "统计总数仍以 totals / note 字段为准，需要细节请调用只读查询工具。"
        if reduced
        else
        f"上下文约 {final_size} 字节，已达到可发送的 {budget} 字节预算。"
    )
    context["context_budget_note"] = note

    # 极小预算下，说明字段或低优先级分析块仍可能把 JSON 推过边界。
    # 按信息价值从低到高删除可选块，绝不发送超过硬上限的请求。
    # tool_results 与 events/样本同源（元数据、统计、事件、时间线都能在上下文里直接读到），
    # 因此排在删减序列靠前的位置：丢掉它只是少一份「重复的副本」，不会丢事实。
    for key in (
        "terminal_chains",
        "tool_results",
        "timeline",
        "entities",
        "templates",
        "risk_scores",
        "uncovered_records_sample",
        "records_sample",
        "events",
    ):
        if size_bytes(context) <= budget:
            break
        context.pop(key, None)
        reduced = True
    # 删块之后若仍越界，说明说明字段本身超预算：说明是纯辅助信息，优先级最低，
    # 收缩为一句短提示再试，而不是直接把整次研判判失败。
    if size_bytes(context) > budget and "context_budget_note" in context:
        context["context_budget_note"] = "上下文过大，已自动裁剪；总数以各字段 note 为准。"
    if size_bytes(context) > budget:
        raise RuntimeError(
            "AI 上下文超过安全发送上限，请减少日志范围或调大 AI_CONTEXT_MAX_BYTES"
        )
    # 最终断言保留在生产路径上，防止后续新增字段绕过预算。
    return context


def _high_risk_evidence_recall(
    result: AnalysisResult, picked: list[int], facts: list[evidence_value.EventFacts]
) -> tuple[int, int]:
    """高风险事件的证据召回：(下发, 可用)（P4 ④）。

    高风险事件（critical/high）的基准档位就是满额，因此它们**不会**被深度截断——
    真正的遗漏只会发生在**事件抽样**这一层：高风险事件被抽样丢掉，它的全部证据
    一起消失。所以这个比值就是「压缩前后证据召回率」在本项目里的实际形态。
    """

    available = 0
    sent = 0
    for index, event in enumerate(result.events):
        if str(event.risk_level) not in HIGH_RISK_LEVELS:
            continue
        available += len(event.evidence_items)
        if index not in picked:
            continue
        sent += min(
            len(event.evidence_items),
            _evidence_depth(facts[index], key_node=False),
        )
    return sent, available


def _is_light_context(result: AnalysisResult) -> bool:
    """判断是否走「轻量上下文」。

    条件：**没有命中任何事件，且检测覆盖完整**。此时没有任何需要深挖的线索，
    再发送大块记录样本与完整事件结构，只是让模型把同样的判断重复读一遍。

    刻意要求覆盖完整：覆盖不完整时「没事件」可能只是没解析出来，
    这时恰恰需要更多原始记录来让模型发现盲区，不能省。
    """

    if result.events:
        return False
    coverage = result.coverage
    if coverage.limitation:
        return False
    return coverage.parse_failures == 0 and coverage.retention_drops == 0


def build_ai_context(
    result: AnalysisResult, records: list[dict[str, str | None]]
) -> dict[str, Any]:
    safe_result = result.model_dump(
        exclude={
            "id",
            "created_at",
            "ai_status",
            "ai_error",
            "ai_behaviors",
            # 上一次研判的成本指标对模型毫无意义，进上下文只会白花钱；
            # 而且重跑分析时它会让模型看到上一轮的结论痕迹。
            "ai_metrics",
        }
    )
    log_type = getattr(result.metadata, "log_type", None)
    light = _is_light_context(result)
    # 事件抽样 + 价值评分（P4 ①②）。抽样**先按分层取代表**，再对入选事件算评分；
    # 未入选的高风险事件单独计数（见下方 events_note），不静默丢弃。
    picked = _sample_event_indexes(result.events, EVENT_SAMPLE_LIMIT)
    facts = _event_value_facts(result)
    endpoints = _chain_endpoint_keys(result)

    # P4 ④：压缩前后证据召回率 + 自动降级。
    #
    # 先按标准档位算一次高风险事件的证据召回。若低于底线，说明压缩把高风险证据
    # 漏掉了——此时**自动降级为更完整的档位**（把被抽掉的高风险事件补回来）并重算。
    # 只降级一次，且补回后的事件数受 `EVENT_SAMPLE_HARD_MAX` 约束：自动降级不能
    # 变成「把全部事件都塞进去」，否则预算守卫会被自己的降级逻辑绕过。
    sent, available = _high_risk_evidence_recall(result, picked, facts)
    recall = sent / available if available else 1.0
    degraded = False
    if available and recall < EVIDENCE_RECALL_FLOOR:
        widened = sorted(
            set(picked)
            | {
                index
                for index, event in enumerate(result.events)
                if str(event.risk_level) in HIGH_RISK_LEVELS
            }
        )
        if len(widened) <= EVENT_SAMPLE_HARD_MAX:
            picked = widened
            degraded = True
            sent, available = _high_risk_evidence_recall(result, picked, facts)
            recall = sent / available if available else 1.0

    safe_result["events"] = []
    for index in picked:
        event = result.events[index]
        score = evidence_value.score_event(facts[index])
        key_node = _event_key(event) in endpoints
        safe_result["events"].append(
            _event_context(
                event,
                _evidence_depth(facts[index], key_node=key_node),
                value_note=score.to_note(),
                value_total=score.total,
                key_node=key_node,
            )
        )
    # 高风险事件被抽样丢掉时必须**明说**：模型据此才知道要去 query_events 补查。
    # 原先这类丢弃是无声的——`events_sample` 只给总数，看不出丢的是哪一档。
    high_risk_total = sum(
        1 for event in result.events if str(event.risk_level) in HIGH_RISK_LEVELS
    )
    high_risk_picked = sum(
        1 for index in picked if str(result.events[index].risk_level) in HIGH_RISK_LEVELS
    )
    # 档位说明**不逐档列出**：`critical:5,high:5,medium:3...` 这种图例对模型
    # **不可操作**（它改不了深度），却要每轮付费发送；而且它与 `_EVENT_EVIDENCE_DEPTH`
    # 是两份事实，改一处忘另一处就会对模型谎报。这里只声明「有上限、上限是多少」，
    # 需要更多证据时模型的动作是 `query_evidence`（`evidence_count` 给了真实总数）。
    safe_result["events_note"] = (
        f"events_total={len(result.events)};events_sample={len(picked)};"
        f"strata=rule/risk/type/source;not_all;"
        f"evidence_cap={EVENT_EVIDENCE_ITEM_LIMIT};depth_tune=+-1_by_value;"
        "chain_nodes=keep;"
        # 只在**真有高风险事件**时给出召回率：没有高风险事件就没什么可召回的，
        # 恒报 1.00 只是每轮白付 30 字节。低于 1 时模型才知道要去补查。
        + (
            f"high_risk_evidence_recall={recall:.2f};"
            if available
            else ""
        )
        # 降级只在**真的发生**时声明，且写明原因——否则「档位=标准」是噪音。
        + (
            "evidence_tier=full;reason=hr_recall_low;"
            if degraded
            else ""
        )
        + (
            f"high_risk_dropped={high_risk_total - high_risk_picked};"
            if high_risk_total > high_risk_picked
            else ""
        )
        + f"timeline_max={EVENT_TIMELINE_LIMIT};evidence_count=total;"
        "raw=evidence_items[].raw;more=query_events/query_evidence."
    )
    safe_result["risk_scores"] = (safe_result.get("risk_scores") or [])[:RISK_SCORE_LIMIT]
    _, covered_ids = detect_events_with_coverage(records)
    covered_count = sum(1 for record in records if record.get("record_id") in covered_ids)
    uncovered_pool = [
        record for record in records if record.get("record_id") not in covered_ids
    ]
    # 轻量模式：无事件且覆盖完整时，记录样本按更小配额给；需要细节仍可 query_records
    limit = (
        LIGHT_SAMPLE_LIMIT
        if light
        else min(_sample_limit(len(records)), EVENT_RECORD_SAMPLE_LIMIT)
        if result.events
        else _sample_limit(len(records))
    )
    event_record_ids = {
        evidence.record_id
        for index in picked
        for evidence in result.events[index].evidence_items[:EVENT_EVIDENCE_ITEM_LIMIT]
        if evidence.record_id
    }
    sampled_records = [
        record
        for record in _information_gain_sample(_stratified_sample(records, limit), limit)
        if record.get("record_id") not in event_record_ids
    ]
    safe_result["records_sample"] = _compact_sample_records(sampled_records, log_type)
    # 两块样本必须**互斥**，否则同一批原文会被发两遍。
    #
    # 原先刻意保留重叠（语义上「整体形态」与「规则未覆盖部分」是两种视角），
    # 但实测重叠率 **96%~97%**：规则覆盖少时，从全体抽样和从未覆盖池抽样
    # 几乎命中同一批记录，两块合计约 47% 的体积是纯重复。
    #
    # 两种视角靠 **note 里的计数** 表达（命中规则 N 条 / 未覆盖 M 条），
    # 明细则各出一份、互不重复——这样视角没丢，字节省下近一半，且
    # 两块叠加后覆盖的记录种类反而更多。
    sampled_ids = {record.get("record_id") for record in sampled_records}
    uncovered_sample = [
        record
        for record in _information_gain_sample(
            _stratified_sample(uncovered_pool, limit), limit
        )
        if record.get("record_id") not in sampled_ids
    ]
    safe_result["uncovered_records_sample"] = _compact_sample_records(
        uncovered_sample, log_type
    )
    # 必须显式给出总数、**时间范围**与采样口径：否则模型会把「样本里有 200 条」
    # 当成「日志只有 200 条」，也会把「样本覆盖的这一段时间」当成日志的全部时间跨度
    # （P4 ⑤）。时间范围取自全量记录，不是样本——样本的时间跨度天然更窄，
    # 用样本的时间范围会让模型低估日志的时间跨度。
    safe_result["records_sample_note"] = (
        f"records_total={len(records)};rule_hit={covered_count};uncovered={len(uncovered_pool)};"
        f"time_range={_records_time_range(records)};"
        f"samples=stratified;limit_each={limit};两块互不重复;"
        f"raw_max={AI_RAW_TEXT_LIMIT};"
        "not_all;more=query_records."
        + (
            "light_context=no_events_and_full_coverage;规则未命中不等于正常."
            if light
            else ""
        )
    )
    safe_result["templates"] = [
        {**item, "template": sanitize_text(str(item["template"]))}
        for item in safe_result.get("templates", [])
    ]
    safe_result["entities"] = [
        {**item, "summary": sanitize_text(str(item["summary"]))}
        for item in safe_result.get("entities", [])
    ]
    # 时间线中的 evidence.detail 通常就是事件证据原文，发送它会与 events.records
    # 重复；保留定位信息，细节按 record_id/evidence_id 通过工具查询。
    # 威胁情报（第三方数据）：**只读缓存，不发起外部请求**。
    # 情报库的结论不是日志事实，必须与 rules/events 明确区分，否则模型会把
    # 「第三方说这个 IP 是恶意的」当成「日志证明它是恶意的」。
    intel = cached_report(result.id, result, records)
    intel_findings = [
        {
            "indicator": finding.value,
            "type": finding.indicator_type,
            "verdict": finding.summary,
            "sources": {item.source: item.status for item in finding.sources},
        }
        for finding in intel.findings[:AI_CONTEXT_INDICATOR_LIMIT]
    ]
    safe_result["threat_intel"] = intel_findings
    if intel_findings:
        safe_result["threat_intel_note"] = (
            f"threat_intel_total={len(intel.findings)};sent={len(intel_findings)};"
            "source=third_party_reputation;not_log_evidence;queried=cache_only;"
            "在威胁情报模块查询后可获得更多."
        )
    else:
        # 没查过就说没查过：模型不得据「没有情报块」推断「IP 声誉正常」
        safe_result["threat_intel_note"] = (
            "queried=none;未查询威胁情报，不得据此推断 IP 声誉."
        )

    safe_result["timeline"] = [
        {
            key: value
            for key, value in {
                "timestamp": item.get("timestamp"),
                "kind": item.get("kind"),
                "title": _compact_context_text(item.get("title"), 160),
                "risk_level": item.get("risk_level"),
                "rule_id": item.get("rule_id"),
                "source_ip": item.get("source_ip"),
                "username": item.get("username"),
                "record_id": item.get("record_id"),
                "source_file": item.get("source_file"),
            }.items()
            if value not in (None, "")
        }
        for item in safe_result.get("timeline", [])[:50]
    ]
    safe_result["terminal_chains"] = [
        {
            **chain,
            "summary": sanitize_text(chain["summary"]),
            "nodes": [
                {
                    **node,
                    "title": sanitize_text(str(node.get("title") or "")),
                    "detail": sanitize_text(str(node["detail"])) if node.get("detail") else None,
                }
                for node in chain.get("nodes", [])[:100]
            ],
        }
        for chain in safe_result.get("terminal_chains", [])[:20]
    ]
    return _fit_context_budget(_order_context_for_cache(safe_result))


# 上下文字段顺序（prompt caching 友好）：**稳定 → 易变**。
# 缓存按前缀命中，一旦靠前的字段逐字相同，后面新增内容仍能复用已缓存前缀。
# 因此把「同一份日志反复研判时不变」的键放前面（日志类型、配置、规则命中摘要），
# 把「每次都可能不同」的键放后面（采样记录、时间线、证据链、预算说明）。
_CONTEXT_KEY_ORDER = (
    # 稳定前缀
    "metadata",
    "statistics",
    "coverage",
    "conclusion",
    "risk_level",
    "confidence",
    "limitation",
    "templates",
    "entities",
    "risk_scores",
    "threat_intel",
    "threat_intel_note",
    # 易变尾部
    "events",
    "events_note",
    "events_total",
    "records_sample",
    "uncovered_records_sample",
    "records_sample_note",
    "behavior_deviations",
    "timeline",
    "terminal_chains",
    "parse_error_details",
    "context_budget_note",
    "tool_results",
)


def _order_context_for_cache(context: dict[str, Any]) -> dict[str, Any]:
    """重排上下文字段顺序，让稳定内容构成可复用的缓存前缀。

    只改顺序、不改内容与取值，因此对模型语义无影响；未列入白名单的键（解析器后续
    可能新增）保留在尾部，避免被静默丢弃。
    """

    ordered: dict[str, Any] = {}
    for key in _CONTEXT_KEY_ORDER:
        if key in context:
            ordered[key] = context[key]
    for key, value in context.items():
        if key not in ordered:
            ordered[key] = value
    return ordered


def _extract_json(content: str) -> dict[str, Any]:
    cleaned = content.strip()
    cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"\s*```$", "", cleaned)
    value = json.loads(cleaned)
    if not isinstance(value, dict):
        raise ValueError("AI 返回结果不是 JSON 对象")
    return value


def _first(value: dict[str, Any], *keys: str, default: Any = None) -> Any:
    for key in keys:
        item = value.get(key)
        if item not in (None, "", [], {}):
            return item
    return default


def _price_table() -> ai_metrics.PriceTable:
    """读取单价配置。**不内置任何厂商价格**——价格会变，写死就会悄悄算错成本。

    没配全就没有成本数字（报告显示 n/a），而不是给一个过期的数字。
    """

    def _price(name: str) -> float | None:
        raw = _setting(name, "").strip()
        if not raw:
            return None
        try:
            value = float(raw)
        except ValueError:
            return None
        return value if value >= 0 else None

    return ai_metrics.PriceTable(
        input_per_m=_price("AI_PRICE_INPUT_PER_M"),
        output_per_m=_price("AI_PRICE_OUTPUT_PER_M"),
        cache_hit_per_m=_price("AI_PRICE_CACHE_HIT_PER_M"),
    )


def _coerce_confidence(value: Any) -> float:
    """把模型给的置信度夹到 [0, 1]；不可解析一律 0.0。

    NaN 必须单独挡掉：`json.loads` 默认接受非标准的 `NaN` 字面量，而
    `min(1.0, nan)` 返回 1.0 —— 一个无意义的值会被放大成「最高置信度」，
    正好和「不允许过度自信」相反。
    """

    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0.0
    if math.isnan(number):
        return 0.0
    return max(0.0, min(1.0, number))


def _normalize_evidence_ids(
    values: Any,
    valid_evidence_ids: set[str] | None,
    record_to_evidence: dict[str, str] | None,
    dropped: list[str] | None = None,
) -> list[str]:
    """接受 evidence id 或 record id 两种写法，统一映射为 evidence id。

    `dropped` 是**只读诊断出口**：无法解析到任何真实证据的编号会追加进去，
    但**不影响返回值**——运行时仍然宽容（丢掉了就是丢掉了），只是让「模型引用了
    不存在的证据」这件事变得可观测。此前它被静默吞掉，导致评测无法统计引用覆盖率。
    仅在 `valid_evidence_ids` 给出（即校验真的跑过）时记录：拿不到有效集合时
    「不存在」无从谈起。
    """

    # 模型偶尔把 evidence_ids 写成单个字符串而不是数组。直接返回 [] 会让这条引用连
    # 「不存在」都算不上，`dropped` 诊断出口也统计不到，等于静默丢失。按单项处理。
    if isinstance(values, str):
        values = [values]
    if not isinstance(values, list):
        return []
    normalized: list[str] = []
    for raw in values:
        token = str(raw)
        if valid_evidence_ids is not None and token in valid_evidence_ids:
            resolved = token
        else:
            resolved = (record_to_evidence or {}).get(token, "")
        if resolved and resolved not in normalized:
            normalized.append(resolved)
        elif not resolved and valid_evidence_ids is not None and dropped is not None:
            dropped.append(token)
    return normalized


def _build_behavior(
    item: dict[str, Any],
    valid_evidence_ids: set[str] | None,
    record_to_evidence: dict[str, str] | None,
    dropped: list[str] | None = None,
) -> AiBehavior:
    behavior_type = str(
        _first(item, "type", "behavior_id", "attack_type", "event_type", default="unknown_behavior")
    )
    return AiBehavior(
        type=behavior_type,
        name=str(_first(item, "name", "title", default=behavior_type)),
        confidence=_coerce_confidence(item.get("confidence", item.get("score", 0.0))),
        # 用 `_as_list`：模型把 evidence 写成单个字符串时，直接迭代会**逐字符拆开**，
        # 界面上就会出现 `1 0 . 0 . 0 . 1` 这种证据。
        evidence=_as_list(item.get("evidence", [])),
        evidence_ids=_normalize_evidence_ids(
            _first(item, "evidence_ids", "evidence_id", "record_ids", default=[]),
            valid_evidence_ids,
            record_to_evidence,
            dropped,
        ),
        analysis=str(
            _first(item, "analysis", "description", "rationale", "detail", default="")
        ),
    )


def _as_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if item not in (None, "")]
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    return []


def _build_structured_verdict(value: dict[str, Any]) -> StructuredVerdict | None:
    """把 AI 返回的 11 字段结构化研判归一化为 StructuredVerdict。

    兼容顶层直接给出字段、或放在 `structured` / `verdict` 子对象里两种写法，
    以及不同 Provider 的同义键名；全部缺失则返回 None（前端隐藏该卡片）。
    """

    sources: list[dict[str, Any]] = [value]
    for key in ("structured", "verdict", "structured_findings"):
        item = value.get(key)
        if isinstance(item, dict):
            sources.append(item)

    def pick(*keys: str, default: Any = None) -> Any:
        for source in sources:
            got = _first(source, *keys, default=None)
            if got not in (None, "", [], {}):
                return got
        return default

    def pick_text(*keys: str) -> str | None:
        """这些字段是 IP / 账号 / 时间这类语义字符串，只接受 `str`。

        模型偶尔把它们写成数字（`"involved_account": 0`）或数组，直接交给 pydantic
        会抛 ValidationError，整轮 AI 研判随之失败。形状不对就当未提供，
        而不是让一次分析崩掉（AGENTS.md §35）。
        """

        got = pick(*keys, default=None)
        return got if isinstance(got, str) else None

    # risk_level 必须在构造前归一化：它是 pydantic Literal，非法值在构造时就抛错，
    # 原先写在构造之后的兜底永远执行不到（死代码）——模型返回大写的 "HIGH" 会让整次分析崩掉。
    risk = pick("risk_level", "risk", "level", default="info")
    if not isinstance(risk, str) or risk not in {"critical", "high", "medium", "low", "info"}:
        risk = "info"

    verdict = StructuredVerdict(
        event_time=pick_text("event_time", "time", "event_time_display"),
        attack_source_ip=pick_text("attack_source_ip", "source_ip", "attacker_ip", "src_ip"),
        target_asset=pick_text("target_asset", "target", "target_host", "destination", "asset"),
        involved_account=pick_text("involved_account", "account", "username", "user"),
        abnormal_behavior=pick_text("abnormal_behavior", "behavior", "description", "detail"),
        related_logs=_as_list(pick("related_logs", "related_logs_list", "source_files", "logs", default=[])),
        attack_type=pick_text("attack_type", "type", "attack"),
        risk_level=risk,
        judgment_basis=pick_text("judgment_basis", "basis", "rationale", "reason", "evidence_summary"),
        success_indicator=pick_text("success_indicator", "success_evidence", "has_success", "success"),
        recommended_actions=_as_list(
            pick("recommended_actions", "actions", "handling", "recommendations", default=[])
        ),
    )
    # 11 个字段全空则视为未提供
    if not any(
        (
            verdict.event_time,
            verdict.attack_source_ip,
            verdict.target_asset,
            verdict.involved_account,
            verdict.abnormal_behavior,
            verdict.related_logs,
            verdict.attack_type,
            verdict.judgment_basis,
            verdict.success_indicator,
            verdict.recommended_actions,
        )
    ):
        return None
    return verdict


def _validate_response(
    value: dict[str, Any],
    valid_evidence_ids: set[str] | None = None,
    record_to_evidence: dict[str, str] | None = None,
) -> dict[str, Any]:
    """校验并归一化 AI 返回；不同 Provider 的字段命名差异在此统一。"""

    assessment = value.get("risk_assessment")
    if not isinstance(assessment, dict):
        assessment = {}
    risk = _first(value, "risk_level", "risk", "level", default=None) or _first(
        assessment, "risk_level", "risk", "level", default="info"
    )
    # 先判类型再判取值：模型给数组时 `in {...}` 会抛 TypeError: unhashable type，
    # 比取值非法更糟——那是崩溃而不是降级。
    if not isinstance(risk, str) or risk not in {"critical", "high", "medium", "low", "info"}:
        risk = "info"
    raw_confidence = _first(value, "confidence", "score", default=None)
    if raw_confidence is None:
        raw_confidence = assessment.get("confidence", 0.0)
    confidence = _coerce_confidence(raw_confidence)
    conclusion = _first(value, "summary", "conclusion", "assessment", default=None)
    if not conclusion:
        conclusion = _first(assessment, "rationale", "summary", "conclusion", default=None)
    behaviors = []
    dropped_evidence_ids: list[str] = []
    for item in _first(value, "behaviors", "findings", "detections", default=[]) or []:
        if not isinstance(item, dict):
            continue
        try:
            behaviors.append(
                _build_behavior(item, valid_evidence_ids, record_to_evidence, dropped_evidence_ids)
            )
        except Exception:
            continue
    recommendations = _first(
        value, "recommendations", "next_steps", "suggestions", default=[]
    )
    return {
        "risk_level": risk,
        "confidence": confidence,
        "conclusion": str(conclusion or "AI 无法根据当前证据确认更具体的结论。"),
        "recommendations": [str(item) for item in recommendations if item][:8],
        "behaviors": behaviors,
        "structured_verdict": _build_structured_verdict(value),
        # 诊断字段：模型引用过但日志里不存在的证据编号（已从 behaviors 中丢弃）。
        # 供 AI 评测统计「引用不存在证据」，不参与研判判定，也不进 AnalysisResult。
        "dropped_evidence_ids": dropped_evidence_ids,
    }


PROVIDER_PRESETS: dict[str, dict[str, str]] = {
    "openai": {
        "env_prefix": "OPENAI",
        "base_url": "https://api.openai.com/v1",
        "model": "gpt-4o-mini",
        "protocol": "openai",
    },
    "deepseek": {
        "env_prefix": "DEEPSEEK",
        "base_url": "https://api.deepseek.com",
        "model": "deepseek-chat",
        "protocol": "openai",
    },
    "qwen": {
        "env_prefix": "QWEN",
        "base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1",
        "model": "qwen-plus",
        "protocol": "openai",
    },
    "qianfan": {
        "env_prefix": "QIANFAN",
        "base_url": "https://qianfan.baidubce.com/v2",
        "model": "ernie-4.0-turbo-8k",
        "protocol": "openai",
    },
    "zhipu": {
        "env_prefix": "ZHIPU",
        "base_url": "https://open.bigmodel.cn/api/paas/v4",
        "model": "glm-4-flash",
        "protocol": "openai",
    },
    "moonshot": {
        "env_prefix": "MOONSHOT",
        "base_url": "https://api.moonshot.cn/v1",
        "model": "moonshot-v1-8k",
        "protocol": "openai",
    },
    "minimax": {
        "env_prefix": "MINIMAX",
        "base_url": "https://api.minimax.chat/v1",
        "model": "MiniMax-Text-01",
        "protocol": "openai",
    },
    "siliconflow": {
        "env_prefix": "SILICONFLOW",
        "base_url": "https://api.siliconflow.cn/v1",
        "model": "Qwen/Qwen2.5-72B-Instruct",
        "protocol": "openai",
    },
    "openrouter": {
        "env_prefix": "OPENROUTER",
        "base_url": "https://openrouter.ai/api/v1",
        "model": "openai/gpt-4o-mini",
        "protocol": "openai",
    },
    "groq": {
        "env_prefix": "GROQ",
        "base_url": "https://api.groq.com/openai/v1",
        "model": "llama-3.3-70b-versatile",
        "protocol": "openai",
    },
    "together": {
        "env_prefix": "TOGETHER",
        "base_url": "https://api.together.xyz/v1",
        "model": "meta-llama/Llama-3.3-70B-Instruct-Turbo",
        "protocol": "openai",
    },
    "fireworks": {
        "env_prefix": "FIREWORKS",
        "base_url": "https://api.fireworks.ai/inference/v1",
        "model": "accounts/fireworks/models/llama-v3p1-70b-instruct",
        "protocol": "openai",
    },
    "mistral": {
        "env_prefix": "MISTRAL",
        "base_url": "https://api.mistral.ai/v1",
        "model": "mistral-small-latest",
        "protocol": "openai",
    },
    "xai": {
        "env_prefix": "XAI",
        "base_url": "https://api.x.ai/v1",
        "model": "grok-3-mini",
        "protocol": "openai",
    },
    "gemini": {
        "env_prefix": "GEMINI",
        "base_url": "https://generativelanguage.googleapis.com/v1beta/openai",
        "model": "gemini-2.0-flash",
        "protocol": "openai",
    },
    "ollama": {
        "env_prefix": "OLLAMA",
        "base_url": "http://127.0.0.1:11434/v1",
        "model": "llama3.1",
        "protocol": "openai",
    },
    "anthropic": {
        "env_prefix": "ANTHROPIC",
        "base_url": "https://api.anthropic.com",
        "model": "claude-3-5-haiku-latest",
        "protocol": "anthropic",
    },
    "openai_compatible": {
        "env_prefix": "AI",
        "base_url": "",
        "model": "",
        "protocol": "openai",
    },
}

PROVIDER_MODEL_OPTIONS: dict[str, list[str]] = {
    "deepseek": ["deepseek-chat", "deepseek-reasoner"],
    "openai": ["gpt-4o-mini", "gpt-4.1-mini", "gpt-4.1"],
    "qwen": ["qwen-plus", "qwen-turbo", "qwen-max"],
    "qianfan": ["ernie-4.0-turbo-8k", "ernie-3.5-8k"],
    "zhipu": ["glm-4-flash", "glm-4-plus"],
    "moonshot": ["moonshot-v1-8k", "moonshot-v1-32k"],
    "minimax": ["MiniMax-Text-01"],
    "siliconflow": ["Qwen/Qwen2.5-72B-Instruct", "deepseek-ai/DeepSeek-V3"],
    "openrouter": ["openai/gpt-4o-mini", "deepseek/deepseek-chat"],
    "groq": ["llama-3.3-70b-versatile", "openai/gpt-oss-20b"],
    "together": ["meta-llama/Llama-3.3-70B-Instruct-Turbo"],
    "fireworks": ["accounts/fireworks/models/llama-v3p1-70b-instruct"],
    "mistral": ["mistral-small-latest", "mistral-large-latest"],
    "xai": ["grok-3-mini", "grok-3"],
    "gemini": ["gemini-2.0-flash", "gemini-2.5-flash"],
    "anthropic": ["claude-3-5-haiku-latest", "claude-3-7-sonnet-latest"],
    "ollama": ["llama3.1", "qwen2.5", "deepseek-r1"],
    "openai_compatible": [],
}

PROVIDER_ALIASES = {
    "google": "gemini",
    "gemini_openai": "gemini",
    "qwen_dashscope": "qwen",
    "glm": "zhipu",
    "kimi": "moonshot",
    "claude": "anthropic",
    "custom": "openai_compatible",
}


def _provider_settings() -> tuple[str, str, str, str, bool]:
    requested = _setting("AI_PROVIDER", "deepseek").lower().strip()
    provider = PROVIDER_ALIASES.get(requested, requested)
    preset = PROVIDER_PRESETS.get(provider, PROVIDER_PRESETS["openai_compatible"])
    prefix = preset["env_prefix"]
    legacy_prefix = "OPENAI" if provider == "openai_compatible" else prefix
    base_url = _setting(
        "AI_BASE_URL",
        _setting(
            f"{prefix}_BASE_URL",
            _setting(f"{legacy_prefix}_BASE_URL", preset["base_url"]),
        ),
    )
    model = _setting(
        "AI_MODEL",
        _setting(
            f"{prefix}_MODEL",
            _setting(f"{legacy_prefix}_MODEL", preset["model"]),
        ),
    )
    api_key = _setting(
        "AI_API_KEY",
        _setting(
            f"{prefix}_API_KEY",
            _setting(
                f"{legacy_prefix}_API_KEY",
                "ollama" if provider == "ollama" else "",
            ),
        ),
    )
    return provider, base_url.rstrip("/"), model, api_key, bool(api_key)


def check_ai_config() -> AiConfigStatus:
    provider, base_url, model, api_key, api_key_present = _provider_settings()
    key_problem = _api_key_problem(api_key)
    configured = (
        provider == "ollama"
        and bool(base_url)
        or bool(base_url)
        and api_key_present
        and not key_problem
    )
    if key_problem:
        message = key_problem
    elif configured:
        message = "AI 配置完整，可以进行研判。"
    else:
        message = "未配置 API Key，当前只能使用本地规则分析。"
    return AiConfigStatus(
        configured=configured,
        provider=provider,
        model=model,
        base_url=base_url,
        api_key_present=api_key_present,
        message=message,
        supported_providers=list(PROVIDER_PRESETS),
        provider_presets={
            name: {"base_url": values["base_url"], "models": PROVIDER_MODEL_OPTIONS.get(name, [values["model"]])}
            for name, values in PROVIDER_PRESETS.items()
        },
    )


def save_ai_config(
    provider: str,
    base_url: str,
    model: str,
    api_key: str | None = None,
    clear_api_key: bool = False,
) -> AiConfigStatus:
    requested = provider.lower().strip()
    provider = PROVIDER_ALIASES.get(requested, requested)
    if provider not in PROVIDER_PRESETS:
        raise ValueError("不支持的 AI Provider")
    preset = PROVIDER_PRESETS[provider]
    if not base_url.strip():
        base_url = preset["base_url"]
    if not model.strip():
        model = preset["model"]
    env_path = env_files()[0]
    values: dict[str, str] = {}
    source = next((path for path in env_files() if path.exists()), None)
    if source is not None:
        for line in source.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            key, value = stripped.split("=", 1)
            values[key] = value.strip().strip('"').strip("'")
    values["AI_PROVIDER"] = provider
    values["AI_BASE_URL"] = base_url.rstrip("/")
    values["AI_MODEL"] = model
    if clear_api_key:
        values.pop("AI_API_KEY", None)
        prefix = preset["env_prefix"]
        values.pop(f"{prefix}_API_KEY", None)
    elif api_key and api_key.strip() and api_key.strip() != "********":
        values["AI_API_KEY"] = api_key.strip()
    env_path.write_text(
        "\n".join(f"{key}={value}" for key, value in values.items()) + "\n",
        encoding="utf-8",
    )
    return check_ai_config()


# ---------- 请求错误分类与重试 ----------
# 只重试「可能自己恢复」的错误。鉴权 / 请求格式 / 端点错误重试无效，直接给用户可行动的提示。
DEFAULT_MAX_RETRIES = 2
RETRY_BACKOFF_SECONDS = 1.0
RETRY_MAX_WAIT_SECONDS = 30.0
NON_RETRYABLE_STATUS = frozenset({400, 401, 403, 404, 405, 422})

ERROR_KIND_LABELS = {
    "auth": "鉴权失败",
    "bad_request": "请求被拒绝",
    "not_found": "接口地址不存在",
    "rate_limit": "调用被限流",
    "context_too_long": "输入上下文超出模型上限",
    "server": "AI 服务端故障",
    "timeout": "响应超时",
    "network": "网络不可达",
    "format": "响应格式异常",
}


# 不可重试错误的处置建议：直接给用户「下一步做什么」，而不是笼统地说"检查配置"
NON_RETRYABLE_ADVICE = {
    "auth": "请检查模型、密钥与接口地址配置。",
    "context_too_long": (
        "请减少一次性分析的日志量（按设备/时间段分批上传），或改用上下文更大的模型。"
    ),
    "not_found": "请检查接口地址（base_url）是否包含正确的版本路径。",
    "bad_request": "请检查模型名与请求参数；若服务端消息指向输入过长，请减少日志量。",
}
# 服务端消息里出现这些词，说明 400 是「输入太长」而不是配置错误
CONTEXT_HINTS = ("context length", "context_length", "maximum context", "too many tokens", "tokens")


def _server_message(body: str) -> str:
    """从错误响应体里取出服务端给的原因（OpenAI 兼容格式是 error.message）。"""

    text = body.strip()
    if not text:
        return ""
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return text[:300]
    if isinstance(parsed, dict):
        error = parsed.get("error")
        if isinstance(error, dict) and error.get("message"):
            return str(error["message"])[:300]
        if parsed.get("message"):
            return str(parsed["message"])[:300]
    return ""


class AiRequestError(RuntimeError):
    """带分类的 AI 请求错误：调用方据此决定是否重试，以及给用户什么提示。"""

    def __init__(
        self,
        kind: str,
        detail: str,
        retryable: bool,
        retry_after: float | None = None,
    ) -> None:
        super().__init__(detail)
        self.kind = kind
        self.retryable = retryable
        self.retry_after = retry_after


def _classify_http_error(
    status: int, retry_after: str | None, detail: str = ""
) -> AiRequestError:
    """把 HTTP 状态码翻成「用户能行动的类别」，并带上服务端给出的原因。"""

    message = detail or f"AI 服务返回 HTTP {status}"
    if status in NON_RETRYABLE_STATUS:
        if status in (401, 403):
            kind = "auth"
        elif status == 404:
            kind = "not_found"
        elif status in (400, 422) and any(
            hint in detail.lower() for hint in CONTEXT_HINTS
        ):
            # 400 不都是配置错：请求体过大同样返回 400，提示必须区分开
            kind = "context_too_long"
        else:
            kind = "bad_request"
        return AiRequestError(kind, message, retryable=False)
    if status == 429:
        wait: float | None = None
        try:
            wait = float(retry_after) if retry_after else None
        except (TypeError, ValueError):
            wait = None
        return AiRequestError("rate_limit", message, retryable=True, retry_after=wait)
    return AiRequestError("server", message, retryable=True)


def _failure_message(exc: AiRequestError, attempts: int) -> str:
    label = ERROR_KIND_LABELS.get(exc.kind, "请求失败")
    detail = str(exc)
    if not exc.retryable:
        if exc.kind == "timeout":
            # 单次上限已是数百秒，自动重试会让等待时间成倍增长，交给用户决定
            return (
                f"{label}：{detail}。研判以准确为先，可调大 AI_TIMEOUT_SECONDS 后重试，"
                "或稍后手动重试。"
            )
        advice = NON_RETRYABLE_ADVICE.get(
            exc.kind, "这类错误重试无效，请检查 AI 配置（模型、密钥、接口地址）。"
        )
        return f"{label}：{detail}。{advice}"
    if attempts > 1:
        return (
            f"{label}：{detail}。已自动重试 {attempts - 1} 次仍未成功，"
            "请稍后重试或检查 AI 服务状态。"
        )
    return f"{label}：{detail}。"


def _open(url: str, payload: dict[str, Any], headers: dict[str, str]):
    """发起请求（不读响应体），把传输层错误统一分类。

    抽出来是为了让「一次性请求」与「流式请求」共用同一套错误分类与超时口径。
    """

    http_request = request.Request(
        url,
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        return request.urlopen(http_request, timeout=_effective_timeout())
    except error.HTTPError as exc:
        retry_after = exc.headers.get("Retry-After") if exc.headers else None
        try:
            detail = _server_message(exc.read().decode("utf-8", errors="replace")[:2048])
        except Exception:
            detail = ""
        raise _classify_http_error(exc.code, retry_after, detail) from exc
    except (TimeoutError, error.URLError) as exc:
        if isinstance(exc, TimeoutError) or isinstance(
            getattr(exc, "reason", None), TimeoutError
        ):
            raise AiRequestError(
                "timeout",
                f"AI 服务响应超时（单次上限 {_effective_timeout():.0f} 秒）",
                retryable=False,
            ) from exc
        raise AiRequestError(
            "network", "AI 服务暂时不可用（网络不可达）", retryable=True
        ) from exc


def _post_json_once(url: str, payload: dict[str, Any], headers: dict[str, str]) -> dict[str, Any]:
    """单次请求；所有失败都转成带分类的 `AiRequestError`。"""

    with _open(url, payload, headers) as response:
        raw = response.read().decode("utf-8")
    try:
        body = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise AiRequestError("format", "AI 服务返回内容不是合法 JSON", retryable=True) from exc
    if not isinstance(body, dict):
        raise AiRequestError("format", "AI 服务返回格式无效", retryable=True)
    return body


def _request_json(
    url: str, payload: dict[str, Any], headers: dict[str, str]
) -> dict[str, Any]:
    """带回退重试的请求：指数退避，并尊重服务端给出的 Retry-After。"""

    attempts = _int_setting("AI_MAX_RETRIES", DEFAULT_MAX_RETRIES) + 1
    for attempt in range(1, attempts + 1):
        try:
            return _post_json_once(url, payload, headers)
        except AiRequestError as exc:
            if not exc.retryable or attempt >= attempts:
                raise RuntimeError(_failure_message(exc, attempt)) from exc
            wait = exc.retry_after
            if wait is None:
                wait = RETRY_BACKOFF_SECONDS * (2 ** (attempt - 1))
            time.sleep(min(wait, RETRY_MAX_WAIT_SECONDS))
    raise RuntimeError("AI 请求失败")


def _stream_message(
    url: str,
    payload: dict[str, Any],
    headers: dict[str, str],
    on_delta: Callable[[str], None],
) -> dict[str, Any]:
    """流式取回一条 assistant 消息，并拼回与一次性响应等价的结构。

    逐块回调给调用方用于实时展示；工具调用的参数在流里是**分片**到达的，
    按 `index` 累积后拼成完整 `tool_calls`，这样上层完全不必区分两种取回方式。
    """

    text_parts: list[str] = []
    calls: dict[int, dict[str, Any]] = {}
    with _open(url, payload, headers) as response:
        for raw_line in response:
            line = raw_line.decode("utf-8", errors="replace").strip()
            if not line.startswith("data:"):
                continue
            data = line[5:].strip()
            if data == "[DONE]":
                break
            try:
                event = json.loads(data)
            except json.JSONDecodeError:
                continue
            choices = event.get("choices") or []
            if not choices:
                continue
            delta = choices[0].get("delta") or {}
            chunk = delta.get("content")
            if chunk:
                text_parts.append(chunk)
                on_delta(chunk)
            for item in delta.get("tool_calls") or []:
                index = int(item.get("index") or 0)
                slot = calls.setdefault(
                    index,
                    {"id": "", "type": "function", "function": {"name": "", "arguments": ""}},
                )
                if item.get("id"):
                    slot["id"] = str(item["id"])
                function = item.get("function") or {}
                if function.get("name"):
                    slot["function"]["name"] = str(function["name"])
                if function.get("arguments"):
                    slot["function"]["arguments"] += str(function["arguments"])
    message: dict[str, Any] = {"role": "assistant", "content": "".join(text_parts)}
    if calls:
        message["tool_calls"] = [calls[index] for index in sorted(calls)]
    return {"choices": [{"message": message}]}


def _openai_endpoint(base_url: str) -> str:
    if base_url.endswith("/chat/completions"):
        return base_url
    return f"{base_url}/chat/completions"


def _first_message(body: dict[str, Any]) -> dict[str, Any]:
    try:
        message = body["choices"][0]["message"]
    except (KeyError, IndexError, TypeError) as exc:
        raise RuntimeError("AI 服务返回中缺少可读内容") from exc
    if not isinstance(message, dict):
        raise RuntimeError("AI 服务返回中缺少可读内容")
    return message


def _message_content(message: dict[str, Any]) -> str:
    content = message.get("content")
    if isinstance(content, list):
        return "".join(
            item.get("text", "") for item in content if isinstance(item, dict)
        )
    return str(content or "")


# ---------------------------------------------------------------------------
# 用量与缓存命中统计
#
# 上一步把 prompt caching 接上了，但「接上」不等于「命中」——不同服务端回传的字段名
# 并不统一，命中与否只能从 usage 里读出来。这里统一解析成同一份结构，供 ai_tool_trace
# 累积，让成本优化从「看请求体积」变成「看真实账单」。
#
# 各家字段名：
#   * DeepSeek   prompt_cache_hit_tokens / prompt_cache_miss_tokens
#   * OpenAI     prompt_tokens_details.cached_tokens
#   * Anthropic  cache_read_input_tokens / cache_creation_input_tokens
# ---------------------------------------------------------------------------


def _usage_tokens(body: dict[str, Any]) -> dict[str, Any]:
    """把不同服务端的 usage 归一化为统一口径；缺失字段一律省略，不编造 0。"""

    usage = body.get("usage")
    if not isinstance(usage, dict):
        return {}

    result: dict[str, Any] = {}

    def _put_int(target: str, *candidates: Any) -> None:
        for value in candidates:
            if isinstance(value, int) and value >= 0:
                result[target] = value
                return

    details = usage.get("prompt_tokens_details")
    details = details if isinstance(details, dict) else {}

    _put_int("prompt_tokens", usage.get("prompt_tokens"), usage.get("input_tokens"))
    _put_int("completion_tokens", usage.get("completion_tokens"), usage.get("output_tokens"))
    _put_int(
        "cache_hit_tokens",
        usage.get("prompt_cache_hit_tokens"),
        details.get("cached_tokens"),
        usage.get("cache_read_input_tokens"),
    )
    _put_int(
        "cache_miss_tokens",
        usage.get("prompt_cache_miss_tokens"),
        None,
    )
    _put_int("cache_write_tokens", usage.get("cache_creation_input_tokens"))

    prompt_tokens = result.get("prompt_tokens")
    hit = result.get("cache_hit_tokens")
    if isinstance(prompt_tokens, int) and isinstance(hit, int) and prompt_tokens > 0:
        # 命中率是判断「缓存到底有没有生效」的唯一直接信号
        result["cache_hit_ratio"] = round(hit / prompt_tokens, 4)
        if "cache_miss_tokens" not in result:
            result["cache_miss_tokens"] = max(prompt_tokens - hit, 0)
    return result


def _merge_usage(rounds: list[dict[str, Any]]) -> dict[str, Any]:
    """把各轮 usage 汇总为一份总账（含整体命中率），用于判断缓存是否真的生效。

    同时保留 `by_round` 分轮明细。**合并会把「首轮 vs 工具轮次」的成本结构抹平**——
    而这两者的量级完全不同（首轮发全量上下文，后续轮发摘要占位），
    只看总数就无法回答「成本花在哪一轮」，也就无法判断历史裁剪到底省了多少。
    """

    total: dict[str, int] = {}
    for entry in rounds:
        for key in ("prompt_tokens", "completion_tokens", "cache_hit_tokens", "cache_miss_tokens", "cache_write_tokens"):
            value = entry.get(key)
            if isinstance(value, int):
                total[key] = total.get(key, 0) + value

    merged: dict[str, Any] = {"rounds": len(rounds), **total}
    if rounds:
        merged["by_round"] = [dict(entry) for entry in rounds]
    prompt_tokens = total.get("prompt_tokens")
    if isinstance(prompt_tokens, int) and prompt_tokens > 0 and "cache_hit_tokens" in total:
        merged["cache_hit_ratio"] = round(total["cache_hit_tokens"] / prompt_tokens, 4)
    return merged


# ---------------------------------------------------------------------------
# Prompt caching（前缀缓存）
#
# Chat Completions 每轮都会重发 system prompt + tools 定义，两者在整个会话里逐字节不变，
# 是天然的缓存前缀。命中缓存的输入按折扣计价（DeepSeek 约 1/10、Anthropic 约 1/10、
# OpenAI 约 1/2 且不额外收费），因此只要服务端支持，前缀缓存的收益是白拿的。
#
# 两类服务端语义不同，必须分开处理：
#   * Anthropic 系（Anthropic / OpenRouter / 部分兼容网关）需要**显式**在消息 content 上
#     打 `cache_control: {"type": "ephemeral"}` 标记，缺失则完全不缓存；
#   * DeepSeek / OpenAI 系**自动**做前缀缓存，额外字段既无用也可能被严格网关拒绝，
#     只需把稳定内容排在前面（由 `_order_context_for_cache()` 保证）即可。
# 关闭方式：`AI_PROMPT_CACHE=false`。默认开启，因为这两类服务端都接受或忽略该能力。
# ---------------------------------------------------------------------------

# 需要显式 cache_control 标记的服务端关键字（按 base_url 匹配）
_EXPLICIT_CACHE_HOSTS = ("anthropic", "openrouter", "claude")


def _prompt_cache_enabled() -> bool:
    return _setting("AI_PROMPT_CACHE", "true").strip().lower() not in {"0", "false", "no"}


def _needs_explicit_cache_marker(base_url: str) -> bool:
    """判断该服务端是否必须显式传 `cache_control` 才会启用前缀缓存。"""

    host = (base_url or "").lower()
    return any(token in host for token in _EXPLICIT_CACHE_HOSTS)


class OpenAICompatibleProvider:
    supports_tools = True

    def __init__(self, base_url: str, model: str, api_key: str) -> None:
        self.base_url = base_url
        self.model = model
        self.api_key = api_key
        # 最近一次调用的 token / 缓存命中用量，供调用方读取（可能为空）
        self.last_usage: dict[str, Any] = {}
        # 最近一次工具轮次的轨迹；失败降级时由 _recover_trace 取回，避免整片丢失
        self.last_trace: list[dict[str, Any]] = []

    def _cacheable(self, content: str) -> Any:
        """给稳定前缀打上缓存标记（仅对需要显式标记的服务端）。"""

        if not _prompt_cache_enabled() or not _needs_explicit_cache_marker(self.base_url):
            return content
        return [
            {
                "type": "text",
                "text": content,
                "cache_control": {"type": "ephemeral"},
            }
        ]

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

    def _post(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        on_delta: Callable[[str], None] | None = None,
    ) -> dict[str, Any]:
        # system prompt 在整个会话中逐字节不变，是命中率最高的缓存前缀；
        # 对需要显式标记的服务端在这里统一打上 cache_control。
        messages = [
            (
                {**message, "content": self._cacheable(message["content"])}
                if message.get("role") == "system" and isinstance(message.get("content"), str)
                else message
            )
            for message in messages
        ]
        payload: dict[str, Any] = {
            "model": self.model,
            "temperature": 0.1,
            "messages": messages,
        }
        if tools:
            payload["tools"] = tools
        elif _setting("AI_JSON_RESPONSE_FORMAT", "false").lower() == "true":
            payload["response_format"] = {"type": "json_object"}
        endpoint = _openai_endpoint(self.base_url)
        if on_delta is not None:
            try:
                return _stream_message(
                    endpoint, {**payload, "stream": True}, self._headers(), on_delta
                )
            except AiRequestError:
                # 流式失败只是「看不到实时输出」，不能让研判本身失败：退回一次性请求
                pass
        return _request_json(endpoint, payload, self._headers())

    def complete(
        self,
        system_prompt: str,
        context: dict[str, Any],
        on_delta: Callable[[str], None] | None = None,
    ) -> str:
        body = self._post(
            [
                {"role": "system", "content": system_prompt},
                {
                    "role": "user",
                    "content": json.dumps(context, ensure_ascii=False),
                },
            ],
            on_delta=on_delta,
        )
        # 降级路径（无工具）同样记录用量，否则「模型未按工具返回」时成本就成了盲区
        usage = _usage_tokens(body)
        self.last_usage = {"rounds": 1, **usage} if usage else {}
        return _message_content(_first_message(body))

    def complete_with_tools(
        self,
        system_prompt: str,
        context: dict[str, Any],
        result: AnalysisResult,
        records: list[dict[str, str | None]],
        on_delta: Callable[[str], None] | None = None,
    ) -> tuple[str, list[dict[str, Any]]]:
        """带只读工具的研判；工具由本地执行，模型只负责选择与阅读结果。

        **成本约束（Chat Completions 无状态，每轮重发全部历史）**：
        首轮那条 user 消息带着完整上下文，如果每轮都原样重发，N 轮就是 N+1 份
        首轮上下文的账单。因此从第二轮起把那份超大上下文**替换成摘要占位**——
        模型在首轮已经读过它，需要细节时用 query_records / query_evidence 取回，
        而工具结果与已产出的对话被完整保留。
        """

        messages: list[dict[str, Any]] = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": json.dumps(context, ensure_ascii=False)},
        ]
        trace: list[dict[str, Any]] = []
        usage_rounds: list[dict[str, Any]] = []
        # 本轮的工具轨迹与用量要「边做边存」：中途某一轮请求失败时，
        # 调用方（_request_content）需要把它们取回来，否则降级会把已完成的
        # 工具调用与用量一并抹掉（历史上就是这样，导致用量长期为空）。
        self.last_trace = trace
        self.last_usage = {}
        for round_index in range(_effective_tool_rounds()):
            body = self._post(messages, tools=list(AGENT_TOOLS), on_delta=on_delta)
            usage = _usage_tokens(body)
            if usage:
                usage_rounds.append({"round": round_index + 1, **usage})
                # 每轮都落一次，保证「后续某轮失败」时已发生的用量不丢
                self.last_usage = _merge_usage(usage_rounds)
            message = _first_message(body)
            calls = message.get("tool_calls") or []
            if not calls:
                # 模型不再需要工具 → 这一轮就是终轮，直接收敛（早停）。
                if usage_rounds:
                    self.last_usage = _merge_usage(usage_rounds)
                    trace.append(
                        {"tool": "usage", "source": "auto", "summary": "", "usage": self.last_usage}
                    )
                return _message_content(message), trace
            messages.append(
                {
                    key: value
                    for key, value in message.items()
                    if key in {"role", "content", "tool_calls"}
                }
            )
            for call in calls:
                function = call.get("function") or {}
                name = str(function.get("name") or "")
                arguments = _parse_tool_arguments(function.get("arguments"))
                output = execute_tool(name, arguments, result, records)
                trace.append(
                    {
                        "tool": name,
                        "arguments": {
                            key: value
                            for key, value in arguments.items()
                            if value not in (None, "")
                        },
                        "summary": str(output.get("summary", "")),
                        "source": "model",
                    }
                )
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": str(call.get("id") or name),
                        "content": json.dumps(output, ensure_ascii=False),
                    }
                )
            # 本轮已经用过完整上下文，下一轮起换成摘要占位（首轮消息不删，保持对话结构合法）
            _shrink_history_context(messages, context)
        # 走到这里 = 轮次用尽（模型若主动停止调用工具，上一轮就已提前返回）。
        # 此时消息末尾是刚回填的 tool 结果，**不能**再插入终局提示：
        # 那会让 `messages[-1]` 变成 user 消息，把 tool 结果挤出「最后一条」，
        # 模型看不到自己刚取回的证据就被要求出结论。
        if not _has_open_tool_round(messages):
            messages.append({"role": "user", "content": _BUDGET_EXHAUSTED_HINT})
        return (
            _message_content(_first_message(self._post(messages, on_delta=on_delta))),
            trace,
        )


# 轮次用尽时的收尾提示：只提示「可以收敛」，不再要求「不要调用工具」，
# 因为此时最后一条消息可能是刚回填的 tool 结果，模型仍需要它才能作答。
_BUDGET_EXHAUSTED_HINT = "请基于已获取的证据输出最终 JSON 结论。"


def _has_open_tool_round(messages: list[dict[str, Any]]) -> bool:
    """消息序列是否停在「刚回填完工具结果、模型尚未就下一步表态」的位置。

    用来区分两种走到轮次上限的情形：
      - 模型每轮都在调工具、轮次被用尽 → 末尾是 `tool`，不能插入 user 提示；
      - 模型已给出无 tool_calls 的回复（早停前的一轮）→ 可以插入提示。
    """

    return bool(messages) and messages[-1].get("role") == "tool"


def _history_context_placeholder(context: dict[str, Any]) -> str:
    """把「已读过的完整上下文」压成摘要占位，供后续轮次重发使用。

    刻意保留**计数与结论性事实**（总数、覆盖度、风险等级、事件数）：模型做数量表述
    和风险判断时的锚点都在这里，丢了会导致结论退化成「只看样本」。被丢掉的是一大块
    原始原文（events / 记录样本），它们可以用 query_records / query_evidence 按需取回。
    """

    metadata = context.get("metadata") or {}
    coverage = context.get("coverage") or {}
    placeholder = {
        "continuing": "以下是本轮的日志上下文摘要；完整数据已在首轮提供，需要细节请调用只读工具。",
        "tool_results": context.get("tool_results"),
        "log_type": metadata.get("log_type"),
        "total_records": metadata.get("total_lines"),
        "parsed_records": metadata.get("parsed_lines"),
        "time_range": metadata.get("time_range"),
        "events_total": context.get("events_total") or len(context.get("events") or []),
        "local_risk_level": context.get("risk_level"),
        "local_conclusion": context.get("conclusion"),
        "coverage": coverage,
        "statistics": context.get("statistics"),
        "events_note": context.get("events_note"),
        "records_sample_note": context.get("records_sample_note"),
        "query_hint": (
            "需要原始记录用 query_records（可按字段/关键字/日志类型筛选）；"
            "需要某事件全部证据用 query_evidence；需要行为偏离用 query_behavior_deviations；"
            "需要未覆盖记录用 query_uncovered_records。"
        ),
    }
    return json.dumps(placeholder, ensure_ascii=False)


def _shrink_history_context(
    messages: list[dict[str, Any]], context: dict[str, Any]
) -> None:
    """把历史里那条超大 user 上下文替换为摘要占位（幂等）。

    只替换「第一条 user 消息」——它的 role 与位置不变，因此对话结构仍合法；
    工具消息（role=tool）与助手回复原样保留。
    """

    for message in messages:
        if message.get("role") != "user":
            continue
        content = message.get("content")
        if isinstance(content, str) and len(content) > _HISTORY_SHRINK_THRESHOLD:
            message["content"] = _history_context_placeholder(context)
        return


def _parse_tool_arguments(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    if not isinstance(raw, str) or not raw.strip():
        return {}
    try:
        value = json.loads(raw)
    except ValueError:
        return {}
    return value if isinstance(value, dict) else {}


class DeepSeekProvider(OpenAICompatibleProvider):
    pass


class OllamaProvider(OpenAICompatibleProvider):
    supports_tools = False


class AnthropicProvider:
    # 工具调用只实现 OpenAI-compatible 协议；Anthropic 走单次调用，避免协议差异导致研判失败
    supports_tools = False

    def __init__(self, base_url: str, model: str, api_key: str) -> None:
        self.base_url = base_url
        self.model = model
        self.api_key = api_key
        # 与 OpenAICompatibleProvider 保持同一套用量口径，供上层统一读取
        self.last_usage: dict[str, Any] = {}
        # Anthropic 不走工具轮次，但保留同名字段以免上层取用时 AttributeError
        self.last_trace: list[dict[str, Any]] = []

    def complete(
        self,
        system_prompt: str,
        context: dict[str, Any],
        on_delta: Callable[[str], None] | None = None,
    ) -> str:
        # Anthropic 的流式是另一套协议（event: content_block_delta），这里只做单次调用
        endpoint = self.base_url
        if endpoint.endswith("/v1/messages"):
            pass
        elif endpoint.endswith("/v1"):
            endpoint = f"{endpoint}/messages"
        else:
            endpoint = f"{endpoint}/v1/messages"
        body = _request_json(
            endpoint,
            {
                "model": self.model,
                "max_tokens": _int_setting(
                    "AI_MAX_OUTPUT_TOKENS", DEFAULT_OUTPUT_TOKENS
                ),
                "temperature": 0.1,
                "system": system_prompt,
                "messages": [
                    {
                        "role": "user",
                        "content": json.dumps(context, ensure_ascii=False),
                    }
                ],
            },
            {
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json",
            },
        )
        try:
            content = body["content"]
            text = "".join(
                item.get("text", "")
                for item in content
                if isinstance(item, dict) and item.get("type") == "text"
            )
        except (KeyError, TypeError) as exc:
            raise RuntimeError("Anthropic 服务返回中缺少可读内容") from exc
        usage = _usage_tokens(body)
        self.last_usage = {"rounds": 1, **usage} if usage else {}
        return text


def _api_key_problem(api_key: str) -> str | None:
    """API Key 里出现非 ASCII 字符时给出可读原因。

    真实事故（2026-10-13 真实模型评测）：`.env` 里的 Key 是没替换的中文占位符，
    请求头按 latin-1 编码，于是 11 条用例全部失败在同一句
    `'latin-1' codec can't encode characters in position 7-8` —— 报错完全指不到病因。
    """

    if not api_key:
        return None
    if api_key.isascii():
        return None
    return (
        "API Key 含非 ASCII 字符（常见于 .env 里没替换的中文占位符），"
        "请在设置或 .env 中填写服务商提供的真实 Key。"
    )


def _create_provider() -> OpenAICompatibleProvider | AnthropicProvider:
    provider, base_url, model, api_key, _ = _provider_settings()
    problem = _api_key_problem(api_key)
    if problem:
        raise AiRequestError("config", problem, retryable=False)
    protocol = PROVIDER_PRESETS.get(provider, PROVIDER_PRESETS["openai_compatible"])[
        "protocol"
    ]
    if protocol == "anthropic":
        return AnthropicProvider(base_url, model, api_key)
    provider_class = OllamaProvider if provider == "ollama" else (
        DeepSeekProvider if provider == "deepseek" else OpenAICompatibleProvider
    )
    return provider_class(base_url, model, api_key)


def _build_grounding_index(
    result: AnalysisResult, records: list[dict[str, str | None]]
) -> dict[str, set[str]]:
    """收集日志中真实出现过的 IP、记录编号与 URL，用于校验 AI 结论是否有证据支撑。

    口径包含全部日志记录，而不只是被规则命中的证据：
    未被规则标记的记录同样是日志事实，AI 引用它们不算幻觉。
    """

    index: dict[str, set[str]] = {"ips": set(), "record_ids": set(), "evidence_ids": set(), "urls": set(), "accounts": set(), "targets": set()}

    def note_asset(value: str | None) -> None:
        """目标资产常常直接写成 IP（域控导出就是这样），必须计入已知 IP。

        否则 AI 一提到「目标主机 10.0.0.11」就会被判成编造 IP —— 那是对正确结论的误报，
        与「不允许虚假告警」的取向冲突。
        """

        if not value:
            return
        index["targets"].add(value)
        if IP_PATTERN.fullmatch(value.strip()):
            index["ips"].add(value.strip())

    for event in result.events:
        note_asset(event.target_asset)
        if event.source_ip:
            index["ips"].add(event.source_ip)
        for item in event.evidence_items:
            for value in (item.source_ip, item.destination_ip):
                if value:
                    index["ips"].add(value)
            if item.username:
                index["accounts"].add(item.username)
            if item.record_id:
                index["record_ids"].add(item.record_id)
            index["evidence_ids"].add(item.id)
            if item.url:
                index["urls"].add(item.url)
    for entry in result.timeline:
        if entry.source_ip:
            index["ips"].add(entry.source_ip)
        if entry.username:
            index["accounts"].add(entry.username)
        if entry.record_id:
            index["record_ids"].add(entry.record_id)
    for record in records:
        for field in ("source_ip", "destination_ip"):
            value = record.get(field)
            if value:
                index["ips"].add(value)
        if record.get("username"):
            index["accounts"].add(record["username"])
        note_asset(record.get("target_asset"))
        if record.get("record_id"):
            index["record_ids"].add(record["record_id"])
        if record.get("evidence_id"):
            index["evidence_ids"].add(record["evidence_id"])
        if record.get("url"):
            index["urls"].add(record["url"])
    return index


def _check_grounding(
    judgement: dict[str, Any],
    result: AnalysisResult,
    records: list[dict[str, str | None]],
) -> list[str]:
    """找出 AI 结论中无法在日志证据里对上的引用（AGENTS.md §16 不允许幻觉）。"""

    index = _build_grounding_index(result, records)
    known_record_ids = index["record_ids"]
    claims: list[str] = []
    seen: set[str] = set()
    raw_texts: list[str] | None = None

    def appears_in_log(value: str) -> bool:
        """目标/来源常常只出现在日志原文里，解析器不会把它提成结构化字段。

        combined log 的 Referer（`http://192.168.200.51/`）与 syslog 的主机名
        （`ip-10-0-10-4`）都只在 `raw` 里。原文里确实出现过，就不是编造——
        把日志事实报成幻觉，和对正确结论的误报是同一类问题。
        只有结构化字段对不上时才来查原文，因此惰性构造。
        """

        nonlocal raw_texts
        if raw_texts is None:
            raw_texts = [record.get("raw") or "" for record in records]
            raw_texts.extend(
                item.raw or ""
                for event in result.events
                for item in event.evidence_items
            )
        if IP_PATTERN.fullmatch(value):
            # 用正则取词再比，避免 192.168.200.5 命中 192.168.200.51 的子串。
            return any(value in IP_PATTERN.findall(text) for text in raw_texts)
        pattern = re.compile(rf"(?<![0-9A-Za-z_.-]){re.escape(value)}(?![0-9A-Za-z_.-])")
        return any(pattern.search(text) for text in raw_texts)

    def inspect(label: str, text: str) -> None:
        for value in IP_PATTERN.findall(text):
            if value not in index["ips"] and value not in seen and not appears_in_log(value):
                seen.add(value)
                claims.append(f"{label} 引用了日志中不存在的 IP：{value}")
        for value in RECORD_PATTERN.findall(text):
            if value not in known_record_ids and value not in seen:
                seen.add(value)
                claims.append(f"{label} 引用了不存在的记录编号：{value}")

    inspect("结论", str(judgement.get("conclusion") or ""))
    for item in judgement.get("behaviors") or []:
        label = getattr(item, "name", None) or getattr(item, "type", None) or "行为"
        parts = [getattr(item, "analysis", "") or ""]
        parts.extend(getattr(item, "evidence", []) or [])
        inspect(str(label), " ".join(str(part) for part in parts))
    # 结构化研判字段也要溯源：攻击源 IP / 目标资产 / 涉及账号须能在日志中对上
    verdict = judgement.get("structured_verdict")
    if verdict is not None:
        for field_name, value in (
            ("攻击源IP", verdict.attack_source_ip),
            ("目标资产", verdict.target_asset),
        ):
            if value:
                inspect(field_name, value)
        # 账号同样要回退查原文：nginx combined 的 remote_user 被解析器固定为 None
        # （`_parse_web_line` 里 `"username": None` 是写死的），只查结构化字段会把
        # 日志原文里明明存在的账号报成编造 —— 与 IP / 目标资产同类的误报。
        account = verdict.involved_account
        if (
            account
            and account not in index["accounts"]
            and account not in seen
            and not appears_in_log(account)
        ):
            seen.add(account)
            claims.append(f"涉及账号 引用了日志中不存在的账号：{account}")
        target = verdict.target_asset
        if (
            target
            and not IP_PATTERN.search(target)
            and target not in index["targets"]
            and target not in seen
            and not appears_in_log(target)
        ):
            seen.add(target)
            claims.append(f"目标资产 引用了日志中不存在的主机：{target}")
    return claims


def _run_auto_tools(
    result: AnalysisResult, records: list[dict[str, str | None]]
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """确定性执行一轮只读工具，作为研判输入与调用轨迹的起点。

    **只回传上下文里没有的内容。** `log_metadata` / `log_statistics` / `timeline`
    的返回与 context 的 `metadata` / `statistics` / `timeline` 块同源，`query_events`
    的返回也与 `context.events` 高度重叠——同一份数据发两遍纯属浪费（实测域控场景
    这部分每轮多付约 14 KB）。因此这里把结果换成**摘要指针**：告诉模型「数据在哪个
    字段里、总数是多少」，需要细节时再用对应工具查询。

    工具仍然真实执行：`trace` 里保留完整调用轨迹（含 summary），前端展示不受影响。
    """

    outputs: dict[str, Any] = {}
    trace: list[dict[str, Any]] = []
    for name, arguments in AUTO_TOOL_PLAN:
        output = execute_tool(name, arguments, result, records)
        outputs[name] = _auto_tool_pointer(name, output, result)
        trace.append(
            {
                "tool": name,
                "arguments": {key: value for key, value in arguments.items() if value},
                "summary": str(output.get("summary", "")),
                "source": "auto",
            }
        )
    return outputs, trace


# 自动预取工具 → 上下文里已有的等价字段（数据只保留一份，另一份换成指针）
_AUTO_TOOL_REDUNDANT_FIELDS = {
    "log_metadata": "metadata",
    "log_statistics": "statistics",
    "query_events": "events",
    "timeline": "timeline",
}


def _auto_tool_pointer(
    name: str, output: dict[str, Any], result: AnalysisResult
) -> dict[str, Any]:
    """把重复的自动工具结果压成「指向上文已有块」的摘要，避免同一份数据发两遍。"""

    field = _AUTO_TOOL_REDUNDANT_FIELDS.get(name)
    if field is None:
        return output
    pointer: dict[str, Any] = {
        "summary": str(output.get("summary", "")),
        "data_in": field,
        "note": f"完整内容见上下文字段 {field}，此处不重复发送。",
    }
    # 保留计数类事实：它们是模型做数量表述时的锚点，体积可忽略
    for key in ("total", "event_count", "record_count", "log_type"):
        if key in output:
            pointer[key] = output[key]
    if name == "query_events":
        pointer["events_total_in_batch"] = len(result.events)
    return pointer


JSON_FORMAT_REMINDER = (
    "\n\n注意：上一次的回答无法解析为 JSON。请只输出一个 JSON 对象，"
    "不要任何解释文字、不要代码块标记。"
    "字段：has_suspicious_behavior、risk_level、confidence、summary、behaviors、recommendations。"
)


def _request_content(
    provider: Any,
    context: dict[str, Any],
    result: AnalysisResult,
    records: list[dict[str, str | None]],
    reminder: str = "",
    on_delta: Callable[[str], None] | None = None,
) -> tuple[str, list[dict[str, Any]]]:
    """取回模型的原始文本；支持工具时走工具轮次，失败则降级为单次调用。

    带 `reminder` 时（格式纠错）刻意不再走工具轮次：同一份上下文已经给过一次，
    再让它挑工具只会拖长恢复时间。
    """

    system_prompt = SYSTEM_PROMPT + reminder
    if getattr(provider, "supports_tools", False) and not reminder:
        try:
            return provider.complete_with_tools(
                system_prompt, context, result, records, on_delta=on_delta
            )
        except Exception:
            # Provider 不支持 tools 或工具轮次失败时降级为单次调用，保证研判不劣化。
            # 但**已经执行过的工具调用轨迹必须留下**：它们在降级前真实发生了，
            # 丢掉会让前端「工具调用轨迹」整片空白、用量也无从展示。
            recovered = _recover_trace(provider)
            content = provider.complete(system_prompt, context, on_delta=on_delta)
            return content, recovered
    return provider.complete(system_prompt, context, on_delta=on_delta), []


def _recover_trace(provider: Any) -> list[dict[str, Any]]:
    """从 provider 上取回「失败前已经完成」的工具轨迹与用量。

    工具轮次是边执行边累积的：第 3 轮失败时，前 2 轮的调用与用量都已真实发生。
    `complete_with_tools` 在抛出前把这些留在 `provider.last_trace`，
    这里取出并补一条 usage 记录，避免降级把已完成的部分一起抹掉。
    """

    trace = list(getattr(provider, "last_trace", None) or [])
    usage = getattr(provider, "last_usage", None) or {}
    if usage and not any(item.get("tool") == "usage" for item in trace):
        trace.append(
            {"tool": "usage", "source": "auto", "summary": "", "usage": usage}
        )
    return trace


def request_ai_judgement(
    result: AnalysisResult,
    records: list[dict[str, str | None]],
    progress_cb: Callable[[str], None] | None = None,
    delta_cb: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """执行一次 AI 研判。

    `progress_cb` 用于异步任务上报真实阶段（prepare_context / run_tools /
    call_model / parse_response / grounding）；`delta_cb` 接收模型输出的
    增量文本，**仅用于实时展示**——最终结论始终来自完整文本经结构化与证据校验后的结果，
    因此流式中断既不影响规则结果，也不影响结论。同步调用可都不传。
    """

    global _ACTIVE_RECORD_COUNT, _ACTIVE_EVENT_COUNT
    _ACTIVE_RECORD_COUNT = len(records)
    _ACTIVE_EVENT_COUNT = len(result.events)

    started = time.perf_counter()
    report = progress_cb or (lambda _stage: None)
    report("prepare_context")
    context = build_ai_context(result, records)
    report("run_tools")
    tool_outputs, trace = _run_auto_tools(result, records)
    # 自动工具结果必须在预算校验**之前**并入：它们同样占用模型的输入预算，
    # 挂在校验之后等于绕过硬上限（历史上就是这么漏的）。
    context["tool_results"] = tool_outputs
    context = _fit_context_budget(context)
    valid_evidence_ids = {
        evidence["id"]
        for event in context["events"]
        for evidence in event["evidence_items"]
    }
    valid_evidence_ids.update(
        record.get("evidence_id")
        for record in records
        if record.get("evidence_id")
    )
    record_to_evidence: dict[str, str] = {}
    for event in context["events"]:
        for evidence in event["evidence_items"]:
            record_id = evidence.get("record_id")
            if record_id and record_id not in record_to_evidence:
                record_to_evidence[record_id] = evidence["id"]
    for record in records:
        record_id = record.get("record_id")
        evidence_id = record.get("evidence_id")
        if record_id and evidence_id and record_id not in record_to_evidence:
            record_to_evidence[record_id] = evidence_id
    report("call_model")
    provider = _create_provider()
    content, extra_trace = _request_content(
        provider, context, result, records, on_delta=delta_cb
    )
    trace.extend(extra_trace)
    usage = getattr(provider, "last_usage", None) or {}
    if usage and not any(item.get("tool") == "usage" for item in trace):
        trace.append({"tool": "usage", "source": "auto", "summary": "", "usage": usage})
    report("parse_response")
    try:
        payload = _extract_json(content)
    except ValueError:
        # 模型没按约定输出 JSON。这类「格式错误」重跑整轮工具调用很浪费，改为复用同一份
        # 上下文再要一次并重申格式要求；仍失败才上报给用户。
        report("call_model")
        content, retry_trace = _request_content(
            provider, context, result, records, reminder=JSON_FORMAT_REMINDER
        )
        trace.extend(retry_trace)
        try:
            payload = _extract_json(content)
        except ValueError as exc:
            # 不要把 json 的原始报错抛给用户（"Expecting value: line 1 column 1" 没有可行动信息）
            raise RuntimeError(
                "AI 连续两次未按约定返回 JSON 结论，请稍后重试或检查所用模型是否支持结构化输出。"
            ) from exc
    judgement = _validate_response(payload, valid_evidence_ids, record_to_evidence)
    report("grounding")
    judgement["tool_trace"] = trace
    judgement["unsupported_claims"] = _check_grounding(judgement, result, records)
    # 成本 × 质量联合指标（P3 ①②③）：账单、上下文体量、逐事件/逐证据体量、证据引用覆盖。
    # 只读观测，不参与研判判定，也不改变任何结论。
    referenced: list[str] = []
    for behavior in judgement["behaviors"]:
        for evidence_id in behavior.evidence_ids:
            if evidence_id not in referenced:
                referenced.append(evidence_id)
    judgement["metrics"] = ai_metrics.build_metrics(
        context=context,
        result=result,
        tool_trace=trace,
        evidence_referenced=referenced,
        duration_ms=(time.perf_counter() - started) * 1000,
        prices=_price_table(),
    ).to_payload()
    return judgement


def test_ai_connection() -> dict[str, Any]:
    config = check_ai_config()
    if not config.configured:
        return {
            "configured": False,
            "reachable": False,
            "provider": config.provider,
            "model": config.model,
            "message": config.message,
        }
    try:
        content = _create_provider().complete(
            SYSTEM_PROMPT,
            {
                "purpose": "connection_test",
                "instruction": "Return a JSON object with a single key named status and value ok.",
            },
        )
        if not content.strip():
            raise RuntimeError("AI 服务返回空响应")
    except Exception as exc:
        return {
            "configured": True,
            "reachable": False,
            "provider": config.provider,
            "model": config.model,
            "message": str(exc),
        }
    return {
        "configured": True,
        "reachable": True,
        "provider": config.provider,
        "model": config.model,
        "message": "AI Provider 连接正常。",
    }
