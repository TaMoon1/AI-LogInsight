"""概览看板：把一次分析结果排布成「一眼看清规模与分布」的样子。

参考 Zircolite 的 Overview：严重度卡片（事件数 + 命中规则数）、事件总数标题、
中轴双向时间分布、ATT&CK 战术网格、Top 榜单。

**定位**：纯展示层。所有数字都由既有 `events` / `records` / `coverage` 推导，
不新增判定、不改风险等级、不写回 `AnalysisResult`（与 IOA 行为偏离同一条纪律）。

两个单位必须分清：
- `events_total` / `severities[].events` = **事件**数（规则命中）；
- `buckets[].count` = **记录**数（日志行）。
两者混用会让「1 万条日志 8 个事件」显示成「1 万个事件」。
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime

from ..models import (
    AnalysisDashboard,
    AnalysisResult,
    RISK_ORDER,
    SeverityCell,
    TacticCell,
    TopItem,
    sort_events_by_risk,
)
from .analytics import _PHASE_ORDER, _epoch, _tactic, build_timeseries
from .attack_coverage import RULE_TECHNIQUES
from .rules import get_rules
from .tactics import tactic_from_tags, techniques_from_tags

TOP_RULES_LIMIT = 10
TOP_HOSTS_LIMIT = 8
TOP_IPS_LIMIT = 8
MAX_TECHNIQUES = 40


def _event_time_index(records: list[dict[str, str | None]]) -> dict[str, float]:
    """record_id → 时间戳（epoch）。事件靠它落到时间轴上。"""

    index: dict[str, float] = {}
    for record in records:
        record_id = record.get("record_id")
        if not record_id:
            continue
        ts = _epoch(record.get("timestamp_iso"))
        if ts is not None:
            index[record_id] = ts
    return index


def _timed_events(
    result: AnalysisResult, records: list[dict[str, str | None]]
) -> tuple[list[tuple[float, str]], int]:
    """把事件映射成（时间戳, 风险等级），返回 (列表, 无法定位时间的事件数)。

    事件自身的时间字段是日志原文（形如 `12/Sep/2026:09:59:59 +0800`），不一定可解析；
    权威时间在证据对应的记录里。两处都拿不到时**不猜时间**，只计数并如实说明。
    """

    index = _event_time_index(records)
    timed: list[tuple[float, str]] = []
    undated = 0
    for event in result.events:
        ts = None
        for item in event.evidence_items:
            if item.record_id and item.record_id in index:
                ts = index[item.record_id]
                break
        if ts is None:
            ts = _epoch(event.first_seen)
        if ts is None:
            undated += 1
            continue
        timed.append((ts, event.risk_level))
    return timed, undated


def build_dashboard(
    analysis_id: str,
    result: AnalysisResult,
    records: list[dict[str, str | None]] | None = None,
) -> AnalysisDashboard:
    records = records or []
    events = list(result.events)

    # ① 严重度卡片：事件数 + 命中规则数（每档始终返回，0 也要显示——空档本身就是信息）
    per_level_rules: dict[str, set[str]] = {level: set() for level in RISK_ORDER}
    per_level_events: Counter[str] = Counter()
    for event in events:
        per_level_events[event.risk_level] += 1
        if event.rule_id:
            per_level_rules[event.risk_level].add(event.rule_id)
    severities = [
        SeverityCell(
            risk_level=level,  # type: ignore[arg-type]
            events=per_level_events.get(level, 0),
            rules=len(per_level_rules[level]),
        )
        for level in RISK_ORDER
    ]

    # ② 时间分布：记录数（上轴）+ 事件按等级分层（下轴），共用同一套桶边界
    timed, undated = _timed_events(result, records)
    buckets = build_timeseries(records, timed_events=timed)

    # ③ ATT&CK 战术网格：按事件类型映射到战术（复用攻击链同一套映射，不另立定义）；
    # 内置映射认不出来时回退到规则的 attack.* 标签，否则 503 条 Sigma 导入规则全落「其他」
    rule_tags = {rule.id: list(rule.tags or []) for rule in get_rules()}
    tactic_events: Counter[str] = Counter()
    tactic_rules: dict[str, set[str]] = {}
    for event in events:
        tactic, _ = _tactic(event.rule_id, event.type)
        if tactic == "其他":
            tactic = tactic_from_tags(rule_tags.get(event.rule_id or "")) or tactic
        tactic_events[tactic] += 1
        tactic_rules.setdefault(tactic, set())
        if event.rule_id:
            tactic_rules[tactic].add(event.rule_id)
    tactics = [
        TacticCell(
            tactic=name,
            phase_index=index,
            events=tactic_events.get(name, 0),
            rules=len(tactic_rules.get(name, ())),
        )
        for name, index in sorted(_PHASE_ORDER.items(), key=lambda item: item[1])
    ]

    # ④ 技术计数：内置规则用 RULE_TECHNIQUES 映射，导入规则回退到 attack.Txxxx 标签
    technique_events: Counter[str] = Counter()
    for event in events:
        mapped = RULE_TECHNIQUES.get(event.rule_id or "", ())
        if not mapped:
            mapped = tuple(techniques_from_tags(rule_tags.get(event.rule_id or "")))
        for technique in mapped:
            technique_events[technique] += 1
    techniques = [
        TopItem(key=technique, label=technique, events=count)
        for technique, count in technique_events.most_common(MAX_TECHNIQUES)
    ]

    # ⑤ Top 榜单
    top_rules = _top_rules(events)
    top_hosts = _top_values(events, "target_asset", TOP_HOSTS_LIMIT)
    top_ips = _top_values(events, "source_ip", TOP_IPS_LIMIT)

    trace_note = (
        f"{undated} 个事件因缺少可解析时间未落入时间轴（不猜时间，只计数）"
        if undated
        else ""
    )
    return AnalysisDashboard(
        analysis_id=analysis_id,
        events_total=result.events_total if result.events_total is not None else len(events),
        covered_records=result.coverage.covered_records,
        total_records=result.coverage.total_records,
        severities=severities,
        buckets=buckets,
        tactics=tactics,
        techniques=techniques,
        top_rules=top_rules,
        top_hosts=top_hosts,
        top_ips=top_ips,
        generated_at=datetime.now().astimezone().isoformat(timespec="seconds"),
        note=trace_note,
    )


def _top_rules(events) -> list[TopItem]:
    """按触发次数降序的规则榜；同一规则的多条事件合并为一条。"""

    grouped: dict[str, dict] = {}
    for event in sort_events_by_risk(events):
        key = event.rule_id or event.type
        entry = grouped.setdefault(
            key,
            {"label": event.name, "risk_level": event.risk_level, "events": 0},
        )
        entry["events"] += 1
        if RISK_ORDER.index(event.risk_level) > RISK_ORDER.index(entry["risk_level"]):
            entry["risk_level"] = event.risk_level
    ranked = sorted(
        grouped.items(), key=lambda item: (-item[1]["events"], item[1]["label"])
    )[:TOP_RULES_LIMIT]
    return [
        TopItem(
            key=key,
            label=value["label"],
            risk_level=value["risk_level"],
            events=value["events"],
            rules=1,
        )
        for key, value in ranked
    ]


def _top_values(events, field: str, limit: int) -> list[TopItem]:
    """按事件涉及的实体计数（主机侧日志看 target_asset，网络侧看 source_ip）。"""

    grouped: dict[str, dict] = {}
    for event in events:
        value = getattr(event, field, None)
        if not value:
            continue
        entry = grouped.setdefault(
            value, {"risk_level": event.risk_level, "events": 0, "rules": set()}
        )
        entry["events"] += 1
        if event.rule_id:
            entry["rules"].add(event.rule_id)
        if RISK_ORDER.index(event.risk_level) > RISK_ORDER.index(entry["risk_level"]):
            entry["risk_level"] = event.risk_level
    ranked = sorted(
        grouped.items(), key=lambda item: (-item[1]["events"], item[0])
    )[:limit]
    return [
        TopItem(
            key=key,
            label=key,
            risk_level=value["risk_level"],
            events=value["events"],
            rules=len(value["rules"]),
        )
        for key, value in ranked
    ]
