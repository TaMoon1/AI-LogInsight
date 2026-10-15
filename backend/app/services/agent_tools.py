from __future__ import annotations

from typing import Any

from ..models import AnalysisResult
from .detector import detect_events_with_coverage
from .sanitizer import sanitize_text

MAX_EVENT_LIMIT = 50
MAX_EVIDENCE_LIMIT = 50
MAX_TIMELINE_LIMIT = 100
MAX_RECORD_LIMIT = 50
MAX_CHAIN_LIMIT = 20
# 单条链最多下发多少节点：实测一条链可达 100 个节点 / 71 KB，占一次「全工具查询」
# 体积的 60% 以上。链路是辅助视图（不是攻击结论），保留时间序前 N 个足够判断行为形态。
MAX_CHAIN_NODES = 40
# 终端证据链节点的字段白名单：只保留有判定价值的字段，其余（含恒为 null 的字段）丢弃。
CHAIN_NODE_FIELDS = (
    "timestamp", "kind", "title", "evidence_id", "record_id", "risk_level",
    "process_image", "command_line", "parent_image", "process_id", "parent_process_id",
    "target_filename", "registry_key", "query_name", "query_results",
    "destination_ip", "destination_port", "event_id", "detail",
)

# 只读工具：只能读取已解析的日志上下文，不能执行任何系统操作（AGENTS.md §3/§6）
AGENT_TOOLS: tuple[dict[str, Any], ...] = (
    {
        "type": "function",
        "function": {
            "name": "log_metadata",
            "description": "读取本次分析的日志类型、来源文件、行数、解析情况与时间范围。",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "log_statistics",
            "description": "读取认证成功/失败计数、来源 IP / 账户 / 状态码 Top 统计。",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "query_events",
            "description": "按规则编号、风险等级或事件类型查询检测引擎发现的可疑事件。",
            "parameters": {
                "type": "object",
                "properties": {
                    "rule_id": {"type": "string", "description": "规则编号，例如 ssh.bruteforce"},
                    "risk_level": {
                        "type": "string",
                        "description": "风险等级：critical / high / medium / low / info",
                    },
                    "event_type": {"type": "string", "description": "事件类型标识"},
                    "limit": {"type": "integer", "description": "最多返回条数，默认 20"},
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "query_evidence",
            "description": "获取事件或指定记录对应的日志证据，包含证据编号与原始日志。",
            "parameters": {
                "type": "object",
                "properties": {
                    "event_id": {"type": "string", "description": "事件 ID"},
                    "record_id": {"type": "string", "description": "日志记录 ID，例如 record-12"},
                    "evidence_id": {"type": "string", "description": "事件或普通日志证据编号，例如 evidence-record-12"},
                    "limit": {"type": "integer", "description": "最多返回条数，默认 20"},
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "timeline",
            "description": "获取统一时间线：可疑事件与其日志证据按时间排序后的序列。",
            "parameters": {
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "description": "最多返回条数，默认 30"},
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "query_behavior_deviations",
            "description": "查询本批次内相对基线的行为偏离，例如首次出现的公网地址、域名、非常用端口和罕见路径。",
            "parameters": {
                "type": "object",
                "properties": {
                    "kind": {"type": "string", "description": "偏离类型，可选 rare_destination_ip、rare_domain_query、unusual_outbound_port、rare_source_ip、rare_url_path"},
                    "limit": {"type": "integer", "description": "最多返回条数，默认 20"},
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "query_uncovered_records",
            "description": "查询没有被任何当前检测规则覆盖的已解析日志记录，用于识别检测盲区，不能把未覆盖当成正常。",
            "parameters": {
                "type": "object",
                "properties": {
                    "log_type": {"type": "string", "description": "按日志类型筛选"},
                    "limit": {"type": "integer", "description": "最多返回条数，默认 20"},
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "query_records",
            "description": "按条件查询原始日志记录（不只是样本），用于核实某个来源、账号、路径或状态码下到底发生了什么。字段名可选：source_ip、target_asset、username、status、action、url、process_image、command_line、target_filename、registry_key、query_name、destination_ip、destination_port、event_id。不填 field 时按整条原始内容匹配。",
            "parameters": {
                "type": "object",
                "properties": {
                    "field": {"type": "string", "description": "要筛选的字段名；留空则匹配整条原始内容"},
                    "contains": {"type": "string", "description": "字段值包含该关键字（忽略大小写）"},
                    "equals": {"type": "string", "description": "字段值精确等于该值（忽略大小写）"},
                    "log_type": {"type": "string", "description": "按日志类型筛选"},
                    "limit": {"type": "integer", "description": "最多返回条数，默认 20"},
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "query_terminal_chains",
            "description": "按目标资产查询终端证据链，关联进程、文件、注册表、DNS 与外联行为；链路是日志关联结果，不等同于攻击结论。",
            "parameters": {
                "type": "object",
                "properties": {
                    "target_asset": {"type": "string", "description": "目标资产或主机标识"},
                    "kind": {"type": "string", "description": "节点类型：process_created、file_activity、registry_change、dns_query、outbound_connection"},
                    "limit": {"type": "integer", "description": "最多返回链路数，默认 10"},
                },
                "required": [],
            },
        },
    },
)


def _limit(arguments: dict[str, Any], default: int, maximum: int) -> int:
    try:
        value = int(arguments.get("limit") or default)
    except (TypeError, ValueError):
        return default
    return max(1, min(value, maximum))


def _text(value: Any) -> Any:
    return sanitize_text(value) if isinstance(value, str) else value


def tool_log_metadata(
    result: AnalysisResult, records: list[dict[str, str | None]], arguments: dict[str, Any]
) -> dict[str, Any]:
    metadata = result.metadata
    start = metadata.time_range.get("start") or "未知"
    end = metadata.time_range.get("end") or "未知"
    return {
        "summary": (
            f"日志类型 {metadata.log_type}，{len(metadata.source_files)} 份文件，"
            f"共 {metadata.total_lines} 行，已解析 {metadata.parsed_lines} 行，"
            f"时间范围 {start} ~ {end}。"
        ),
        "log_type": metadata.log_type,
        "recognition_confidence": metadata.recognition_confidence,
        "source_files": metadata.source_files,
        "total_lines": metadata.total_lines,
        "parsed_lines": metadata.parsed_lines,
        "time_range": metadata.time_range,
        "local_risk_level": result.risk_level,
        "event_count": len(result.events),
        "record_count": len(records),
    }


def tool_log_statistics(
    result: AnalysisResult, records: list[dict[str, str | None]], arguments: dict[str, Any]
) -> dict[str, Any]:
    statistics = result.statistics
    ips = "、".join(
        f"{item['value']}({item['count']})" for item in statistics.top_source_ips[:5]
    ) or "无"
    users = "、".join(
        f"{item['value']}({item['count']})" for item in statistics.top_users[:5]
    ) or "无"
    codes = "、".join(
        f"{item['value']}({item['count']})" for item in statistics.status_codes[:5]
    ) or "无"
    return {
        "summary": (
            f"认证失败 {statistics.failed_login} 次 / 成功 {statistics.successful_login} 次；"
            f"来源 IP Top：{ips}；账户 Top：{users}；状态码 Top：{codes}。"
        ),
        "failed_login": statistics.failed_login,
        "successful_login": statistics.successful_login,
        "top_source_ips": statistics.top_source_ips[:10],
        "top_users": statistics.top_users[:10],
        "status_codes": statistics.status_codes[:10],
    }


def tool_query_events(
    result: AnalysisResult, records: list[dict[str, str | None]], arguments: dict[str, Any]
) -> dict[str, Any]:
    rule_id = str(arguments.get("rule_id") or "").strip()
    risk_level = str(arguments.get("risk_level") or "").strip()
    event_type = str(arguments.get("event_type") or "").strip()
    matched = [
        event
        for event in result.events
        if (not rule_id or event.rule_id == rule_id)
        and (not risk_level or event.risk_level == risk_level)
        and (not event_type or event.type == event_type)
    ]
    limit = _limit(arguments, 20, MAX_EVENT_LIMIT)
    filters = "、".join(
        item
        for item in (
            f"规则 {rule_id}" if rule_id else "",
            f"风险 {risk_level}" if risk_level else "",
            f"类型 {event_type}" if event_type else "",
        )
        if item
    )
    return {
        "summary": (
            f"共 {len(matched)} 个事件"
            + (f"（筛选条件：{filters}）" if filters else "")
            + (f"，最高风险 {max((e.risk_level for e in matched), key=lambda v: v) if matched else '无'}。" if matched else "。")
        ),
        "total": len(matched),
        "events": [
            {
                "id": event.id,
                "type": event.type,
                "name": event.name,
                "risk_level": event.risk_level,
                "rule_id": event.rule_id,
                "source_ip": event.source_ip,
                "first_seen": event.first_seen,
                "last_seen": event.last_seen,
                "count": event.count,
                "source_files": event.source_files,
                "summary": sanitize_text(event.summary),
            }
            for event in matched[:limit]
        ],
    }


def tool_query_evidence(
    result: AnalysisResult, records: list[dict[str, str | None]], arguments: dict[str, Any]
) -> dict[str, Any]:
    event_id = str(arguments.get("event_id") or "").strip()
    record_id = str(arguments.get("record_id") or "").strip()
    evidence_id = str(arguments.get("evidence_id") or "").strip()
    collected: list[dict[str, Any]] = []
    for event in result.events:
        if event_id and event.id != event_id:
            continue
        for item in event.evidence_items:
            if record_id and item.record_id != record_id:
                continue
            if evidence_id and item.id != evidence_id:
                continue
            collected.append(
                {
                    "evidence_id": item.id,
                    "event_id": event.id,
                    "rule_id": event.rule_id,
                    "record_id": item.record_id,
                    "timestamp": item.timestamp,
                    "source_file": item.source_file,
                    "source_ip": item.source_ip,
                    "destination_ip": item.destination_ip,
                    "username": item.username,
                    "url": item.url,
                    "raw": sanitize_text(item.raw),
                }
            )
    if not event_id:
        for record in records:
            record_evidence_id = record.get("evidence_id") or (
                f"evidence-{record.get('record_id')}" if record.get("record_id") else ""
            )
            if not record_evidence_id:
                continue
            if record_id and record.get("record_id") != record_id:
                continue
            if evidence_id and record_evidence_id != evidence_id:
                continue
            collected.append(
                {
                    "evidence_id": record_evidence_id,
                    "event_id": None,
                    "rule_id": None,
                    **{
                        key: sanitize_text(record[key]) if key == "raw" and record.get(key) else record.get(key)
                        for key in (
                            "record_id", "timestamp", "source_file", "source_ip",
                            "destination_ip", "username", "url", "destination_port",
                            "process_image", "command_line", "target_filename",
                            "registry_key", "query_name", "target_asset", "event_id", "raw",
                        )
                        if record.get(key) not in (None, "")
                    },
                }
            )
    limit = _limit(arguments, 20, MAX_EVIDENCE_LIMIT)
    scope = "、".join(
        item
        for item in (
            f"事件 {event_id}" if event_id else "",
            f"记录 {record_id}" if record_id else "",
            f"证据 {evidence_id}" if evidence_id else "",
        )
        if item
    )
    return {
        "summary": f"返回 {len(collected)} 条证据" + (f"（{scope}）" if scope else "（全部事件与普通记录证据）。"),
        "total": len(collected),
        "evidence": collected[:limit],
    }


def tool_timeline(
    result: AnalysisResult, records: list[dict[str, str | None]], arguments: dict[str, Any]
) -> dict[str, Any]:
    entries = result.timeline
    limit = _limit(arguments, 30, MAX_TIMELINE_LIMIT)
    if entries:
        summary = (
            f"时间线共 {len(entries)} 条，从 {entries[0].timestamp or '未知'} 到 "
            f"{entries[-1].timestamp or '未知'}。"
        )
    else:
        summary = "当前没有事件时间线（未命中任何检测规则）。"
    return {
        "summary": summary,
        "total": len(entries),
        "entries": [
            {
                "timestamp": entry.timestamp,
                "kind": entry.kind,
                "title": sanitize_text(entry.title),
                "risk_level": entry.risk_level,
                "rule_id": entry.rule_id,
                "source_ip": entry.source_ip,
                "username": entry.username,
                "record_id": entry.record_id,
                "source_file": entry.source_file,
            }
            for entry in entries[:limit]
        ],
    }


def tool_query_behavior_deviations(
    result: AnalysisResult, records: list[dict[str, str | None]], arguments: dict[str, Any]
) -> dict[str, Any]:
    kind = str(arguments.get("kind") or "").strip()
    matched = [
        item for item in result.behavior_deviations
        if not kind or item.kind == kind
    ]
    limit = _limit(arguments, 20, MAX_RECORD_LIMIT)
    return {
        "summary": (
            f"共 {len(matched)} 项行为偏离"
            + (f"（类型：{kind}）" if kind else "")
            + "；这些偏离是低置信度核查信号，不等同于攻击结论。"
        ),
        "total": len(matched),
        "deviations": [
            {
                "kind": item.kind,
                "name": item.name,
                "basis": item.basis,
                "detail": sanitize_text(item.detail),
                "count": item.count,
                "evidence": [sanitize_text(value) for value in item.evidence],
            }
            for item in matched[:limit]
        ],
    }


def tool_query_uncovered_records(
    result: AnalysisResult, records: list[dict[str, str | None]], arguments: dict[str, Any]
) -> dict[str, Any]:
    log_type = str(arguments.get("log_type") or "").strip()
    # 事件证据通常有保留上限，不能用 evidence_items 反推覆盖度；
    # 复用检测引擎的覆盖集合，避免把「已命中但未展示全部证据」误报为盲区。
    _, covered_ids = detect_events_with_coverage(records)
    matched = [
        record for record in records
        if record.get("record_id") not in covered_ids
        and (not log_type or record.get("log_type") == log_type)
    ]
    limit = _limit(arguments, 20, MAX_RECORD_LIMIT)
    fields = (
        "evidence_id", "record_id", "timestamp", "source_file", "log_type", "source_ip",
        "destination_ip", "destination_port", "username", "action", "result",
        "status", "url", "process_image", "command_line", "target_filename",
        "registry_key", "query_name", "target_asset", "event_id", "raw",
    )
    output = [
        {
            key: sanitize_text(record[key]) if key == "raw" and record.get(key) else record.get(key)
            for key in fields
            if record.get(key) not in (None, "")
        }
        for record in matched[:limit]
    ]
    for item, record in zip(output, matched[:limit]):
        item["evidence_id"] = record.get("evidence_id") or (
            f"evidence-{record.get('record_id')}" if record.get("record_id") else None
        )
    return {
        "summary": (
            f"共 {len(matched)} 条已解析记录未被当前规则覆盖"
            + (f"（日志类型：{log_type}）" if log_type else "")
            + "；未覆盖不代表正常，只表示当前规则没有可用判据。"
        ),
        "total": len(matched),
        "records": output,
    }


def tool_query_terminal_chains(
    result: AnalysisResult, records: list[dict[str, str | None]], arguments: dict[str, Any]
) -> dict[str, Any]:
    target_asset = str(arguments.get("target_asset") or "").strip()
    kind = str(arguments.get("kind") or "").strip()
    def value(chain: Any, key: str, default: Any = None) -> Any:
        if isinstance(chain, dict):
            return chain.get(key, default)
        return getattr(chain, key, default)

    matched = [
        chain for chain in result.terminal_chains
        if (not target_asset or value(chain, "target_asset") == target_asset)
        and (not kind or any(node.get("kind") == kind for node in value(chain, "nodes", [])))
    ]
    limit = _limit(arguments, 10, MAX_CHAIN_LIMIT)
    prepared = []
    for chain in matched[:limit]:
        nodes = _chain_nodes(value(chain, "nodes", []), kind)
        prepared.append(
            {
                "chain_id": value(chain, "chain_id"),
                "target_asset": value(chain, "target_asset"),
                "risk_level": value(chain, "risk_level", "info"),
                # 按 kind 过滤后节点数会变，record_count 若仍报整链计数就与返回内容不符
                "record_count": len(nodes) if kind else value(chain, "record_count", 0),
                "first_seen": value(chain, "first_seen"),
                "last_seen": value(chain, "last_seen"),
                "summary": sanitize_text(str(value(chain, "summary", ""))),
                "nodes": nodes,
            }
        )
    return {
        "summary": (
            f"共 {len(matched)} 条终端证据链；链路仅表示按目标资产和时间的日志关联，"
            "不等同于攻击结论。"
            + (f"（目标资产：{target_asset}）" if target_asset else "")
            + (f"（仅 {kind} 节点）" if kind else "")
        ),
        "total": len(matched),
        "node_limit_per_chain": MAX_CHAIN_NODES,
        "chains": prepared,
    }


def _chain_nodes(nodes: list[dict[str, Any]], kind: str) -> list[dict[str, Any]]:
    """裁剪终端证据链节点。

    实测一条链可达 **100 个节点 / 71 KB**，而每个节点带 23 个字段——其中绝大多数
    对该节点类型恒为 null（`file_activity` 节点不会有 `destination_ip`）。原样下发
    等于把一半以上的体积花在 `null` 上，且模型要读的字段被噪声淹没。

    因此这里做三件事：
      1. 只保留链路上真正有判定价值的字段（`CHAIN_NODE_FIELDS` 白名单）；
      2. **丢弃值为 null/空串的字段**——字段缺席比显式 null 更省，语义也更清楚；
      3. 丢弃与 `timestamp` 重复的 `timestamp_iso`（同一时刻的两种写法）。
    节点按时间顺序保留前 `MAX_CHAIN_NODES` 个，并注明是否被截断。
    """

    kept: list[dict[str, Any]] = []
    for node in nodes:
        if kind and node.get("kind") != kind:
            continue
        item: dict[str, Any] = {}
        for key in CHAIN_NODE_FIELDS:
            raw = node.get(key)
            if raw in (None, ""):
                continue
            if key == "title":
                item[key] = sanitize_text(str(raw))
            elif key == "detail":
                item[key] = sanitize_text(str(raw))
            else:
                item[key] = raw
        if item:
            kept.append(item)
        if len(kept) >= MAX_CHAIN_NODES:
            break
    return kept


RECORD_QUERY_FIELDS = (
    "evidence_id", "record_id", "timestamp", "source_file", "log_type", "source_ip",
    "destination_ip", "destination_port", "username", "action", "result",
    "status", "url", "process_image", "command_line", "target_filename",
    "registry_key", "query_name", "target_asset", "event_id", "raw",
)

# 无论查询条件是什么，都必须带上这几个字段，否则模型无法把结论挂到真实证据上。
RECORD_QUERY_ALWAYS = ("evidence_id", "record_id", "timestamp")

# 查询 `raw` 时顺带下发的一组结构化标识：正文已经看到了，但模型仍需要
# 来源文件、结果、状态这些字段来归类。反过来，查某个解析字段时就不再
# 把整条 `raw` 一起下发。省掉的是重复信息，不是证据——
# `raw` 始终可以通过 `field=raw` 单独查到。
_RECORD_QUERY_RAW_SIDE = frozenset(
    {"raw", "source_file", "status", "result", "destination_port", "event_id"}
)


def _record_query_fields(field: str) -> tuple[str, ...]:
    """按查询条件决定每条记录下发哪些字段。

    未指定 field 时要看全貌，保持白名单不变；
    指定了 field（例如只看 `source_ip`）时，模型关心的是「谁在做什么」，
    把 `command_line`、`registry_key`、`query_name` 这类与本次查询无关的
    大字段一并下发，既白花钱又淹没重点。此时做投影：

      - 始终保留 `RECORD_QUERY_ALWAYS`（证据落点）；
      - 保留被查询字段本身；
      - `raw` 与解析字段互斥：查 `raw` 就只给正文，查解析字段就不给正文。
    """

    if not field or field not in RECORD_QUERY_FIELDS:
        return RECORD_QUERY_FIELDS

    keep = set(RECORD_QUERY_ALWAYS)
    keep.add(field)
    if field in _RECORD_QUERY_RAW_SIDE:
        keep |= _RECORD_QUERY_RAW_SIDE
    else:
        # 查的是解析字段：补上上下文标识，但不带原文正文
        keep |= {"log_type", "source_ip", "username", "action", "target_asset"}
        keep.discard("raw")
    return tuple(name for name in RECORD_QUERY_FIELDS if name in keep)


def tool_query_records(
    result: AnalysisResult, records: list[dict[str, str | None]], arguments: dict[str, Any]
) -> dict[str, Any]:
    """按条件查询原始记录。

    模型需要主动「去看」它怀疑的部分（某个来源在做什么、某个状态码下有哪些路径），
    只靠固定样本无法支撑泛化判断。
    """

    field = str(arguments.get("field") or "").strip()
    contains = str(arguments.get("contains") or "").strip().lower()
    equals = str(arguments.get("equals") or "").strip().lower()
    log_type = str(arguments.get("log_type") or "").strip()

    matched: list[dict[str, str | None]] = []
    for record in records:
        if log_type and (record.get("log_type") or "") != log_type:
            continue
        if field:
            value = str(record.get(field) or "")
            if contains and contains not in value.lower():
                continue
            if equals and value.lower() != equals:
                continue
            if not contains and not equals and not value:
                continue
        elif contains or equals:
            # 未指定字段时退回整条原始内容，便于按任意特征捞记录
            raw = str(record.get("raw") or "").lower()
            if contains and contains not in raw:
                continue
            if equals and raw != equals:
                continue
        matched.append(record)

    limit = _limit(arguments, 20, MAX_RECORD_LIMIT)
    fields = _record_query_fields(field)
    output = [
        {
            key: sanitize_text(record[key]) if key == "raw" and record.get(key) else record.get(key)
            for key in fields
            if record.get(key) not in (None, "")
        }
        for record in matched[:limit]
    ]
    narrowed = "（已按查询字段收窄下发）" if fields != RECORD_QUERY_FIELDS else ""
    return {
        "summary": (
            f"按条件命中 {len(matched)} 条记录（返回前 {len(output)} 条）。"
            f"条件：field={field or '全部'}, contains={contains or '-'}, "
            f"equals={equals or '-'}, log_type={log_type or '全部'}{narrowed}"
        ),
        "total_matched": len(matched),
        "records_returned": len(output),
        "records": output,
    }


TOOL_FUNCTIONS = {
    "log_metadata": tool_log_metadata,
    "log_statistics": tool_log_statistics,
    "query_events": tool_query_events,
    "query_evidence": tool_query_evidence,
    "timeline": tool_timeline,
    "query_behavior_deviations": tool_query_behavior_deviations,
    "query_uncovered_records": tool_query_uncovered_records,
    "query_terminal_chains": tool_query_terminal_chains,
    "query_records": tool_query_records,
}


def execute_tool(
    name: str,
    arguments: dict[str, Any],
    result: AnalysisResult,
    records: list[dict[str, str | None]],
) -> dict[str, Any]:
    """执行一个只读工具；未知工具或执行异常都会返回可读的错误结果，不抛出。"""

    function = TOOL_FUNCTIONS.get(name)
    if function is None:
        return {"summary": f"未知工具 {name}。", "error": f"unsupported tool: {name}"}
    try:
        return function(result, records, arguments or {})
    except Exception as exc:  # 工具失败不应中断 AI 研判
        return {"summary": f"工具 {name} 执行失败：{exc}", "error": str(exc)}
