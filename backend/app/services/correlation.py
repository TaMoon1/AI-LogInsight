from __future__ import annotations

from collections import defaultdict
import re

from ..models import RISK_ORDER, Event

MAX_ENTITIES = 10
MAX_TIMELINE_ENTRIES = 200
MAX_TERMINAL_CHAINS = 20
MAX_TERMINAL_NODES = 100
MIN_CROSS_FILES = 2

TERMINAL_NODE_FIELDS = (
    ("process_created", ("process_image", "command_line"), "进程创建"),
    ("file_activity", ("target_filename",), "文件活动"),
    ("registry_change", ("registry_key",), "注册表修改"),
    ("dns_query", ("query_name",), "DNS 查询"),
    ("outbound_connection", ("destination_ip", "destination_port"), "外联行为"),
)

ENTITY_FIELDS = (
    ("source_ip", "source_ip", "来源 IP"),
    ("destination_ip", "destination_ip", "目的 IP"),
    ("account", "username", "账户"),
)


def _risk_of(events: list[Event]) -> str:
    risk = "info"
    for event in events:
        if RISK_ORDER.index(event.risk_level) > RISK_ORDER.index(risk):
            risk = event.risk_level
    return risk


def build_entity_profiles(
    records: list[dict[str, str | None]], events: list[Event]
) -> list[dict[str, object]]:
    """按 IP / 账户串联实体：命中事件的实体，或跨多份日志文件出现的实体。"""

    event_map: dict[tuple[str, str], list[Event]] = defaultdict(list)
    for event in events:
        keys: set[tuple[str, str]] = set()
        if event.source_ip:
            keys.add(("source_ip", event.source_ip))
        for item in event.evidence_items:
            for kind, field, _ in ENTITY_FIELDS:
                value = getattr(item, field, None)
                if value:
                    keys.add((kind, value))
        for key in keys:
            event_map[key].append(event)

    profiles: dict[tuple[str, str], dict[str, object]] = {}
    for record in records:
        for kind, field, _ in ENTITY_FIELDS:
            value = record.get(field)
            if not value:
                continue
            profile = profiles.setdefault(
                (kind, value),
                {
                    "record_count": 0,
                    "timestamps": [],
                    "display_times": [],
                    "log_types": set(),
                    "source_files": set(),
                },
            )
            profile["record_count"] = int(profile["record_count"]) + 1  # type: ignore[arg-type]
            if record.get("timestamp_iso"):
                profile["timestamps"].append(record["timestamp_iso"])  # type: ignore[union-attr]
            display = record.get("timestamp") or record.get("timestamp_iso")
            if display:
                profile["display_times"].append(display)  # type: ignore[union-attr]
            if record.get("log_type"):
                profile["log_types"].add(record["log_type"])  # type: ignore[union-attr]
            if record.get("source_file"):
                profile["source_files"].add(record["source_file"])  # type: ignore[union-attr]

    results: list[dict[str, object]] = []
    for (kind, value), profile in profiles.items():
        linked = event_map.get((kind, value), [])
        log_types = sorted(profile["log_types"])  # type: ignore[arg-type]
        source_files = sorted(profile["source_files"])  # type: ignore[arg-type]
        if not linked and len(source_files) < MIN_CROSS_FILES:
            continue
        timestamps = sorted(profile["timestamps"])  # type: ignore[arg-type]
        display_times = profile["display_times"]  # type: ignore[assignment]
        label = next(item[2] for item in ENTITY_FIELDS if item[0] == kind)
        rule_ids = sorted({event.rule_id for event in linked if event.rule_id})
        parts = [f"{label} {value} 在 {len(source_files)} 份日志中出现 {profile['record_count']} 次"]
        if len(log_types) > 1:
            parts.append(f"跨 {len(log_types)} 类日志（{'、'.join(log_types)}）")
        if linked:
            parts.append(f"关联 {len(linked)} 个可疑事件（{'、'.join(rule_ids) or '未标注规则'}）")
        results.append(
            {
                "kind": kind,
                "value": value,
                "risk_level": _risk_of(linked),
                "record_count": profile["record_count"],
                "event_count": len(linked),
                "rule_ids": rule_ids,
                "log_types": log_types,
                "source_files": source_files,
                "first_seen": display_times[0] if display_times else None,
                "last_seen": display_times[-1] if display_times else None,
                "summary": "，".join(parts) + "。",
            }
        )

    results.sort(
        key=lambda item: (
            -RISK_ORDER.index(str(item["risk_level"])),
            -int(item["event_count"]),  # type: ignore[arg-type]
            -int(item["record_count"]),  # type: ignore[arg-type]
        )
    )
    return results[:MAX_ENTITIES]


def build_timeline(
    records: list[dict[str, str | None]], events: list[Event]
) -> list[dict[str, object]]:
    """把事件与事件证据合并成一条按时间排序的统一时间线。"""

    by_id = {
        record.get("record_id"): record for record in records if record.get("record_id")
    }
    entries: list[dict[str, object]] = []
    for event in events:
        first_record = None
        for item in event.evidence_items:
            record = by_id.get(item.record_id or "")
            if record and record.get("timestamp_iso"):
                first_record = record
                break
        entries.append(
            {
                "timestamp": (first_record or {}).get("timestamp") or event.first_seen,
                "timestamp_iso": (first_record or {}).get("timestamp_iso") or "",
                "kind": "event",
                "title": event.name,
                "risk_level": event.risk_level,
                "rule_id": event.rule_id,
                "source_ip": event.source_ip,
                "username": None,
                "record_id": (first_record or {}).get("record_id"),
                "source_file": ((first_record or {}).get("source_file")),
                "detail": event.summary,
            }
        )
        for item in event.evidence_items:
            record = by_id.get(item.record_id or "")
            entries.append(
                {
                    "timestamp": item.timestamp or (record or {}).get("timestamp"),
                    "timestamp_iso": (record or {}).get("timestamp_iso") or "",
                    "kind": "evidence",
                    "title": item.raw[:160],
                    "risk_level": event.risk_level,
                    "rule_id": event.rule_id,
                    "source_ip": item.source_ip,
                    "username": item.username,
                    "record_id": item.record_id,
                    "source_file": item.source_file,
                    "detail": item.raw,
                }
            )

    seen: set[tuple[str, str, str | None]] = set()
    unique: list[dict[str, object]] = []
    for entry in sorted(entries, key=lambda item: str(item["timestamp_iso"] or "~")):
        key = (str(entry["timestamp_iso"]), str(entry["kind"]), entry["record_id"])  # type: ignore[arg-type]
        if key in seen:
            continue
        seen.add(key)
        unique.append(entry)
    return unique[:MAX_TIMELINE_ENTRIES]


def build_terminal_evidence_chains(
    records: list[dict[str, str | None]], events: list[Event]
) -> list[dict[str, object]]:
    """按目标资产聚合终端行为，并为每个节点保留统一证据编号。"""

    event_risk_by_record: dict[str, str] = {}
    for event in events:
        for item in event.evidence_items:
            if item.record_id:
                current = event_risk_by_record.get(item.record_id, "info")
                if RISK_ORDER.index(event.risk_level) > RISK_ORDER.index(current):
                    event_risk_by_record[item.record_id] = event.risk_level

    groups: dict[str, dict[str, object]] = {}
    for record in records:
        node_fields: list[tuple[str, str, str]] = []
        for kind, fields, label in TERMINAL_NODE_FIELDS:
            values = [str(record.get(field) or "").strip() for field in fields]
            values = [value for value in values if value]
            if values:
                node_fields.append((kind, label, " / ".join(values)))
        if not node_fields:
            continue

        asset = str(record.get("target_asset") or "").strip() or None
        source_ip = str(record.get("source_ip") or "").strip() or None
        if asset:
            group_key = f"asset:{asset}"
        elif source_ip:
            group_key = f"source:{source_ip}"
        else:
            # 没有目标资产时，来源文件不是终端身份。按单条证据隔离，
            # 避免多主机行为因共用导出文件被错误拼成一条链。
            group_key = f"record:{record.get('source_file') or 'unknown-source'}:{record.get('record_id') or id(record)}"
        group = groups.setdefault(
            group_key,
            {"target_asset": asset, "records": set(), "nodes": [], "risks": []},
        )
        record_id = str(record.get("record_id") or "")
        evidence_id = str(record.get("evidence_id") or (f"evidence-{record_id}" if record_id else ""))
        risk = event_risk_by_record.get(record_id, "info")
        if risk != "info":
            group["risks"].append(risk)  # type: ignore[union-attr]
        if record_id:
            group["records"].add(record_id)  # type: ignore[union-attr]
        for kind, label, value in node_fields:
            group["nodes"].append(  # type: ignore[union-attr]
                {
                    "timestamp": record.get("timestamp"),
                    "timestamp_iso": record.get("timestamp_iso"),
                    "kind": kind,
                    "title": f"{label}：{value}",
                    "evidence_id": evidence_id or None,
                    "record_id": record.get("record_id"),
                    "source_file": record.get("source_file"),
                    "target_asset": record.get("target_asset"),
                    "process_image": record.get("process_image"),
                    "command_line": record.get("command_line"),
                    "parent_image": record.get("parent_image"),
                    "process_id": record.get("process_id"),
                    "parent_process_id": record.get("parent_process_id"),
                    "target_filename": record.get("target_filename"),
                    "registry_key": record.get("registry_key"),
                    "query_name": record.get("query_name"),
                    "query_results": record.get("query_results"),
                    "destination_ip": record.get("destination_ip"),
                    "destination_port": record.get("destination_port"),
                    "event_id": record.get("event_id"),
                    "detail": record.get("raw"),
                    "risk_level": risk,
                }
            )

    chains: list[dict[str, object]] = []
    for index, (group_key, group) in enumerate(groups.items(), start=1):
        nodes = sorted(
            group["nodes"],  # type: ignore[arg-type]
            key=lambda item: str(item.get("timestamp_iso") or "~"),
        )[:MAX_TERMINAL_NODES]
        timestamps = [str(item["timestamp"]) for item in nodes if item.get("timestamp")]
        risk = max(group["risks"], key=lambda value: RISK_ORDER.index(value), default="info")  # type: ignore[arg-type]
        target_asset = group["target_asset"]
        label = str(target_asset or group_key)
        kinds = {str(item["kind"]) for item in nodes}
        kind_labels = {
            "process_created": "进程",
            "file_activity": "文件",
            "registry_change": "注册表",
            "dns_query": "DNS",
            "outbound_connection": "外联",
        }
        behaviors = "、".join(kind_labels[kind] for kind in kind_labels if kind in kinds)
        relationships = _build_terminal_relationships(nodes)
        chains.append(
            {
                "chain_id": f"terminal-chain-{index}",
                "target_asset": target_asset,
                "risk_level": risk,
                "record_count": len(group["records"]),  # type: ignore[arg-type]
                "first_seen": timestamps[0] if timestamps else None,
                "last_seen": timestamps[-1] if timestamps else None,
                "summary": f"目标资产 {label} 按时间关联了 {behaviors} 行为，共 {len(group['records'])} 条终端证据。",
                "nodes": nodes,
                "relationships": relationships,
            }
        )
    chains.sort(
        key=lambda item: (
            -RISK_ORDER.index(str(item["risk_level"])),
            -int(item["record_count"]),
        )
    )
    return chains[:MAX_TERMINAL_CHAINS]


def _build_terminal_relationships(nodes: list[dict[str, object]]) -> list[dict[str, object]]:
    """只建立有明确字段依据的进程父子和 DNS 到外联关系。"""

    relationships: list[dict[str, object]] = []
    process_by_id: dict[str, dict[str, object]] = {}
    for node in nodes:
        process_id = str(node.get("process_id") or "").strip()
        if process_id and node.get("kind") == "process_created":
            process_by_id.setdefault(process_id, node)

    for node in nodes:
        if node.get("kind") != "process_created":
            continue
        parent_id = str(node.get("parent_process_id") or "").strip()
        if not parent_id:
            continue
        parent = process_by_id.get(parent_id)
        if parent:
            relationships.append(
                {
                    "kind": "parent_process",
                    "from_record_id": parent.get("record_id"),
                    "to_record_id": node.get("record_id"),
                    "from_evidence_id": parent.get("evidence_id"),
                    "to_evidence_id": node.get("evidence_id"),
                    "confidence": "strong",
                    "basis": f"同一目标资产内 ParentProcessId={parent_id} 对应父进程 ProcessId",
                }
            )
        else:
            parent_image = str(node.get("parent_image") or "").strip().lower()
            parent_by_image = next(
                (
                    candidate
                    for candidate in nodes
                    if candidate.get("kind") == "process_created"
                    and str(candidate.get("process_image") or "").strip().lower()
                    == parent_image
                ),
                None,
            ) if parent_image else None
            if parent_by_image:
                relationships.append(
                    {
                        "kind": "parent_process",
                        "from_record_id": parent_by_image.get("record_id"),
                        "to_record_id": node.get("record_id"),
                        "from_evidence_id": parent_by_image.get("evidence_id"),
                        "to_evidence_id": node.get("evidence_id"),
                        "confidence": "medium",
                        "basis": "ParentImage 与已记录的父进程镜像一致，但缺少可匹配的进程 ID",
                    }
                )
                continue
            relationships.append(
                {
                    "kind": "parent_process",
                    "from_record_id": None,
                    "to_record_id": node.get("record_id"),
                    "from_evidence_id": None,
                    "to_evidence_id": node.get("evidence_id"),
                    "confidence": "weak",
                    "basis": f"记录包含 ParentProcessId={parent_id}，但当前日志未找到对应父进程证据",
                }
            )

    for dns in nodes:
        if dns.get("kind") != "dns_query":
            continue
        results = str(dns.get("query_results") or "")
        if not results:
            continue
        result_ips = set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", results))
        if not result_ips:
            continue
        connection = next(
            (
                node
                for node in nodes
                if node.get("kind") == "outbound_connection"
                and str(node.get("destination_ip") or "") in result_ips
            ),
            None,
        )
        if connection:
            relationships.append(
                {
                    "kind": "dns_to_connection",
                    "from_record_id": dns.get("record_id"),
                    "to_record_id": connection.get("record_id"),
                    "from_evidence_id": dns.get("evidence_id"),
                    "to_evidence_id": connection.get("evidence_id"),
                    "confidence": "strong",
                    "basis": "DNS QueryResults 中的解析地址与后续外联目的 IP 一致",
                }
            )
    return relationships
