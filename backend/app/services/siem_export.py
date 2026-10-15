"""把检测结果（事件）渲染成 SIEM 平台可导入的格式。

对应 Zircolite 对标的五套导出模板：Splunk(CIM) / Elastic(ECS) / OpenSearch(bulk) /
Timesketch / SARIF 2.1.0。

映射原则：只映射事件与证据里**真实存在**的字段，缺失的键直接不产出——
不做「猜时间」「猜用户」的填充（与 AGENTS.md §16 不允许幻觉一致）。
一条事件一条记录，`count` / 证据样本随行，便于在目标平台里复核。
"""

from __future__ import annotations

import json
from typing import Any

from ..models import Event

SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}
ECS_SEVERITY = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 1}


def _primary(event: Event):
    return event.evidence_items[0] if event.evidence_items else None


def _event_time(event: Event) -> str | None:
    return event.first_seen or event.last_seen


def _clean(payload: dict[str, Any]) -> dict[str, Any]:
    """去掉值为 None 的键：缺失字段不产出，比 null 更不容易被误用。"""

    return {key: value for key, value in payload.items() if value is not None}


def _fact_base(event: Event) -> dict[str, Any]:
    """事件本身携带的事实字段（各模板共用的原料，字段名由各模板自行映射）。"""

    evidence = _primary(event)
    return {
        "time": _event_time(event),
        "event_type": event.type,
        "event_name": event.name,
        "rule_id": event.rule_id,
        "risk_level": event.risk_level,
        "count": event.count,
        "source_ip": event.source_ip or (evidence.source_ip if evidence else None),
        "destination_ip": evidence.destination_ip if evidence else None,
        "username": evidence.username if evidence else None,
        "url": evidence.url if evidence else None,
        "user_agent": evidence.user_agent if evidence else None,
        "destination_port": evidence.destination_port if evidence else None,
        "summary": event.summary,
        "sample_raw": evidence.raw if evidence else None,
        "source_files": list(event.source_files) or None,
    }


def render_splunk(events: list[Event]) -> str:
    """Splunk CIM：JSON 数组。字段名按 CIM 惯例（src / dest / user / signature）。"""

    docs = []
    for event in events:
        base = _fact_base(event)
        docs.append(
            _clean(
                {
                    "_time": base["time"],
                    "sourcetype": "loginsight:detection",
                    "source": (base["source_files"] or [None])[0],
                    "signature": base["event_name"],
                    "rule_id": base["rule_id"],
                    "risk_level": base["risk_level"],
                    "severity": event.risk_level,
                    "src": base["source_ip"],
                    "dest": base["destination_ip"],
                    "user": base["username"],
                    "url": base["url"],
                    "dest_port": base["destination_port"],
                    "count": base["count"],
                    "message": base["summary"],
                    "sample_raw": base["sample_raw"],
                }
            )
        )
    return json.dumps(docs, ensure_ascii=False, indent=2)


def _ecs_doc(event: Event) -> dict[str, Any]:
    base = _fact_base(event)
    return _clean(
        {
            "@timestamp": base["time"],
            "event": _clean(
                {
                    "kind": "alert",
                    "dataset": "loginsight.detection",
                    "module": "loginsight",
                    "severity": ECS_SEVERITY.get(event.risk_level),
                    "reason": base["summary"],
                }
            ),
            "message": f"{base['event_name']}：{base['summary']}",
            "rule": _clean({"name": base["event_name"], "id": base["rule_id"]}),
            "labels": _clean(
                {"risk_level": base["risk_level"], "event_type": base["event_type"]}
            ),
            "source": _clean({"ip": base["source_ip"]}),
            "destination": _clean(
                {
                    "ip": base["destination_ip"],
                    "port": int(base["destination_port"])
                    if str(base["destination_port"] or "").isdigit()
                    else None,
                }
            ),
            "user": _clean({"name": base["username"]}),
            "url": _clean({"full": base["url"]}),
            "user_agent": _clean({"name": base["user_agent"]}),
        }
    )


def render_elastic(events: list[Event]) -> str:
    """Elastic ECS：NDJSON，每行一个 ECS 文档。"""

    return "\n".join(
        json.dumps(_ecs_doc(event), ensure_ascii=False) for event in events
    )


def render_opensearch(events: list[Event]) -> str:
    """OpenSearch：bulk NDJSON（_bulk 可直接导入），文档字段与 ECS 一致。"""

    lines: list[str] = []
    index_date = ""
    for event in events:
        time = _event_time(event)
        index_date = (time or "")[:10] or "unknown"
        lines.append(
            json.dumps(
                {"index": {"_index": f"loginsight-detections-{index_date}"}},
                ensure_ascii=False,
            )
        )
        lines.append(json.dumps(_ecs_doc(event), ensure_ascii=False))
    return "\n".join(lines)


def render_timesketch(events: list[Event]) -> str:
    """Timesketch：NDJSON，三要素 message / datetime / timestamp_desc。"""

    lines: list[str] = []
    for event in events:
        base = _fact_base(event)
        lines.append(
            json.dumps(
                _clean(
                    {
                        "message": f"{base['event_name']}：{base['summary']}",
                        "datetime": base["time"],
                        "timestamp_desc": "Event Recorded",
                        "data_type": "loginsight:detection",
                        "rule_id": base["rule_id"],
                        "risk_level": base["risk_level"],
                        "count": base["count"],
                        "ip": base["source_ip"],
                        "source_files": base["source_files"],
                    }
                ),
                ensure_ascii=False,
            )
        )
    return "\n".join(lines)


def render_sarif(events: list[Event]) -> str:
    """SARIF 2.1.0：规则去重进 tool.driver.rules，一条事件一个 result。"""

    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for event in events:
        rule_key = event.rule_id or event.type
        if rule_key not in rules:
            rules[rule_key] = _clean(
                {
                    "id": rule_key,
                    "name": event.name,
                    "shortDescription": {"text": event.name},
                    "properties": {"riskLevel": event.risk_level},
                }
            )
        evidence = _primary(event)
        location: dict[str, Any] | None = None
        if event.source_files:
            location = {
                "physicalLocation": {
                    "artifactLocation": {"uri": event.source_files[0]}
                }
            }
        results.append(
            _clean(
                {
                    "ruleId": rule_key,
                    "level": SARIF_LEVEL.get(event.risk_level, "note"),
                    "message": {"text": event.summary},
                    "properties": _clean(
                        {
                            "count": event.count,
                            "firstSeen": event.first_seen,
                            "lastSeen": event.last_seen,
                            "sourceIp": event.source_ip,
                            "targetAsset": event.target_asset,
                            "sampleRaw": evidence.raw if evidence else None,
                        }
                    ),
                    "locations": [location] if location else None,
                }
            )
        )
    return json.dumps(
        {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "AI-LogInsight",
                            "informationUri": "https://github.com/local/ai-loginsight",
                            "rules": list(rules.values()),
                        }
                    },
                    "results": results,
                }
            ],
        },
        ensure_ascii=False,
        indent=2,
    )


#: format 参数 → (渲染函数, 媒体类型, 文件后缀)
SIEM_EXPORT_FORMATS: dict[str, tuple[Any, str, str]] = {
    "splunk": (render_splunk, "application/json", "splunk-cim.json"),
    "elastic": (render_elastic, "application/x-ndjson", "elastic-ecs.ndjson"),
    "opensearch": (render_opensearch, "application/x-ndjson", "opensearch-bulk.ndjson"),
    "timesketch": (render_timesketch, "application/x-ndjson", "timesketch.ndjson"),
    "sarif": (render_sarif, "application/json", "report.sarif"),
}
