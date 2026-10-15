from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from ..models import Event, EvidenceItem

# 事件构造与时间窗工具：被声明式规则引擎与检测器共用，保证两种实现产出结构完全一致。


def record_time(record: dict[str, str | None]) -> datetime | None:
    """统一按「无时区的 UTC」参与比较，避免带时区（EVTX）与不带时区的时间戳混用报错。"""

    value = record.get("timestamp_iso")
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed


def failure_window(
    records: list[dict[str, str | None]],
    window_seconds: int,
    threshold: int,
) -> list[dict[str, str | None]]:
    """以最早的记录为锚点，取窗口内记录数首次达到阈值的连续片段。"""

    ordered = sorted(records, key=lambda record: record_time(record) or datetime.min)
    for index, start in enumerate(ordered):
        start_time = record_time(start)
        if start_time is None:
            continue
        window = [
            record
            for record in ordered[index:]
            if (record_value := record_time(record)) is not None
            and (record_value - start_time).total_seconds() <= window_seconds
        ]
        if len(window) >= threshold:
            return window
    return []


def distinct_window(
    records: list[dict[str, str | None]],
    window_seconds: int,
    field: str,
    threshold: int,
) -> list[dict[str, str | None]]:
    """窗口内指定字段的去重取值数达到阈值：用于端口扫描等「多目标」聚合。"""

    ordered = sorted(records, key=lambda record: record_time(record) or datetime.min)
    for index, start in enumerate(ordered):
        start_time = record_time(start)
        if start_time is None:
            continue
        window = [
            record
            for record in ordered[index:]
            if (record_value := record_time(record)) is not None
            and (record_value - start_time).total_seconds() <= window_seconds
        ]
        values = {record.get(field) for record in window if record.get(field)}
        if len(values) >= threshold:
            return window
    return []


def build_event(
    event_type: str,
    name: str,
    risk_level: str,
    summary: str,
    *,
    source_ip: str | None = None,
    target_asset: str | None = None,
    first_seen: str | None = None,
    last_seen: str | None = None,
    count: int = 0,
    records: list[dict[str, str | None]] | None = None,
    rule_id: str | None = None,
) -> Event:
    records = records or []
    evidence = [record["raw"] for record in records if record.get("raw")]
    evidence_items = [
        EvidenceItem(
            id=f"evidence-{event_type}-{index}",
            record_id=record.get("record_id"),
            timestamp=record.get("timestamp"),
            source_file=record.get("source_file"),
            source_ip=record.get("source_ip"),
            destination_ip=record.get("destination_ip"),
            username=record.get("username"),
            url=record.get("url"),
            destination_port=record.get("destination_port"),
            raw=record["raw"],
        )
        for index, record in enumerate(records[:10], start=1)
        if record.get("raw")
    ]
    timeline = [
        f"{record.get('timestamp', '未知时间')}：{record['raw']}"
        for record in records
        if record.get("raw")
    ]
    source_files = sorted(
        {record.get("source_file") for record in records if record.get("source_file")}
    )
    correlation_basis: list[str] = []
    if source_ip:
        correlation_basis.append("同一来源 IP")
    if target_asset:
        correlation_basis.append("同一目标资产")
    if len(source_files) > 1:
        correlation_basis.append("事件证据来自多个日志文件")
    if first_seen and last_seen and first_seen != last_seen:
        correlation_basis.append("事件时间范围存在连续记录")
    return Event(
        id=f"event-{uuid4().hex[:8]}",
        type=event_type,
        name=name,
        risk_level=risk_level,
        source_ip=source_ip,
        target_asset=target_asset,
        first_seen=first_seen,
        last_seen=last_seen,
        count=count,
        evidence=evidence[:10],
        evidence_items=evidence_items,
        timeline=timeline[:10],
        source_files=source_files,
        correlation_basis=correlation_basis,
        rule_id=rule_id,
        summary=summary,
    )
