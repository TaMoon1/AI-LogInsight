"""概览看板测试：口径正确性优先于外观。

两条最容易错的口径都用测试钉住：
① 事件数与记录数不能混（`events_total` vs `buckets[].count`）；
② 事件落到时间轴必须与记录共用同一套桶边界，且拿不到时间时**不猜**。
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app
from app.models import (
    AnalysisResult,
    Event,
    EvidenceItem,
    DetectionCoverage,
    LogMetadata,
    LogStatistics,
)
from app.services.dashboard import build_dashboard

client = TestClient(app)


def _event(
    event_id: str,
    rule_id: str | None,
    risk_level: str,
    source_ip: str | None = None,
    target_asset: str | None = None,
    event_type: str = "ssh.bruteforce",
    record_ids: list[str] | None = None,
    first_seen: str | None = None,
) -> Event:
    evidence_items = [
        EvidenceItem(id=f"evidence-{record_id}", record_id=record_id, raw="raw line")
        for record_id in (record_ids or [])
    ]
    return Event(
        id=event_id,
        type=event_type,
        name=f"{rule_id or event_type} 事件",
        risk_level=risk_level,
        source_ip=source_ip,
        target_asset=target_asset,
        rule_id=rule_id,
        first_seen=first_seen,
        evidence_items=evidence_items,
        summary="",
    )


def _result(events: list[Event], coverage: DetectionCoverage | None = None) -> AnalysisResult:
    return AnalysisResult(
        id="a1",
        metadata=LogMetadata(
            filename="t.log",
            log_type="ssh",
            recognition_confidence=1.0,
            total_lines=0,
            parsed_lines=0,
            time_range={},
        ),
        statistics=LogStatistics(),
        events=events,
        coverage=coverage or DetectionCoverage(total_records=10, covered_records=3),
        summary="",
    )


def _record(record_id: str, iso: str, source_ip: str = "10.0.0.1") -> dict[str, str]:
    return {
        "record_id": record_id,
        "timestamp_iso": iso,
        "source_ip": source_ip,
        "timestamp": iso,
    }


def test_severity_cells_cover_all_levels_with_rule_counts():
    events = [
        _event("e1", "ssh.bruteforce", "high"),
        _event("e2", "ssh.bruteforce", "high"),
        _event("e3", "web.404_scan", "medium"),
        _event("e4", "ssh.bruteforce", "critical"),
    ]
    dashboard = build_dashboard("a1", _result(events), [])
    by_level = {cell.risk_level: cell for cell in dashboard.severities}
    assert [cell.risk_level for cell in dashboard.severities] == [
        "info", "low", "medium", "high", "critical",
    ]
    assert by_level["high"].events == 2
    assert by_level["high"].rules == 1  # 同一规则两条事件只算一条规则
    assert by_level["medium"].events == 1
    assert by_level["critical"].events == 1
    assert by_level["info"].events == 0  # 空档也要出现


def test_units_are_not_mixed_between_events_and_records():
    records = [_record(f"record-{i}", f"2026-09-12T09:{i:02d}:00+08:00") for i in range(10)]
    events = [_event("e1", "ssh.bruteforce", "high", record_ids=["record-1"])]
    dashboard = build_dashboard("a1", _result(events), records)
    assert dashboard.events_total == 1
    assert sum(bucket.count for bucket in dashboard.buckets) == 10  # 记录数


def test_events_share_the_record_bucket_boundaries():
    records = [
        _record("record-1", "2026-09-12T09:00:00+00:00"),
        _record("record-2", "2026-09-12T09:00:10+00:00"),
        _record("record-3", "2026-09-12T09:20:00+00:00"),
    ]
    events = [
        _event("e1", "ssh.bruteforce", "high", record_ids=["record-1"]),
        _event("e2", "ssh.bruteforce", "medium", record_ids=["record-3"]),
    ]
    dashboard = build_dashboard("a1", _result(events), records)
    assert sum(sum(bucket.levels.values()) for bucket in dashboard.buckets) == 2
    # 注意：不能用 label 当键——分桶可能细到秒，而 label 只到分钟，会重名
    assert any(bucket.levels.get("high") == 1 for bucket in dashboard.buckets)
    assert any(bucket.levels.get("medium") == 1 for bucket in dashboard.buckets)
    # 同一套桶：记录总数仍然对得上，说明没有为事件另建一条时间轴
    assert sum(bucket.count for bucket in dashboard.buckets) == 3


def test_events_outside_record_range_clamp_into_nearest_bucket():
    records = [
        _record("record-1", "2026-09-12T09:00:00+00:00"),
        _record("record-2", "2026-09-12T09:00:10+00:00"),
    ]
    # 事件证据指向的记录时间远早于记录范围（例如证据被抽样时只留了部分记录）
    far_record = _record("record-far", "2020-01-01T00:00:00+00:00")
    events = [_event("e1", "ssh.bruteforce", "high", record_ids=["record-far"])]
    dashboard = build_dashboard("a1", _result(events), records + [far_record])
    placed = sum(sum(bucket.levels.values()) for bucket in dashboard.buckets)
    assert placed == 1  # 被丢弃会让「有事件但时间轴上看不到」变成查不出的假象


def test_undated_events_are_counted_not_guessed():
    events = [
        _event("e1", "ssh.bruteforce", "high", record_ids=["record-missing"], first_seen=None),
        _event("e2", "ssh.bruteforce", "high", record_ids=["record-missing"], first_seen=None),
    ]
    dashboard = build_dashboard("a1", _result(events), [])
    assert "2 个事件因缺少可解析时间未落入时间轴" in dashboard.note


def test_events_with_parseable_first_seen_are_still_placed():
    records = [_record("record-1", "2026-09-12T09:00:00+00:00")]
    events = [
        _event(
            "e1",
            "ssh.bruteforce",
            "high",
            first_seen="2026-09-12T09:00:05+00:00",
        )
    ]
    dashboard = build_dashboard("a1", _result(events), records)
    assert sum(sum(bucket.levels.values()) for bucket in dashboard.buckets) == 1
    assert dashboard.note == ""


def test_tactics_are_ordered_by_phase_and_counted():
    events = [
        _event("e1", "ssh.bruteforce", "high"),  # 凭据访问
        _event("e2", "web.404_scan", "medium", event_type="web_scan_candidate"),  # 发现
    ]
    dashboard = build_dashboard("a1", _result(events), [])
    names = [cell.tactic for cell in dashboard.tactics]
    assert names[0] == "侦察"
    indexes = [cell.phase_index for cell in dashboard.tactics]
    assert indexes == sorted(indexes)
    by_tactic = {cell.tactic: cell for cell in dashboard.tactics}
    assert by_tactic["凭据访问"].events == 1
    assert by_tactic["发现"].events == 1
    assert by_tactic["凭据访问"].rules == 1


def test_techniques_come_from_rule_mapping():
    events = [_event("e1", "ssh.bruteforce", "high")]
    dashboard = build_dashboard("a1", _result(events), [])
    assert [item.key for item in dashboard.techniques] == ["T1110.001"]


def test_top_rules_sorted_and_merged():
    events = [
        _event("e1", "web.404_scan", "medium"),
        _event("e2", "ssh.bruteforce", "high"),
        _event("e3", "ssh.bruteforce", "high"),
    ]
    dashboard = build_dashboard("a1", _result(events), [])
    assert [item.key for item in dashboard.top_rules] == ["ssh.bruteforce", "web.404_scan"]
    assert dashboard.top_rules[0].events == 2
    assert dashboard.top_rules[0].risk_level == "high"


def test_top_hosts_and_ips_split_by_field():
    events = [
        _event("e1", "ssh.bruteforce", "high", source_ip="203.0.113.9"),
        _event("e2", "windows.discovery_command", "medium", target_asset="DC01"),
        _event("e3", "windows.discovery_command", "medium", target_asset="DC01"),
    ]
    dashboard = build_dashboard("a1", _result(events), [])
    assert [item.key for item in dashboard.top_hosts] == ["DC01"]
    assert dashboard.top_hosts[0].events == 2
    assert dashboard.top_hosts[0].rules == 1
    assert [item.key for item in dashboard.top_ips] == ["203.0.113.9"]


def test_dashboard_endpoint(monkeypatch):
    assert client.get("/api/analysis/nope/dashboard").status_code == 404
    demos = client.get("/api/demo/logs").json()
    if not demos:
        import pytest

        pytest.skip("演示日志库为空")
    created = client.post("/api/demo/analyze", json={"files": [demos[0]["path"]]})
    analysis_id = created.json()["analysis_id"]
    response = client.get(f"/api/analysis/{analysis_id}/dashboard")
    assert response.status_code == 200
    body = response.json()
    assert body["analysis_id"] == analysis_id
    assert len(body["severities"]) == 5
    assert body["tactics"]
