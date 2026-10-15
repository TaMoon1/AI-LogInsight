"""IOA 行为偏离：既要在没有攻击特征时给出偏离，又绝不能把正常流量当异常。

覆盖 `docs/ioa-behavior-baseline.md` 的口径与防噪要求：
层 1（同批次低频）+ 层 2（内置白名单），输出与 events 分离、不改风险等级。
"""

from __future__ import annotations

from app.services.analyzer import analyze_log
from app.services.behavior_baseline import MAX_DEVIATIONS, build_behavior_deviations

INTERNAL = "10.0.0.10"


def _record(**overrides) -> dict[str, str | None]:
    base: dict[str, str | None] = {
        "timestamp": "2026-09-18 10:00:00",
        "source_ip": INTERNAL,
        "destination_ip": None,
        "username": None,
        "action": "GET",
        "result": None,
        "status": "200",
        "url": None,
        "destination_port": None,
        "protocol": None,
        "query_name": None,
        "raw": "sample",
    }
    base.update(overrides)
    return base


def _kinds(records: list[dict[str, str | None]]) -> list[str]:
    return [item.kind for item in build_behavior_deviations(records)]


# ---------- 层 1：低频实体（正向） ----------


def test_rare_public_destination_ip_is_reported():
    records = [
        _record(destination_ip="203.0.113.9", destination_port="443"),
        _record(source_ip="10.0.0.11"),
        _record(source_ip="10.0.0.12"),
    ]
    deviations = build_behavior_deviations(records)
    assert [item.kind for item in deviations] == ["rare_destination_ip"]
    assert "203.0.113.9" in deviations[0].detail
    assert deviations[0].basis == "与本批次全部记录相比仅出现 1 次"


def test_rare_domain_query_is_reported_with_basis():
    records = [_record(query_name="news.axonbyte.org")]
    deviations = build_behavior_deviations(records)
    assert [item.kind for item in deviations] == ["rare_domain_query"]
    assert "news.axonbyte.org" in deviations[0].detail
    # 口径必须写明「与本批次相比」，不得暗示历史首次
    assert "与本批次" in deviations[0].basis


def test_unusual_outbound_port_is_reported():
    records = [_record(destination_ip="203.0.113.9", destination_port="8000")]
    deviations = build_behavior_deviations(records)
    # 同一记录会同时命中「唯一目的地址」与「非常用端口」，两者是不同视角，均保留
    ports = [item for item in deviations if item.kind == "unusual_outbound_port"]
    assert len(ports) == 1
    # 详情文案必须与实际命中的端口一致
    assert "203.0.113.9:8000" in ports[0].detail
    assert ":443" not in ports[0].detail


def test_rare_public_source_ip_with_success_is_reported():
    records = [
        _record(source_ip="198.51.100.7", status="200"),
        _record(source_ip="10.0.0.11"),
        _record(source_ip="10.0.0.12"),
    ]
    assert "rare_source_ip" in _kinds(records)


def test_rare_url_path_is_reported_when_baseline_exists():
    records = [_record(url="/api/data") for _ in range(5)]
    records.append(_record(url="/admin/export"))
    deviations = build_behavior_deviations(records)
    assert [item.kind for item in deviations] == ["rare_url_path"]
    assert "/admin/export" in deviations[0].detail


# ---------- 层 2：白名单（防噪，关键） ----------


def test_private_destination_ip_is_not_reported():
    records = [
        _record(destination_ip="10.1.2.3", destination_port="445"),
        _record(source_ip="10.0.0.11"),
        _record(source_ip="10.0.0.12"),
    ]
    assert _kinds(records) == []


def test_common_ports_are_not_reported():
    records = [
        _record(destination_ip="203.0.113.9", destination_port="443"),
        _record(destination_ip="203.0.113.8", destination_port="80"),
        _record(source_ip="10.0.0.11"),
    ]
    assert "unusual_outbound_port" not in _kinds(records)


def test_common_domains_are_not_reported():
    records = [
        _record(query_name="www.microsoft.com"),
        _record(query_name="update.googleapis.com"),
        _record(query_name="cdn.jsdelivr.net"),
    ]
    assert "rare_domain_query" not in _kinds(records)


def test_internal_hostnames_are_not_reported():
    records = [
        _record(query_name="fileserver"),
        _record(query_name="printer.local"),
        _record(query_name="srv01.corp"),
    ]
    assert "rare_domain_query" not in _kinds(records)


def test_internal_one_off_sources_are_not_reported():
    """内网地址只出现一次属正常（不同终端/用户），不得当成偏离。"""

    records = [
        _record(source_ip="192.168.1.50", status="200"),
        _record(source_ip="192.168.1.51", status="200"),
        _record(source_ip="::1", status="200"),
    ]
    assert _kinds(records) == []


def test_failed_one_off_source_is_not_reported():
    records = [
        _record(source_ip="198.51.100.9", status="404"),
        _record(source_ip="10.0.0.11"),
    ]
    assert "rare_source_ip" not in _kinds(records)


def test_static_assets_are_not_reported_as_rare_paths():
    records = [_record(url="/api/data") for _ in range(5)]
    records.append(_record(url="/assets/logo-2026.png"))
    assert "rare_url_path" not in _kinds(records)


def test_high_cardinality_url_log_is_suppressed():
    """路径几乎都唯一时「唯一」不携带信息 → 整体抑制，避免刷屏。"""

    records = [_record(url=f"/page/{index}") for index in range(30)]
    assert "rare_url_path" not in _kinds(records)


def test_deviations_are_capped():
    records = [
        _record(query_name=f"host{index}.example-{index}.net")
        for index in range(MAX_DEVIATIONS + 10)
    ]
    assert len(build_behavior_deviations(records)) == MAX_DEVIATIONS


# ---------- 与结论、events 的关系 ----------


def test_deviations_do_not_change_risk_level_or_events():
    log = (
        '198.51.100.7 - - [12/Sep/2026:06:00:00 +0800] "GET /portal HTTP/1.1" 200 1 "-" "Mozilla/5.0"\n'
        '10.0.0.11 - - [12/Sep/2026:06:00:01 +0800] "POST /gateway/login HTTP/1.1" 401 1 "-" "Mozilla/5.0"\n'
    )
    result = analyze_log("deviations.log", log)
    assert result.events == []
    assert result.behavior_deviations
    assert result.risk_level == "info"
    assert result.coverage.limitation is None


def test_conclusion_reports_deviations_instead_of_no_anomaly():
    log = (
        '198.51.100.7 - - [12/Sep/2026:06:00:00 +0800] "GET /portal HTTP/1.1" 200 1 "-" "Mozilla/5.0"\n'
        '10.0.0.11 - - [12/Sep/2026:06:00:01 +0800] "POST /gateway/login HTTP/1.1" 401 1 "-" "Mozilla/5.0"\n'
    )
    result = analyze_log("deviations.log", log)
    assert "未发现明确攻击特征" in result.conclusion
    assert f"{len(result.behavior_deviations)} 项行为偏离" in result.conclusion
    assert "没有发现" not in result.conclusion
    assert "低置信度" in result.summary
    assert any("逐项核实" in item or "行为偏离" in item for item in result.recommendations)


def test_clean_log_without_deviations_still_reports_no_anomaly():
    log = (
        '10.0.0.11 - - [12/Sep/2026:06:00:00 +0800] "GET /index.html HTTP/1.1" 200 5120 "-" "Mozilla/5.0"\n'
        '10.0.0.11 - - [12/Sep/2026:06:00:01 +0800] "GET /static/app.js HTTP/1.1" 200 20480 "-" "Mozilla/5.0"\n'
    )
    result = analyze_log("clean.log", log)
    assert result.behavior_deviations == []
    assert "没有发现" in result.conclusion


def test_deviations_are_exposed_by_upload_api():
    from fastapi.testclient import TestClient

    from app.main import app

    client = TestClient(app)
    log = (
        '198.51.100.7 - - [12/Sep/2026:06:00:00 +0800] "GET /portal HTTP/1.1" 200 1 "-" "Mozilla/5.0"\n'
        '10.0.0.11 - - [12/Sep/2026:06:00:01 +0800] "POST /gateway/login HTTP/1.1" 401 1 "-" "Mozilla/5.0"\n'
    )
    response = client.post("/api/logs/upload", files={"file": ("d.log", log, "text/plain")})
    assert response.status_code == 200
    body = response.json()["result"]
    assert body["behavior_deviations"], body
    first = body["behavior_deviations"][0]
    assert set(first) == {"kind", "name", "basis", "detail", "count", "evidence"}
    assert first["basis"]

def _time_kinds(log: str) -> set[str]:
    return {item.kind for item in analyze_log("t.log", log).behavior_deviations}


TIME_KINDS = {
    "off_hours_activity",
    "entity_time_shift",
    "burst_activity",
    "periodic_heartbeat",
}


def test_off_hours_activity_is_reported_but_does_not_raise_risk():
    """深夜活动属低置信度提示——按 IOA 约定不得改变风险等级。"""

    log = "\n".join(
        [
            '203.0.113.5 - - [21/Sep/2026:23:40:00 +0800] "GET /a HTTP/1.1" 200 1 "-" "ua"',
            '203.0.113.5 - - [21/Sep/2026:05:10:00 +0800] "GET /b HTTP/1.1" 200 1 "-" "ua"',
        ]
    )
    result = analyze_log("t.log", log)
    assert "off_hours_activity" in _time_kinds(log)
    assert result.risk_level in ("info", "low")
    assert result.events == []


def test_working_hours_activity_is_not_flagged():
    log = "\n".join(
        [
            '203.0.113.5 - - [21/Sep/2026:09:40:00 +0800] "GET /a HTTP/1.1" 200 1 "-" "ua"',
            '203.0.113.5 - - [21/Sep/2026:14:10:00 +0800] "GET /b HTTP/1.1" 200 1 "-" "ua"',
        ]
    )
    assert not (_time_kinds(log) & TIME_KINDS)


def test_entity_time_shift_requires_working_and_off_hours_activity():
    log = "\n".join(
        [
            '203.0.113.31 - admin [21/Sep/2026:10:40:00 +0800] "GET /health HTTP/1.1" 200 1 "-" "ua"',
            '203.0.113.31 - admin [21/Sep/2026:23:40:00 +0800] "GET /admin HTTP/1.1" 200 1 "-" "ua"',
        ]
    )
    deviations = build_behavior_deviations(
        [
            {
                "source_ip": "203.0.113.31",
                "username": "admin",
                "timestamp_iso": "2026-09-21T10:40:00+08:00",
                "raw": "work-hours event",
            },
            {
                "source_ip": "203.0.113.31",
                "username": "admin",
                "timestamp_iso": "2026-09-21T23:40:00+08:00",
                "raw": "off-hours event",
            },
        ]
    )
    shifts = [item for item in deviations if item.kind == "entity_time_shift"]
    assert len(shifts) == 2
    assert all("时间范围" in item.detail for item in shifts)
    assert all(item.evidence for item in shifts)


def test_entity_time_shift_does_not_flag_single_time_band():
    records = [
        {
            "source_ip": "203.0.113.32",
            "username": "admin",
            "timestamp_iso": "2026-09-21T23:40:00+08:00",
            "raw": "off-hours event",
        },
        {
            "source_ip": "203.0.113.32",
            "username": "admin",
            "timestamp_iso": "2026-09-22T01:40:00+08:00",
            "raw": "off-hours event",
        },
    ]
    assert not any(
        item.kind == "entity_time_shift" for item in build_behavior_deviations(records)
    )


def test_burst_activity_requires_a_comparison_baseline():
    """单来源日志没有对照，「高频」不携带信息——否则任何批量导出都会触发。"""

    single = "\n".join(
        f'203.0.113.9 - - [21/Sep/2026:14:00:{i % 60:02d} +0800] "GET /p{i} HTTP/1.1" 200 1 "-" "ua"'
        for i in range(35)
    )
    assert "burst_activity" not in _time_kinds(single)

    mixed = single + "\n" + "\n".join(
        f'203.0.113.{60 + i} - - [21/Sep/2026:14:0{i}:00 +0800] "GET /x HTTP/1.1" 200 1 "-" "ua"'
        for i in range(5)
    )
    assert "burst_activity" in _time_kinds(mixed)


def test_periodic_heartbeat_only_for_regular_intervals():
    regular = "\n".join(
        f'203.0.113.20 - - [21/Sep/2026:10:{i:02d}:00 +0800] "GET /hb HTTP/1.1" 200 1 "-" "ua"'
        for i in range(7)
    )
    assert "periodic_heartbeat" in _time_kinds(regular)

    irregular = "\n".join(
        f'203.0.113.21 - - [21/Sep/2026:10:{minute:02d}:00 +0800] "GET /hb HTTP/1.1" 200 1 "-" "ua"'
        for minute in (0, 3, 4, 11, 12, 25)
    )
    assert "periodic_heartbeat" not in _time_kinds(irregular)


def test_time_deviations_are_silent_on_existing_scenarios():
    """现有场景日志不得产生时间维度偏离（防误报回归网）。"""

    from pathlib import Path as _Path

    root = _Path(__file__).resolve().parents[1] / "evaluation" / "scenarios"
    for path in sorted(root.glob("*.log")):
        log = path.read_text(encoding="utf-8", errors="replace")
        assert not (_time_kinds(log) & TIME_KINDS), f"{path.name} 触发了时间维度偏离"
