"""检测视图测试：归组口径与规则元数据补全。

重点钉住两个容易混的口径：`event_count`（事件条数）与 `trigger_count`（触发次数合计），
以及「Sigma 导入规则要在提示里如实标注可靠性低于内置规则」。
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app
from app.models import AnalysisResult, Event, LogMetadata, LogStatistics
from app.services.detections import build_detections

client = TestClient(app)


def _event(
    event_id: str,
    rule_id: str | None,
    risk_level: str,
    count: int = 1,
    source_ip: str | None = None,
    event_type: str = "ssh.bruteforce",
) -> Event:
    return Event(
        id=event_id,
        type=event_type,
        name=f"{rule_id or event_type} 事件",
        risk_level=risk_level,
        source_ip=source_ip,
        rule_id=rule_id,
        count=count,
        first_seen="2026-09-12T09:00:00+00:00",
        last_seen="2026-09-12T09:10:00+00:00",
        source_files=["auth.log"],
        summary=f"{rule_id} 命中",
    )


def _result(events: list[Event]) -> AnalysisResult:
    return AnalysisResult(
        id="a1",
        metadata=LogMetadata(
            filename="auth.log",
            log_type="ssh",
            recognition_confidence=1.0,
            total_lines=10,
            parsed_lines=10,
            time_range={},
        ),
        statistics=LogStatistics(),
        events=events,
        summary="",
    )


def test_groups_by_rule_with_both_count_units():
    events = [
        _event("e1", "ssh.bruteforce", "high", count=120, source_ip="10.0.0.8"),
        _event("e2", "ssh.bruteforce", "high", count=30, source_ip="10.0.0.9"),
        _event("e3", "web.404_scan", "medium", count=22, source_ip="10.0.0.10"),
    ]
    report = build_detections("a1", _result(events))
    assert report.groups_total == 2
    top = report.groups[0]
    assert top.rule_id == "ssh.bruteforce"
    assert top.event_count == 2  # 两条事件
    assert top.trigger_count == 150  # 触发次数合计
    assert top.entities == ["10.0.0.8", "10.0.0.9"]
    assert top.variants_total == 2


def test_groups_sorted_by_risk_then_event_count():
    events = [
        _event("e1", "web.404_scan", "medium"),
        _event("e2", "ssh.bruteforce", "high"),
        _event("e3", "ssh.bruteforce", "high"),
        _event("e4", "windows.sam_registry_dump", "critical"),
    ]
    report = build_detections("a1", _result(events))
    assert [group.rule_id for group in report.groups] == [
        "windows.sam_registry_dump",
        "ssh.bruteforce",
        "web.404_scan",
    ]


def test_rule_metadata_is_attached():
    report = build_detections("a1", _result([_event("e1", "ssh.bruteforce", "high")]))
    group = report.groups[0]
    assert group.source == "builtin"
    assert group.tactic == "凭据访问"
    assert group.technique
    assert group.description
    assert group.source_files == ["auth.log"]
    # `validation_status` 来自规则元数据。内置规则已在 YAML 里声明 `validated`，
    # 依据是标注语料 74/74 覆盖（口径由 `scripts/eval_rules.py` 的元数据门禁核对，
    # 见 docs/IMPROVEMENT_ROADMAP.md P5-①）——不是「未声明 → 默认 unverified」了。
    assert group.validation_status == "validated"


def test_note_marks_sigma_groups_as_unverified():
    # 用一条不存在的 rule_id 模拟导入规则：规则清单里查不到 → source 记 unknown
    report = build_detections("a1", _result([_event("e1", "sigma.imported.rule", "high")]))
    assert report.note


def test_variants_are_capped_and_total_kept():
    events = [
        _event(f"e{index}", "ssh.bruteforce", "high", source_ip=f"10.0.0.{index}")
        for index in range(30)
    ]
    report = build_detections("a1", _result(events))
    group = report.groups[0]
    assert len(group.variants) == 20
    assert group.variants_total == 30  # 截断处必须给出总数


def test_events_without_rule_id_fall_back_to_event_type():
    event = _event("e1", None, "medium", event_type="web_scan_candidate")
    report = build_detections("a1", _result([event]))
    assert report.groups[0].rule_id == "web_scan_candidate"


def test_detections_endpoint():
    assert client.get("/api/analysis/missing/detections").status_code == 404
    demos = client.get("/api/demo/logs").json()
    if not demos:
        import pytest

        pytest.skip("演示日志库为空")
    created = client.post("/api/demo/analyze", json={"files": [demos[0]["path"]]})
    analysis_id = created.json()["analysis_id"]
    response = client.get(f"/api/analysis/{analysis_id}/detections")
    assert response.status_code == 200
    body = response.json()
    assert body["analysis_id"] == analysis_id
    assert isinstance(body["groups"], list)
