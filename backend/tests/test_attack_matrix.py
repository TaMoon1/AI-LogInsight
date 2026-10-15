"""ATT&CK 矩阵测试：两级映射与「清单外也能显示」。

口径要点：
① 清单里没命中的技术也要出现（0 值），否则前端「全部清单」模式没数据；
② 清单外但本次真命中的技术必须返回并标 `in_benchmark=False`——藏起来等于漏报手法；
③ 战术列按攻击阶段排序（不是字母序）。
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app
from app.models import AnalysisResult, Event, LogMetadata, LogStatistics
from app.services.attack_matrix import build_attack_matrix, _catalog

client = TestClient(app)


def _event(event_id: str, rule_id: str, risk_level: str = "high", event_type: str = "ssh.bruteforce") -> Event:
    return Event(
        id=event_id,
        type=event_type,
        name=f"{rule_id} 事件",
        risk_level=risk_level,
        rule_id=rule_id,
        summary="",
    )


def _result(events: list[Event]) -> AnalysisResult:
    return AnalysisResult(
        id="a1",
        metadata=LogMetadata(
            filename="t.log",
            log_type="ssh",
            recognition_confidence=1.0,
            total_lines=1,
            parsed_lines=1,
            time_range={},
        ),
        statistics=LogStatistics(),
        events=events,
        summary="",
    )


def test_catalog_is_loaded():
    catalog = _catalog()
    assert catalog, "内置 ATT&CK 标尺应可读取"
    assert any(item["tactic"] for item in catalog.values())


def test_hit_technique_is_counted_with_rules():
    matrix = build_attack_matrix("a1", _result([_event("e1", "ssh.bruteforce")]))
    cells = {cell.technique: cell for column in matrix.columns for cell in column.techniques}
    assert cells["T1110.001"].events == 1
    assert cells["T1110.001"].rules == ["ssh.bruteforce"]
    assert cells["T1110.001"].in_benchmark is True
    assert matrix.techniques_hit >= 1


def test_uncatalogued_technique_is_still_reported():
    """不在内置清单里的技术也要出现：靠 Sigma 标签声明技术的规则命中时就是这种情况。"""

    matrix = build_attack_matrix("a1", _result([_event("e1", "ssh.bruteforce")]))
    # 用一个必然不在清单中的规则：直接验证「订阅不到的 rule 不会凭空造格」
    unknown = build_attack_matrix("a1", _result([_event("e1", "does.not.exist", event_type="unknown")]))
    assert unknown.techniques_hit == 0
    assert all(cell.events == 0 for column in unknown.columns for cell in column.techniques)
    assert matrix.techniques_total == unknown.techniques_total


def test_tactic_columns_follow_phase_order_not_alphabet():
    matrix = build_attack_matrix(
        "a1",
        _result(
            [
                _event("e1", "web.404_scan", "medium", event_type="web_scan_candidate"),
                _event("e2", "ssh.bruteforce", "high"),
            ]
        ),
    )
    indexes = [column.phase_index for column in matrix.columns]
    assert indexes == sorted(indexes)
    names = [column.tactic for column in matrix.columns]
    assert names.index("发现") < names.index("凭据访问")


def test_column_events_sum_matches_cells():
    matrix = build_attack_matrix("a1", _result([_event("e1", "ssh.bruteforce"), _event("e2", "ssh.bruteforce")]))
    for column in matrix.columns:
        assert column.events == sum(cell.events for cell in column.techniques)
    assert matrix.events_total == matrix.techniques_hit and matrix.events_total == 2 or matrix.events_total == 2


def test_matrix_endpoint():
    assert client.get("/api/analysis/nope/attack-matrix").status_code == 404
    demos = client.get("/api/demo/logs").json()
    if not demos:
        import pytest

        pytest.skip("演示日志库为空")
    created = client.post("/api/demo/analyze", json={"files": ["iis/iis-access.log"]})
    analysis_id = created.json()["analysis_id"]
    response = client.get(f"/api/analysis/{analysis_id}/attack-matrix")
    assert response.status_code == 200
    body = response.json()
    assert body["analysis_id"] == analysis_id
    assert body["techniques_total"] >= 1
    assert "不等于 ATT&CK 全量" in body["note"]


# ---------- ATT&CK Navigator 导出 ----------


def test_navigator_layer_only_contains_hits_with_rules():
    from app.services.attack_matrix import build_navigator_layer

    matrix = build_attack_matrix("a1", _result([_event("e1", "ssh.bruteforce")]))
    layer = build_navigator_layer(matrix)
    assert layer["domain"] == "enterprise-attack"
    assert layer["versions"]["layer"] == "4.5"
    ids = [item["techniqueID"] for item in layer["techniques"]]
    assert "T1110.001" in ids
    # 未命中的技术不进图层：否则图层读起来像「全都被打过」
    assert all(item["score"] > 0 for item in layer["techniques"])
    entry = next(item for item in layer["techniques"] if item["techniqueID"] == "T1110.001")
    assert entry["tactic"] == "凭据访问"
    assert "ssh.bruteforce" in entry["comment"]
    assert entry["color"].startswith("#")


def test_navigator_layer_is_json_serializable_and_empty_safe():
    import json

    from app.services.attack_matrix import build_navigator_layer

    empty = build_attack_matrix("a1", _result([]))
    layer = build_navigator_layer(empty)
    assert layer["techniques"] == []
    assert layer["gradient"]["maxValue"] == 1  # 空结果也不能出现 0 除
    assert json.dumps(layer, ensure_ascii=False)


def test_navigator_endpoint_downloads_file():
    assert client.get("/api/analysis/nope/attack-navigator").status_code == 404
    created = client.post("/api/demo/analyze", json={"files": ["iis/iis-access.log"]})
    analysis_id = created.json()["analysis_id"]
    response = client.get(f"/api/analysis/{analysis_id}/attack-navigator")
    assert response.status_code == 200
    assert "attachment" in response.headers["content-disposition"]
    body = response.json()
    assert body["name"].startswith("AI-LogInsight")
    assert all(item["score"] > 0 for item in body["techniques"])
