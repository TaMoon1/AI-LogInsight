"""字段概览（facet）测试：覆盖率与 Top 值口径。

要钉住的两点：
① 覆盖率的分母是**总记录数**（含该字段为空的记录），不是「有值的记录数」；
② 取值截断时必须给出真实去重总数（`values_total`），否则「就这几个值」是假象。
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app
from app.models import AnalysisResult, LogMetadata, LogStatistics
from app.services.facets import build_facets

client = TestClient(app)


def _result() -> AnalysisResult:
    return AnalysisResult(
        id="a1",
        metadata=LogMetadata(
            filename="t.log",
            log_type="web",
            recognition_confidence=1.0,
            total_lines=4,
            parsed_lines=4,
            time_range={},
        ),
        statistics=LogStatistics(),
        summary="",
    )


def _record(**overrides) -> dict[str, str | None]:
    base = {"record_id": "record-1", "source_ip": "10.0.0.8", "status": "404"}
    base.update(overrides)
    return base


def test_coverage_uses_total_records_as_denominator():
    records = [
        _record(source_ip="10.0.0.8"),
        _record(source_ip=None),
        _record(source_ip=""),
        _record(source_ip="10.0.0.9"),
    ]
    facets = build_facets("a1", _result(), records)
    field = next(item for item in facets.fields if item.name == "source_ip")
    assert facet_present(field) == 2
    assert field.coverage == 0.5  # 2 / 4，而不是 2 / 2
    assert field.values_total == 2


def facet_present(field) -> int:
    return field.present_records


def test_top_values_sorted_and_total_kept():
    records = [_record(status="404")] * 5 + [_record(status="200")] * 3 + [_record(status="500")]
    facets = build_facets("a1", _result(), records, top_values=2)
    field = next(item for item in facets.fields if item.name == "status")
    assert [item.value for item in field.values] == ["404", "200"]
    assert field.values_total == 3  # 截断了但仍给出真实去重总数


def test_empty_records_do_not_divide_by_zero():
    facets = build_facets("a1", _result(), [])
    assert facets.total_records == 0
    assert all(field.coverage == 0.0 for field in facets.fields)


def test_high_cardinality_fields_are_not_listed():
    """raw 与 command_line 刻意不列入：无区分度 / 取值近乎唯一，列进去只会刷屏。"""

    names = {field.name for field in build_facets("a1", _result(), [_record()]).fields}
    assert "raw" not in names
    assert "command_line" not in names


def test_facets_endpoint():
    assert client.get("/api/analysis/missing/facets").status_code == 404
    created = client.post("/api/demo/analyze", json={"files": ["iis/iis-access.log"]})
    analysis_id = created.json()["analysis_id"]
    response = client.get(f"/api/analysis/{analysis_id}/facets")
    assert response.status_code == 200
    body = response.json()
    assert body["total_records"] >= 1
    status_field = next(item for item in body["fields"] if item["name"] == "status")
    assert status_field["values"], "IIS 日志应能统计出状态码分布"
    assert "覆盖率" in body["note"]
