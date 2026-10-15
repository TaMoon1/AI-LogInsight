"""搜索语法测试：词法、字段别名、容错与两个口径不混。

最容易被忽略的是**容错**：字段名拼错时如果静默按全文查，用户会以为「查过了，
没有」——实际是查询没生效。所以未知字段必须留下警告。
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app
from app.models import AnalysisResult, Event, LogMetadata, LogStatistics
from app.services.search import parse_query, record_matches, search

client = TestClient(app)


def _record(**overrides) -> dict[str, str | None]:
    base = {
        "record_id": "record-1",
        "source_ip": "10.0.0.8",
        "destination_ip": "10.0.0.1",
        "username": "root",
        "status": "401",
        "url": "/admin/login",
        "query_name": None,
        "process_image": None,
        "command_line": None,
        "raw": "Failed password for root from 10.0.0.8 port 22",
    }
    base.update(overrides)
    return base


def _result(events: list[Event] | None = None) -> AnalysisResult:
    return AnalysisResult(
        id="a1",
        metadata=LogMetadata(
            filename="auth.log",
            log_type="ssh",
            recognition_confidence=1.0,
            total_lines=1,
            parsed_lines=1,
            time_range={},
        ),
        statistics=LogStatistics(),
        events=events or [],
        summary="",
    )


def test_field_and_negation_parsing():
    parsed = parse_query("source_ip:10.0.0.8 -username:root")
    assert [(term.field, term.value, term.negated) for term in parsed.terms] == [
        ("source_ip", "10.0.0.8", False),
        ("username", "root", True),
    ]
    assert parsed.warnings == []


def test_quoted_phrase_keeps_spaces():
    parsed = parse_query('"failed password" src:10.0.0.8')
    assert [term.value for term in parsed.terms] == ["failed password", "10.0.0.8"]
    assert parsed.terms[0].field is None
    assert parsed.terms[1].field == "source_ip"


def test_unknown_field_warns_and_falls_back_to_fulltext():
    parsed = parse_query("sourceip:10.0.0.8")
    assert parsed.warnings and "认不出字段" in parsed.warnings[0]
    assert parsed.terms[0].field is None  # 退回全文匹配，但明确告警
    assert record_matches(_record(), parsed.terms)


def test_chinese_aliases_work():
    parsed = parse_query("账号:root")
    assert parsed.terms[0].field == "username"
    assert record_matches(_record(), parsed.terms)


def test_and_semantics_across_terms():
    terms = parse_query("source_ip:10.0.0.8 status:401").terms
    assert record_matches(_record(), terms)
    assert not record_matches(_record(status="200"), terms)


def test_negation_excludes_matches():
    terms = parse_query("-username:admin").terms
    assert record_matches(_record(), terms)
    assert not record_matches(_record(username="admin"), terms)


def test_fulltext_covers_raw_only_content():
    """只在 raw 里出现的事实也要能查到（combined log 的 Referer 就是这种情况）。"""

    record = _record(referer_free="x", raw="GET /x HTTP/1.1 200 \"http://192.168.200.51/\"")
    terms = parse_query("192.168.200.51").terms
    assert record_matches(record, terms)


def test_empty_query_is_reported_not_silently_empty():
    outcome = search("a1", _result(), [_record()], "   ")
    assert outcome.records_total == 0
    assert outcome.warnings and "请输入查询条件" in outcome.warnings[0]


def test_records_and_events_have_separate_totals():
    events = [
        Event(
            id="e1",
            type="ssh.bruteforce",
            name="SSH 爆破",
            risk_level="high",
            source_ip="10.0.0.8",
            rule_id="ssh.bruteforce",
            summary="来自 10.0.0.8 的大量失败",
        )
    ]
    records = [_record(), _record(record_id="record-2"), _record(record_id="record-3")]
    outcome = search("a1", _result(events), records, "10.0.0.8")
    assert outcome.records_total == 3
    assert outcome.events_total == 1


def test_pagination_and_true_total():
    records = [_record(record_id=f"record-{index}") for index in range(25)]
    outcome = search("a1", _result(), records, "10.0.0.8", page=2, page_size=10)
    assert outcome.records_total == 25
    assert len(outcome.records) == 10
    assert outcome.page == 2


def test_search_endpoint():
    assert client.get("/api/analysis/missing/search", params={"q": "x"}).status_code == 404
    created = client.post("/api/demo/analyze", json={"files": ["iis/iis-access.log"]})
    analysis_id = created.json()["analysis_id"]
    response = client.get(f"/api/analysis/{analysis_id}/search", params={"q": "status:404"})
    assert response.status_code == 200
    body = response.json()
    assert body["analysis_id"] == analysis_id
    assert body["records_total"] >= 1
    assert body["terms"][0]["field"] == "status"

    fields = client.get(f"/api/analysis/{analysis_id}/search-fields")
    assert fields.status_code == 200
    assert "source_ip" in fields.json()["fields"]
