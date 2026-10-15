"""威胁情报富化测试。

所有外部请求一律 mock（patch urllib urlopen），测试绝不真连情报库。
默认关闭的语义也要钉住：不开 THREAT_INTEL_ENABLED 时不允许发出任何请求。
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.models import (
    AnalysisResult,
    EntityProfile,
    Event,
    LogMetadata,
    LogStatistics,
)
from app.services import threat_intel
from app.services.threat_intel import (
    ThreatIntelRepository,
    enrich,
    extract_indicators,
    indicators_total,
    query_abuseipdb,
    query_threatfox,
    query_urlhaus,
)

client = TestClient(app)


class FakeResponse:
    """模拟 urlopen 返回的上下文管理器响应。"""

    def __init__(self, payload: dict):
        self._raw = json.dumps(payload).encode("utf-8")

    def read(self) -> bytes:
        return self._raw

    def __enter__(self):
        return self

    def __exit__(self, *args) -> bool:
        return False


def fake_urlopen_factory(routes: dict[str, dict], calls: list[str]):
    """按 URL 关键词路由的 urlopen 替身，记录每次请求的 URL。"""

    def _fake(req, timeout=None):
        url = req.full_url
        calls.append(url)
        for keyword, payload in routes.items():
            if keyword in url:
                return FakeResponse(payload)
        raise AssertionError(f"未 mock 的 URL：{url}")

    return _fake


@pytest.fixture(autouse=True)
def clean_cache(monkeypatch):
    """缓存持久化在测试 DB 里，测试之间清空；同时确保本机环境变量不泄漏进测试。"""

    def wipe() -> None:
        with threat_intel.threat_intel_repository.connect() as connection:
            connection.execute("DELETE FROM threat_intel_cache")
            connection.commit()

    monkeypatch.delenv("THREAT_INTEL_ENABLED", raising=False)
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    wipe()
    yield
    wipe()


# ---------- 指标提取 ----------


def _result(
    events: list[Event] | None = None,
    entities: list[EntityProfile] | None = None,
) -> AnalysisResult:
    return AnalysisResult(
        metadata=LogMetadata(
            filename="test.log",
            log_type="ssh",
            recognition_confidence=1.0,
            total_lines=0,
            parsed_lines=0,
            time_range={},
        ),
        statistics=LogStatistics(),
        events=events or [],
        entities=entities or [],
        summary="",
    )


def _event(source_ip: str | None, risk_level: str = "high") -> Event:
    return Event(
        id="event-1",
        type="ssh.bruteforce",
        name="SSH 爆破",
        risk_level=risk_level,
        source_ip=source_ip,
        summary="",
    )


def test_extract_keeps_public_ip_and_drops_private():
    result = _result(
        events=[_event("203.0.113.9")],
        entities=[
            EntityProfile(kind="source_ip", value="192.168.1.5", summary=""),
        ],
    )
    found = extract_indicators(result)
    assert [item.value for item in found] == ["203.0.113.9"]
    assert found[0].related_events == 1


def test_extract_target_asset_as_public_ip():
    event = _event(None)
    event.target_asset = "198.51.100.23"
    found = extract_indicators(_result(events=[event]))
    assert [item.value for item in found] == ["198.51.100.23"]


def test_extract_domain_from_records_and_filter():
    records = [
        {"query_name": "evil-c2.example.org"},
        {"query_name": "update.microsoft.com"},  # 常见厂商域名不外发
        {"query_name": "nas.local"},  # 内网后缀不外发
        {"query_name": "192.168.1.1"},  # IP 不当域名查
        {"query_name": ""},
    ]
    found = extract_indicators(_result(), records=records)
    assert [item.value for item in found] == ["evil-c2.example.org"]
    assert found[0].indicator_type == "domain"


def test_extract_event_related_indicators_come_first():
    result = _result(
        events=[_event("203.0.113.5", risk_level="low")],
        entities=[
            EntityProfile(kind="destination_ip", value="203.0.113.200", summary=""),
        ],
    )
    found = extract_indicators(result)
    assert found[0].value == "203.0.113.5"
    assert found[0].related_events == 1
    assert found[1].value == "203.0.113.200"


def test_extract_cap_and_total():
    entities = [
        EntityProfile(kind="source_ip", value=f"203.0.113.{index}", summary="")
        for index in range(20)
    ]
    result = _result(entities=entities)
    assert len(extract_indicators(result, limit=5)) == 5
    assert indicators_total(result) == 20


# ---------- 情报源响应解析 ----------


def test_threatfox_hit(monkeypatch):
    monkeypatch.setattr(
        threat_intel.request,
        "urlopen",
        fake_urlopen_factory(
            {"threatfox": {"query_status": "ok", "data": [{"malware_printable": "Cobalt"}]}},
            [],
        ),
    )
    outcome = query_threatfox("203.0.113.9")
    assert outcome.status == "hit"
    assert outcome.confidence == 0.9
    assert "Cobalt" in outcome.detail


def test_threatfox_not_listed_and_empty_data(monkeypatch):
    calls: list[str] = []
    monkeypatch.setattr(
        threat_intel.request,
        "urlopen",
        fake_urlopen_factory({"threatfox": {"query_status": "no_result"}}, calls),
    )
    assert query_threatfox("203.0.113.9").status == "not_listed"
    monkeypatch.setattr(
        threat_intel.request,
        "urlopen",
        fake_urlopen_factory({"threatfox": {"query_status": "ok", "data": []}}, calls),
    )
    assert query_threatfox("203.0.113.9").status == "not_listed"


def test_threatfox_network_error_is_error_not_crash(monkeypatch):
    def _fail(req, timeout=None):
        raise TimeoutError("boom")

    monkeypatch.setattr(threat_intel.request, "urlopen", _fail)
    outcome = query_threatfox("203.0.113.9")
    assert outcome.status == "error"
    assert "boom" in outcome.detail


def test_urlhaus_hit_and_not_listed(monkeypatch):
    monkeypatch.setattr(
        threat_intel.request,
        "urlopen",
        fake_urlopen_factory(
            {
                "urlhaus": {
                    "query_status": "ok",
                    "urlhaus_reference": "https://urlhaus.abuse.ch/host/evil.example/",
                    "urls": [{"url": "http://evil.example/p"}],
                }
            },
            [],
        ),
    )
    outcome = query_urlhaus("evil.example")
    assert outcome.status == "hit"
    assert outcome.link is not None
    monkeypatch.setattr(
        threat_intel.request,
        "urlopen",
        fake_urlopen_factory({"urlhaus": {"query_status": "no_results"}}, []),
    )
    assert query_urlhaus("evil.example").status == "not_listed"


def test_abuseipdb_skipped_without_key(monkeypatch):
    outcome = query_abuseipdb("203.0.113.9")
    assert outcome.status == "skipped"
    assert "ABUSEIPDB_API_KEY" in outcome.detail


def test_abuseipdb_score_mapping(monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-key")
    monkeypatch.setattr(
        threat_intel.request,
        "urlopen",
        fake_urlopen_factory(
            {"abuseipdb": {"data": {"abuseConfidenceScore": 91}}}, []
        ),
    )
    assert query_abuseipdb("203.0.113.9").status == "hit"
    monkeypatch.setattr(
        threat_intel.request,
        "urlopen",
        fake_urlopen_factory({"abuseipdb": {"data": {"abuseConfidenceScore": 10}}}, []),
    )
    outcome = query_abuseipdb("203.0.113.9")
    assert outcome.status == "not_listed"
    assert "10/100" in outcome.detail
    monkeypatch.setattr(
        threat_intel.request,
        "urlopen",
        fake_urlopen_factory({"abuseipdb": {"errors": [{"detail": "bad key"}]}}, []),
    )
    assert query_abuseipdb("203.0.113.9").status == "error"


# ---------- 缓存 ----------


def test_cache_roundtrip_and_refresh(tmp_path):
    repo = ThreatIntelRepository(tmp_path / "ti.db")
    payload = {"source": "ThreatFox", "status": "not_listed", "detail": "库中未收录"}
    repo.store("ip", "203.0.113.9", "threatfox", payload)
    assert repo.get_cached("ip", "203.0.113.9", "threatfox", ttl_hours=24) == payload
    assert repo.get_cached("ip", "203.0.113.9", "urlhaus", ttl_hours=24) is None


def test_cache_expired_returns_none(tmp_path):
    repo = ThreatIntelRepository(tmp_path / "ti.db")
    payload = {"source": "ThreatFox", "status": "not_listed"}
    repo.store("ip", "203.0.113.9", "threatfox", payload)
    old = (datetime.now().astimezone() - timedelta(hours=48)).isoformat(timespec="seconds")
    with repo.connect() as connection:
        connection.execute("UPDATE threat_intel_cache SET fetched_at = ?", (old,))
        connection.commit()
    assert repo.get_cached("ip", "203.0.113.9", "threatfox", ttl_hours=24) is None


# ---------- 富化主流程 ----------


def test_disabled_by_default_and_no_http(monkeypatch):
    def _boom(req, timeout=None):
        raise AssertionError("默认关闭时不允许发出任何外部请求")

    monkeypatch.setattr(threat_intel.request, "urlopen", _boom)
    report = enrich(
        "analysis-x",
        _result(events=[_event("203.0.113.9")]),
    )
    assert report.enabled is False
    assert report.findings == []
    assert "THREAT_INTEL_ENABLED" in report.note


def test_enabled_full_flow_with_mocked_providers(monkeypatch):
    monkeypatch.setenv("THREAT_INTEL_ENABLED", "true")
    calls: list[str] = []
    monkeypatch.setattr(
        threat_intel.request,
        "urlopen",
        fake_urlopen_factory(
            {
                "threatfox": {"query_status": "no_result"},
                "urlhaus": {
                    "query_status": "ok",
                    "urlhaus_reference": "https://urlhaus.abuse.ch/host/evil.example.org/",
                    "urls": [{"url": "http://evil.example.org/payload"}],
                },
            },
            calls,
        ),
    )
    result = _result(
        events=[_event("203.0.113.9")],
        entities=[],
    )
    records = [{"query_name": "evil.example.org"}]
    report = enrich("analysis-x", result, records=records)
    assert report.enabled is True
    assert len(report.findings) == 2
    ip_finding = next(item for item in report.findings if item.indicator_type == "ip")
    domain_finding = next(item for item in report.findings if item.indicator_type == "domain")
    # AbuseIPDB 无 key → skipped；URLhaus hit → 综合摘要必须如实反映
    assert domain_finding.summary.startswith("1 个情报源")
    assert "URLhaus" in domain_finding.summary
    assert ip_finding.summary.startswith("已查询来源均未收录") or "skipped" in {
        item.status for item in ip_finding.sources
    }
    # 没有指向任何事件的指标：域名来自记录
    assert domain_finding.related_events == 0
    assert "record" in domain_finding.origins


def test_cache_avoids_repeat_http(monkeypatch):
    monkeypatch.setenv("THREAT_INTEL_ENABLED", "true")
    calls: list[str] = []
    monkeypatch.setattr(
        threat_intel.request,
        "urlopen",
        fake_urlopen_factory(
            {
                "threatfox": {"query_status": "no_result"},
                "urlhaus": {"query_status": "no_results"},
            },
            calls,
        ),
    )
    result = _result(events=[_event("203.0.113.9")])
    enrich("analysis-x", result)
    first_call_count = len(calls)
    assert first_call_count == 2  # ThreatFox + URLhaus（AbuseIPDB 无 key 跳过）
    second = enrich("analysis-x", result)
    assert len(calls) == first_call_count  # 全部命中缓存
    assert any("缓存" in part for part in second.note.split("；"))
    # refresh=true 强制重查
    enrich("analysis-x", result, refresh=True)
    assert len(calls) == first_call_count * 2


def test_budget_exhaustion_skips_without_crash(monkeypatch):
    monkeypatch.setenv("THREAT_INTEL_ENABLED", "true")
    # _int_setting 对非正值回退默认，所以不能用预算 0 触发；
    # 用可控时钟让「现在」始终远在 deadline 之后。
    clock = [0.0]

    def fake_monotonic() -> float:
        clock[0] += 100.0
        return clock[0]

    monkeypatch.setattr(threat_intel.time, "monotonic", fake_monotonic)

    def _boom(req, timeout=None):
        raise AssertionError("预算耗尽时不允许发出请求")

    monkeypatch.setattr(threat_intel.request, "urlopen", _boom)
    report = enrich("analysis-x", _result(events=[_event("203.0.113.9")]))
    assert report.enabled is True
    statuses = {item.status for item in report.findings[0].sources}
    assert statuses <= {"skipped"}


def test_empty_indicators_reports_honestly(monkeypatch):
    monkeypatch.setenv("THREAT_INTEL_ENABLED", "true")
    report = enrich("analysis-x", _result(events=[_event("10.0.0.5")]))
    assert report.enabled is True
    assert report.indicators_total == 0
    assert "没有可外发查询" in report.note


# ---------- 接口 ----------


def test_endpoint_disabled_returns_report(monkeypatch):
    result = client.get("/api/analysis/does-not-exist/threat-intel")
    assert result.status_code == 404


def test_endpoint_with_real_analysis(monkeypatch):
    # 演示分析接口免上传，生成一份真实分析记录
    demos = client.get("/api/demo/logs").json()
    if not demos:
        pytest.skip("演示日志库为空")
    response = client.post("/api/demo/analyze", json={"files": [demos[0]["path"]]})
    assert response.status_code == 200
    analysis_id = response.json()["analysis_id"]

    report = client.get(f"/api/analysis/{analysis_id}/threat-intel")
    assert report.status_code == 200
    assert report.json()["enabled"] is False

    monkeypatch.setenv("THREAT_INTEL_ENABLED", "true")
    monkeypatch.setattr(
        threat_intel.request,
        "urlopen",
        fake_urlopen_factory(
            {
                "threatfox": {"query_status": "no_result"},
                "urlhaus": {"query_status": "no_results"},
            },
            [],
        ),
    )
    report = client.get(f"/api/analysis/{analysis_id}/threat-intel")
    assert report.status_code == 200
    body = report.json()
    assert body["enabled"] is True
    # 两种情况都要如实说明：无可查指标，或「未收录不等于安全」（界面上照抄这句话）
    if body["findings"]:
        assert "不等于安全" in body["note"]
    else:
        assert "没有可外发查询" in body["note"]


# ---------- 进 AI 上下文（只读缓存，绝不外呼） ----------


def test_ai_context_reads_cache_without_external_calls(monkeypatch):
    """研判过程中**不允许**偷偷访问外部服务：只读此前查询过的缓存。"""

    from app.models import Event, LogMetadata, LogStatistics
    from app.services.ai import build_ai_context
    from app.services.threat_intel import threat_intel_repository

    def _boom(req, timeout=None):
        raise AssertionError("研判不得发起外部请求")

    monkeypatch.setattr(threat_intel.request, "urlopen", _boom)
    result = AnalysisResult(
        id="analysis-intel",
        metadata=LogMetadata(
            filename="t.log",
            log_type="ssh",
            recognition_confidence=1.0,
            total_lines=1,
            parsed_lines=1,
            time_range={},
        ),
        statistics=LogStatistics(),
        events=[_event("203.0.113.9")],
        summary="",
    )
    records = [{"record_id": "record-1", "timestamp_iso": "2026-09-12T09:00:00+00:00", "source_ip": "203.0.113.9"}]

    # 未查过：只有「未查询」说明，没有情报条目
    context = build_ai_context(result, records)
    assert context["threat_intel"] == []
    assert "queried=none" in context["threat_intel_note"]

    # 有缓存：带上条目，并明确标注是第三方数据
    threat_intel_repository.store(
        "ip",
        "203.0.113.9",
        "threatfox",
        {"source": "ThreatFox", "status": "hit", "confidence": 0.9, "detail": "收录为恶意 IOC", "link": None},
    )
    context = build_ai_context(result, records)
    assert context["threat_intel"][0]["indicator"] == "203.0.113.9"
    assert context["threat_intel"][0]["sources"]["ThreatFox"] == "hit"
    assert "not_log_evidence" in context["threat_intel_note"]


def test_cached_report_never_queries_when_cache_is_empty(monkeypatch):
    from app.services.threat_intel import cached_report

    def _boom(req, timeout=None):
        raise AssertionError("cached_report 不得发起外部请求")

    monkeypatch.setattr(threat_intel.request, "urlopen", _boom)
    report = cached_report("analysis-x", _result(events=[_event("203.0.113.9")]))
    assert report.findings == []
    assert "没有已缓存" in report.note


# ---------- 进 AI 上下文（只读缓存，绝不外呼） ----------


def test_ai_context_reads_cache_without_external_calls(monkeypatch):
    """研判过程中**不允许**偷偷访问外部服务：只读此前查询过的缓存。"""

    from app.models import Event, LogMetadata, LogStatistics
    from app.services.ai import build_ai_context
    from app.services.threat_intel import threat_intel_repository

    def _boom(req, timeout=None):
        raise AssertionError("研判不得发起外部请求")

    monkeypatch.setattr(threat_intel.request, "urlopen", _boom)
    result = AnalysisResult(
        id="analysis-intel",
        metadata=LogMetadata(
            filename="t.log",
            log_type="ssh",
            recognition_confidence=1.0,
            total_lines=1,
            parsed_lines=1,
            time_range={},
        ),
        statistics=LogStatistics(),
        events=[_event("203.0.113.9")],
        summary="",
    )
    records = [{"record_id": "record-1", "timestamp_iso": "2026-09-12T09:00:00+00:00", "source_ip": "203.0.113.9"}]

    # 未查过：只有「未查询」说明，没有情报条目
    context = build_ai_context(result, records)
    assert context["threat_intel"] == []
    assert "queried=none" in context["threat_intel_note"]

    # 有缓存：带上条目，并明确标注是第三方数据
    threat_intel_repository.store(
        "ip",
        "203.0.113.9",
        "threatfox",
        {"source": "ThreatFox", "status": "hit", "confidence": 0.9, "detail": "收录为恶意 IOC", "link": None},
    )
    context = build_ai_context(result, records)
    assert context["threat_intel"][0]["indicator"] == "203.0.113.9"
    assert context["threat_intel"][0]["sources"]["ThreatFox"] == "hit"
    assert "not_log_evidence" in context["threat_intel_note"]


def test_cached_report_never_queries_when_cache_is_empty(monkeypatch):
    from app.services.threat_intel import cached_report

    def _boom(req, timeout=None):
        raise AssertionError("cached_report 不得发起外部请求")

    monkeypatch.setattr(threat_intel.request, "urlopen", _boom)
    report = cached_report("analysis-x", _result(events=[_event("203.0.113.9")]))
    assert report.findings == []
    assert "没有已缓存" in report.note
