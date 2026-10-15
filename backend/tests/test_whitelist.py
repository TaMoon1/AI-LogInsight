from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services.analyzer import analyze_log
from app.services.whitelist import (
    WhitelistEntry,
    WhitelistMatcher,
    match_value,
    whitelist_repository,
)

client = TestClient(app)


@pytest.fixture(autouse=True)
def clean_whitelist():
    """白名单持久化在 DB 里，测试之间必须清空，否则条目会互相累积。"""

    def wipe() -> None:
        with whitelist_repository.connect() as connection:
            connection.execute("DELETE FROM whitelist_entries")
            connection.execute("DELETE FROM whitelist_changes")
            connection.commit()

    wipe()
    yield
    wipe()


def _entry(kind: str, value: str, enabled: bool = True) -> WhitelistEntry:
    return WhitelistEntry(id=1, kind=kind, value=value, note="", enabled=enabled, created_at="")


@pytest.mark.parametrize(
    "kind,pattern,candidate,expected",
    [
        ("ip", "192.168.1.50", "192.168.1.50", True),
        ("ip", "192.168.1.50", "192.168.1.51", False),
        ("ip", "192.168.1.0/24", "192.168.1.77", True),
        ("ip", "192.168.1.0/24", "192.168.2.77", False),
        ("port", "8080", "8080", True),
        ("port", "8080", "8081", False),
        # path 按前缀：/health 覆盖自身与子路径，但不覆盖 /healthz（否则会放过同名业务路径）
        ("path", "/health", "/health", True),
        ("path", "/health", "/health/live", True),
        ("path", "/health", "/healthz", False),
        # domain 按后缀：example.com 覆盖子域，但不覆盖 notexample.com
        ("domain", "example.com", "a.example.com", True),
        ("domain", "example.com", "notexample.com", False),
        ("process", r"\msmpeng.exe", r"C:\Program Files\Windows Defender\MsMpEng.exe", True),
        ("process", r"\msmpeng.exe", r"C:\Other\tool.exe", False),
        # username 精确匹配：admin 不应连 administrator 一起放过
        ("username", "admin", "admin", True),
        ("username", "admin", "administrator", False),
        ("user_agent", "kube-probe", "Mozilla/5.0 (compatible; kube-probe/1.29)", True),
    ],
)
def test_whitelist_match_semantics(kind, pattern, candidate, expected):
    assert match_value(kind, pattern, candidate) is expected


def test_whitelisted_record_is_skipped_but_kept_as_evidence():
    """白名单放过告警，但不删证据——记录仍在明细里，并标明被哪条白名单放过。"""

    log = '203.0.113.7 - - [21/Sep/2026:09:10:00 +0800] "GET /.env HTTP/1.1" 403 1 "-" "curl/8.0"'
    assert analyze_log("a.log", log, whitelist=WhitelistMatcher([])).events

    result = analyze_log("a.log", log, whitelist=WhitelistMatcher([_entry("ip", "203.0.113.7")]))
    assert result.events == []
    assert result.coverage.whitelisted_records == 1
    # 证据不删：记录与可判定字段都还在
    assert result.coverage.total_records == 1
    assert result.coverage.evaluable_records == 1


def test_disabled_whitelist_entry_takes_no_effect():
    matcher = WhitelistMatcher([_entry("ip", "203.0.113.7", enabled=False)])
    assert not matcher
    log = '203.0.113.7 - - [21/Sep/2026:09:10:00 +0800] "GET /.env HTTP/1.1" 403 1 "-" "curl/8.0"'
    assert analyze_log("a.log", log, whitelist=matcher).events


def test_whitelist_api_crud_and_audit():
    """白名单增删改与变更审计：非法输入被拒、每次变更都留痕。"""

    assert client.get("/api/whitelist").json()["entries"] == []

    created = client.post(
        "/api/whitelist", json={"kind": "ip", "value": "10.0.0.5", "note": "内网探针"}
    )
    assert created.status_code == 200
    entry_id = created.json()["id"]
    assert created.json()["enabled"] is True

    assert client.post("/api/whitelist", json={"kind": "bad", "value": "x"}).status_code == 400
    assert client.post("/api/whitelist", json={"kind": "ip", "value": "   "}).status_code == 400

    assert client.patch(f"/api/whitelist/{entry_id}?enabled=false").json() == {"enabled": False}
    assert client.patch("/api/whitelist/9999?enabled=true").status_code == 404

    overview = client.get("/api/whitelist").json()
    assert [item["action"] for item in overview["changes"]][:2] == ["disable", "add"]
    assert overview["entries"][0]["enabled"] is False

    assert client.delete(f"/api/whitelist/{entry_id}").json() == {"removed": True}
    assert client.delete(f"/api/whitelist/{entry_id}").status_code == 404
    assert client.get("/api/whitelist").json()["changes"][0]["action"] == "remove"


def test_whitelist_marker_is_written_back_to_parsed_records():
    """标记必须写回解析层原始记录——调用方会另行组装 records，只改本地副本会丢标记。"""

    from app.services.analyzer import analyze_parsed_logs
    from app.services.parser import parse_upload

    content = (
        b'203.0.113.7 - - [21/Sep/2026:09:10:00 +0800] "GET /.env HTTP/1.1" 403 1 "-" "curl/8.0"\n'
    )
    parsed = parse_upload(content)
    result = analyze_parsed_logs(
        ["a.log"], [parsed], whitelist=WhitelistMatcher([_entry("ip", "203.0.113.7")])
    )
    assert parsed.records[0]["whitelisted_by"] == "IP / 网段=203.0.113.7"
    assert result.events == []
    assert result.coverage.whitelisted_records == 1
