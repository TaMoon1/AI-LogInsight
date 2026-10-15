from fastapi.testclient import TestClient

import io
import hashlib
import json
import os
import time
import zipfile

import pytest

from app.database import repository
from app.main import app
from app.models import AiBehavior, StructuredVerdict
from app.services.analyzer import analyze_log
from app.services.sanitizer import sanitize_records, sanitize_text

client = TestClient(app)


@pytest.fixture(autouse=True)
def isolate_ai_env_file(monkeypatch):
    """隔离项目根 `.env`：本机真实 AI 配置不应影响配置类测试。"""

    from app.services import ai as ai_module

    monkeypatch.setattr(
        ai_module, "_setting", lambda name, default="": os.getenv(name) or default
    )


def make_ssh_log(
    failures: int = 20,
    success: bool = True,
    success_timestamp: str = "Sep 12 01:04:00",
) -> str:
    lines = [
        f"Sep 12 01:00:{index:02d} host sshd[100]: Failed password for root from 10.0.0.8 port 22 ssh2"
        for index in range(failures)
    ]
    if success:
        lines.append(
            f"{success_timestamp} host sshd[100]: Accepted password for root from 10.0.0.8 port 22 ssh2"
        )
    return "\n".join(lines)


def make_web_log(url: str, status: int = 404, index: int = 0) -> str:
    return (
        f'10.0.0.9 - - [12/Sep/2026:01:00:{index:02d} +0800] '
        f'"GET {url} HTTP/1.1" {status} 123 "-" "test-agent"'
    )


def make_iis_log(
    not_found: int = 20,
    extra_paths: tuple[str, ...] = ("/.git/config", "/download?file=../../etc/passwd"),
    source_ip: str = "10.0.0.9",
    server_ip: str = "10.0.0.5",
) -> str:
    lines = [
        "#Software: Microsoft Internet Information Services 10.0",
        "#Version: 1.0",
        "#Date: 2026-09-12 01:00:00",
        "#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username "
        "c-ip cs(User-Agent) sc-status sc-substatus sc-win32-status time-taken",
    ]
    for index in range(not_found):
        lines.append(
            f"2026-09-12 01:00:{index:02d} {server_ip} GET /missing-{index}.aspx - "
            f"80 - {source_ip} Mozilla/5.0 404 0 2 32"
        )
    for index, path in enumerate(extra_paths):
        lines.append(
            f"2026-09-12 01:0{1 + index}:00 {server_ip} GET {path} - "
            f"80 - {source_ip} Mozilla/5.0 404 0 2 15"
        )
    return "\n".join(lines)


def make_windows_event(
    event_id: int,
    username: str = "administrator",
    source_ip: str = "10.0.0.9",
    logon_type: int = 10,
    timestamp: str = "2026-09-12 01:00:00",
) -> str:
    is_failure = event_id == 4625
    lines = [
        "Log Name:      Security",
        "Source:        Microsoft-Windows-Security-Auditing",
        f"Date:          {timestamp}",
        f"Event ID:      {event_id}",
        "Task Category: Logon",
        "Level:         Information",
        f"Keywords:      {'Audit Failure' if is_failure else 'Audit Success'}",
        "Computer:      WIN-SRV01",
        "",
        "Description:",
        "An account failed to log on." if is_failure else "An account was successfully logged on.",
        "",
        "Subject:",
        "    Security ID:  SYSTEM",
        "    Account Name:  WIN-SRV01$",
        "    Account Domain:  WORKGROUP",
        "",
        "Account For Which Logon Failed:" if is_failure else "New Logon:",
        f"    Account Name:  {username}",
        "    Account Domain:  WORKGROUP",
        "",
        "Detailed Authentication Information:",
        f"    Logon Type:    {logon_type}",
        "",
        "Network Information:",
        f"    Source Network Address: {source_ip}",
    ]
    return "\n".join(lines)


def make_windows_log(
    failures: int = 12,
    success: bool = True,
    username: str = "administrator",
    source_ip: str = "10.0.0.9",
    logon_type: int = 10,
) -> str:
    blocks = [
        make_windows_event(
            4625, username, source_ip, logon_type, f"2026-09-12 01:00:{index:02d}"
        )
        for index in range(failures)
    ]
    if success:
        blocks.append(make_windows_event(4624, username, source_ip, logon_type, "2026-09-12 01:04:00"))
    return "\n\n".join(blocks)


def make_json_event_log(
    failures: int = 20,
    success: bool = True,
    source_ip: str = "198.51.100.30",
) -> str:
    events = [
        {
            "@timestamp": f"2026-09-12T05:00:{index:02d}+08:00",
            "src_ip": source_ip,
            "dst_ip": "10.0.0.20",
            "user": "vpnuser",
            "event_type": "login",
            "result": "failure" if index % 2 == 0 else "失败",
            "message": f"authentication failed for vpnuser from {source_ip}",
        }
        for index in range(failures)
    ]
    if success:
        events.append(
            {
                "@timestamp": "2026-09-12T05:04:10+08:00",
                "src_ip": source_ip,
                "dst_ip": "10.0.0.20",
                "user": "vpnuser",
                "event_type": "signin",
                "result": "success",
                "message": "authentication succeeded",
            }
        )
    return json.dumps({"events": events}, ensure_ascii=False)


def make_csv_auth_log(failures: int = 20, source_ip: str = "203.0.113.90") -> str:
    lines = ["timestamp;src_ip;user;action;result"]
    for index in range(failures):
        lines.append(f"2026-09-12 06:00:{index:02d};{source_ip};admin;login;failure")
    lines.append(f"2026-09-12 06:04:30;{source_ip};admin;login;success")
    return "\n".join(lines)


def make_csv_web_log(not_found: int = 20, source_ip: str = "203.0.113.91") -> str:
    lines = ["time,client_ip,server_ip,method,path,status_code"]
    for index in range(not_found):
        lines.append(f"2026-09-12 07:00:{index:02d},{source_ip},10.0.0.5,GET,/missing-{index}.php,404")
    lines.append(f"2026-09-12 07:01:00,{source_ip},10.0.0.5,GET,/.git/config,404")
    return "\n".join(lines)


def make_firewall_log(ports: int = 10, source_ip: str = "198.51.100.80") -> str:
    return "\n".join(
        f"Sep 12 09:00:{index:02d} fw kernel: SRC={source_ip} DST=10.0.0.5 "
        f"PROTO=TCP SPT={40000 + index} DPT={port} ACTION=DROP"
        for index, port in enumerate(range(22, 22 + ports))
    )


def make_sanitized_web_log() -> str:
    """脱敏后的访问日志：请求段无引号，路径与时间的 `/` `:` 已被剥离。"""

    return "\n".join(
        [
            "192.168.1.101 - - [16Sep2026090112 +0800] GET  HTTP1.1 200 5231 - Mozilla5.0 (Windows NT 10.0)",
            "203.0.113.45 - - [16Sep2026090311 +0800] GET wp-admin HTTP1.1 403 512 - scanner1.0",
            "203.0.113.45 - - [16Sep2026090315 +0800] GET .env HTTP1.1 403 481 - scanner1.0",
            "198.51.100.27 - - [16Sep2026090421 +0800] GET searchq=' OR '1'='1 HTTP1.1 403 621 - Mozilla5.0",
            "198.51.100.27 - - [16Sep2026090423 +0800] GET userid=1%20UNION%20SELECT%20NULL,NULL-- HTTP1.1 403 684 - sqlmap1.8",
            "198.51.100.31 - - [16Sep2026090511 +0800] GET commenttext=%3Cimg%20src=x%20onerror=alert(1)%3E HTTP1.1 403 631 - Mozilla5.0",
            "203.0.113.88 - - [16Sep2026090721 +0800] GET apipinghost=127.0.0.1%3Bwhoami HTTP1.1 403 523 - Mozilla5.0",
            "203.0.113.99 - - [16Sep2026090916 +0800] GET actuatorheapdump HTTP1.1 403 521 - scanner3.0",
            "198.51.100.52 - - [16Sep2026090803 +0800] GET uploadsshell.php HTTP1.1 404 312 - curl8.10.1",
        ]
    )


def make_evtx_xml_event(
    event_id: int,
    username: str,
    source_ip: str,
    logon_type: int,
    timestamp: str,
) -> str:
    return (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        "<System>"
        '<Provider Name="Microsoft-Windows-Security-Auditing"/>'
        f"<EventID>{event_id}</EventID>"
        f'<TimeCreated SystemTime="{timestamp}"/>'
        "<Computer>WIN-SRV01</Computer>"
        "</System>"
        "<EventData>"
        f'<Data Name="TargetUserName">{username}</Data>'
        f'<Data Name="LogonType">{logon_type}</Data>'
        f'<Data Name="IpAddress">{source_ip}</Data>'
        '<Data Name="SubjectUserName">WIN-SRV01$</Data>'
        "</EventData>"
        "</Event>"
    )


def make_evtx_xml_log(failures: int = 10, success: bool = True, source_ip: str = "203.0.113.70") -> str:
    events = [
        make_evtx_xml_event(
            4625, "administrator", source_ip, 10, f"2026-09-16T03:00:{index:02d}.500000Z"
        )
        for index in range(failures)
    ]
    if success:
        events.append(
            make_evtx_xml_event(4624, "administrator", source_ip, 10, "2026-09-16T03:02:10.123456Z")
        )
    return '<?xml version="1.0" encoding="utf-8"?>\n<Events>' + "".join(events) + "</Events>"


def test_upload_detects_ssh_bruteforce():
    response = client.post(
        "/api/logs/upload",
        files={"file": ("auth.log", make_ssh_log(), "text/plain")},
    )
    assert response.status_code == 200
    body = response.json()["result"]
    assert body["metadata"]["log_type"] == "ssh"
    assert body["statistics"]["failed_login"] == 20
    assert body["has_suspicious_behavior"] is True
    assert body["events"][0]["risk_level"] == "high"
    assert "10.0.0.8" in body["events"][0]["summary"]
    assert body["events"][0]["rule_id"] == "ssh.bruteforce.success"
    assert body["events"][0]["evidence_items"][0]["id"] == "evidence-ssh_bruteforce_success-1"
    assert body["events"][0]["evidence_items"][0]["record_id"] == "record-1"
    assert body["events"][0]["evidence_items"][0]["source_ip"] == "10.0.0.8"
    assert body["risk_level"] == "high"
    assert body["confidence"] == 0.88
    assert body["analysis_source"] == "rules"
    assert "高风险" in body["conclusion"]
    assert any("sudo" in item for item in body["recommendations"])


def test_rule_catalog_exposes_reusable_metadata(monkeypatch):
    monkeypatch.setenv("SSH_FAILURE_THRESHOLD", "25")
    response = client.get("/api/rules")
    assert response.status_code == 200
    rules = {item["id"]: item for item in response.json()}
    assert rules["ssh.bruteforce"]["threshold"] == 25
    assert rules["ssh.bruteforce"]["window_seconds"] == 300
    # SSH 规则的实际作用是「非结构化认证日志」（规则内以 exclude_log_types 表达），
    # 未识别为 ssh 但含 SSH 认证行的 generic 日志同样在内，因此元数据如实展示两者。
    assert rules["ssh.bruteforce"]["log_types"] == ["ssh", "generic"]
    assert rules["web.path_traversal"]["threshold"] is None


def test_rules_can_be_disabled_individually(monkeypatch):
    for name in (
        "RULE_SSH_BRUTEFORCE_ENABLED",
        "RULE_SSH_BRUTEFORCE_SUCCESS_ENABLED",
        "RULE_SSH_PRIVILEGED_LOGIN_ENABLED",
        "RULE_WEB_SENSITIVE_PATH_ENABLED",
        "RULE_WEB_PATH_TRAVERSAL_ENABLED",
        "RULE_WEB_404_SCAN_ENABLED",
        # 社区导入规则（Sigma）由全局开关一键停用，避免与内置规则的断言相互干扰
        "RULE_SIGMA_IMPORTED_ENABLED",
    ):
        monkeypatch.setenv(name, "false")

    ssh_result = analyze_log("disabled-ssh.log", make_ssh_log())
    web_result = analyze_log(
        "disabled-web.log",
        "\n".join(
            make_web_log(f"/missing-{index}", index=index)
            for index in range(20)
        )
        + "\n"
        + make_web_log("/.git/config", status=404, index=21)
        + "\n"
        + make_web_log(
            "/download?file=../../etc/passwd",
            status=400,
            index=22,
        ),
    )

    assert not ssh_result.events
    assert not web_result.events


def test_rule_enable_state_is_exposed(monkeypatch):
    monkeypatch.setenv("RULE_WEB_404_SCAN_ENABLED", "false")
    response = client.get("/api/rules")
    assert response.status_code == 200
    rules = {item["id"]: item for item in response.json()}
    assert rules["web.404_scan"]["enabled"] is False
    assert rules["web.sensitive_path"]["enabled"] is True


def test_ssh_threshold_can_be_overridden(monkeypatch):
    monkeypatch.setenv("SSH_FAILURE_THRESHOLD", "3")
    result = analyze_log("threshold.log", make_ssh_log(failures=3, success=False))
    assert any(item.type == "ssh_bruteforce" for item in result.events)


def test_upload_handles_empty_log():
    response = client.post(
        "/api/logs/upload",
        files={"file": ("empty.log", "", "text/plain")},
    )
    assert response.status_code == 200
    body = response.json()["result"]
    assert body["metadata"]["total_lines"] == 0
    assert body["metadata"]["parsed_lines"] == 0
    assert body["risk_level"] == "info"
    # 空文件没有任何可判定内容：结论必须是「无法确认」，不能是「未发现异常」
    assert body["confidence"] == 0.2
    assert body["coverage"]["total_records"] == 0
    assert body["coverage"]["limitation"]
    assert "无法确认" in body["conclusion"]
    assert body["conclusion"]
    assert body["analysis_source"] == "rules"


def test_analysis_is_persisted_and_can_be_deleted():
    response = client.post(
        "/api/logs/upload",
        files={"file": ("persisted.log", make_ssh_log(1), "text/plain")},
    )
    analysis_id = response.json()["analysis_id"]

    listed = client.get("/api/logs")
    assert listed.status_code == 200
    assert any(item["id"] == analysis_id for item in listed.json())

    loaded = client.get(f"/api/analysis/{analysis_id}")
    assert loaded.status_code == 200
    assert loaded.json()["metadata"]["filename"] == "persisted.log"

    deleted = client.delete(f"/api/analysis/{analysis_id}")
    assert deleted.status_code == 204
    assert client.get(f"/api/analysis/{analysis_id}").status_code == 404
    assert repository.delete(analysis_id) is False


def test_upload_rejects_when_single_analysis_exceeds_total_limit(monkeypatch):
    import app.main as main_module

    monkeypatch.setattr(main_module, "MAX_ANALYSIS_UPLOAD_BYTES", 10)
    response = client.post(
        "/api/logs/upload",
        files=[
            ("files", ("one.log", b"123456", "text/plain")),
            ("files", ("two.log", b"123456", "text/plain")),
        ],
    )
    assert response.status_code == 413
    assert "本次分析文件总大小" in response.json()["detail"]


def test_upload_rejects_when_single_file_exceeds_file_limit(monkeypatch):
    import app.main as main_module

    monkeypatch.setattr(main_module, "MAX_UPLOAD_BYTES", 5)
    response = client.post(
        "/api/logs/upload",
        files={"file": ("large.log", b"123456", "text/plain")},
    )
    assert response.status_code == 413
    assert "large.log" in response.json()["detail"]


def test_upload_rejects_when_global_upload_storage_is_full(monkeypatch):
    import app.main as main_module

    monkeypatch.setattr(main_module, "MAX_UPLOAD_STORAGE_BYTES", 1)
    response = client.post(
        "/api/logs/upload",
        files={"file": ("full.log", b"123456", "text/plain")},
    )
    assert response.status_code == 507
    assert "上传空间不足" in response.json()["detail"]


def test_upload_rolls_back_when_persisting_files_fails(monkeypatch):
    """落盘失败必须回滚：不能留下「结果正常但没有原始日志」的记录和残留目录。"""

    import app.main as main_module

    seen: dict[str, str] = {}

    def failing_persist(analysis_id: str, uploads) -> None:
        # 模拟写到一半失败：目录和文件已经产生
        directory = main_module.UPLOAD_ROOT / analysis_id
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "partial.log").write_bytes(b"partial")
        seen["analysis_id"] = analysis_id
        raise OSError("disk full")

    monkeypatch.setattr(main_module, "_persist_upload_files", failing_persist)
    response = client.post(
        "/api/logs/upload",
        files={
            "file": (
                "rollback.log",
                b'1.2.3.4 - - [12/Sep/2026:09:00:00 +0800] "GET / HTTP/1.1" 200 1 "-" "ua"',
                "text/plain",
            )
        },
    )

    assert response.status_code == 500
    assert response.json()["detail"] == "原始文件保存失败，本次分析已回滚"
    assert seen["analysis_id"]
    assert not (main_module.UPLOAD_ROOT / seen["analysis_id"]).exists()
    assert repository.get(seen["analysis_id"]) is None


def test_history_api_supports_server_side_pagination_and_filters():
    first = client.post(
        "/api/logs/upload",
        files={"file": ("alpha.log", make_ssh_log(1), "text/plain")},
    )
    second = client.post(
        "/api/logs/upload",
        files={"file": ("beta.log", make_ssh_log(1), "text/plain")},
    )
    assert first.status_code == 200
    assert second.status_code == 200

    response = client.get(
        "/api/logs",
        params={"page": 1, "page_size": 1, "keyword": "beta", "sort": "created_asc"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    assert body["total_pages"] == 1
    assert [item["filename"] for item in body["items"]] == ["beta.log"]
    assert "ssh" in body["available_log_types"]


def test_ssh_multiple_accounts_and_timeline_are_reported():
    lines = [
        f"Sep 12 01:00:{index:02d} host sshd[100]: Failed password for {['root', 'admin', 'deploy'][index % 3]} from 10.0.0.10 port 22 ssh2"
        for index in range(20)
    ]
    result = analyze_log("multi-user.log", "\n".join(lines))
    event = next(item for item in result.events if item.type == "ssh_bruteforce")
    assert "涉及 3 个账户" in event.summary
    assert event.timeline
    assert event.evidence[0] == lines[0]


def test_entity_investigation_returns_records_events_and_timeline():
    response = client.post(
        "/api/logs/upload",
        files={"file": ("entity.log", make_ssh_log(), "text/plain")},
    )
    assert response.status_code == 200
    analysis_id = response.json()["analysis_id"]

    by_ip = client.get(
        f"/api/analysis/{analysis_id}/entities/ip/10.0.0.8?page_size=10"
    )
    assert by_ip.status_code == 200
    payload = by_ip.json()
    assert payload["kind"] == "ip"
    assert payload["records"]["total"] > 0
    assert payload["records"]["items"][0]["source_ip"] == "10.0.0.8"
    assert payload["events"]
    assert payload["timeline"]

    by_account = client.get(
        f"/api/analysis/{analysis_id}/entities/account/root?page_size=10"
    )
    assert by_account.status_code == 200
    assert by_account.json()["records"]["total"] > 0


def test_ssh_success_is_associated_only_with_nearby_failure():
    nearby = analyze_log("nearby.log", make_ssh_log()).events
    assert any(item.type == "ssh_bruteforce_success" for item in nearby)

    distant = analyze_log(
        "distant.log",
        make_ssh_log(success_timestamp="Sep 12 02:00:00"),
    ).events
    assert any(item.type == "ssh_bruteforce" for item in distant)
    assert not any(item.type == "ssh_bruteforce_success" for item in distant)


def test_privileged_login_is_detected():
    result = analyze_log(
        "privileged.log",
        "Sep 12 03:00:00 host sshd[100]: Accepted publickey for administrator from 10.0.0.11 port 22 ssh2",
    )
    event = next(item for item in result.events if item.type == "privileged_login")
    assert event.risk_level == "medium"
    assert "administrator" in event.evidence[0]


def test_repeated_privileged_logons_are_aggregated_by_real_identity():
    content = "\n".join(
        f"Sep 12 03:00:0{index} host sshd[100]: Accepted publickey for administrator from 10.0.0.11 port 22 ssh2"
        for index in range(3)
    )
    result = analyze_log("privileged-repeat.log", content)
    events = [item for item in result.events if item.type == "privileged_login"]
    assert len(events) == 1
    assert events[0].count == 3
    assert "共 3 次" in events[0].summary
    assert len(events[0].evidence_items) == 3


def test_windows_rdp_privileged_logons_keep_rdp_context_when_aggregated():
    result = analyze_log(
        "privileged-rdp-repeat.log",
        "\n\n".join(
            make_windows_log(failures=0, success=True, source_ip="10.0.0.11")
            for _ in range(2)
        ),
    )
    event = next(item for item in result.events if item.type == "privileged_login")
    assert event.count == 2
    assert "RDP" in event.summary


def test_web_sensitive_path_and_traversal_detection():
    result = analyze_log(
        "web.log",
        "\n".join(
            [
                make_web_log("/.git/config", status=404),
                make_web_log("/download?file=../../etc/passwd", status=400, index=1),
                make_web_log("/search?q=/.env", status=200, index=2),
            ]
        ),
    )
    assert any(item.type == "sensitive_path_access" for item in result.events)
    assert any(item.type == "path_traversal_candidate" for item in result.events)
    assert not any(
        item.type == "sensitive_path_access" and "search?q=/.env" in item.evidence[0]
        for item in result.events
    )


def test_web_404_scan_candidate_requires_threshold():
    text = "\n".join(make_web_log(f"/missing-{index}", index=index) for index in range(20))
    result = analyze_log("scan.log", text)
    event = next(item for item in result.events if item.type == "web_scan_candidate")
    assert event.count == 20
    assert len(event.timeline) == 10


def test_sensitive_values_are_redacted_for_ai_context():
    source = (
        "Authorization: Bearer abc123 "
        "Cookie: session=secret-cookie "
        "password=hunter2 token=secret-token"
    )
    sanitized = sanitize_text(source)
    assert "abc123" not in sanitized
    assert "secret-cookie" not in sanitized
    assert "hunter2" not in sanitized
    assert "secret-token" not in sanitized
    assert "[REDACTED]" in sanitized

    records = sanitize_records([{"raw": source, "username": "admin"}])
    assert "abc123" not in records[0]["raw"]
    assert records[0]["username"] == "admin"


def test_ai_context_includes_rule_and_structured_evidence(monkeypatch):
    from app.services.ai import build_ai_context

    result = analyze_log("context.log", make_ssh_log())
    context = build_ai_context(result, [{"raw": "Authorization: Bearer secret-token"}])
    event = context["events"][0]
    assert event["rule_id"] == "ssh.bruteforce.success"
    assert event["evidence_items"][0]["id"].startswith("evidence-")
    assert "secret-token" not in context["records_sample"][0]["raw"]


def test_ai_evidence_ids_are_limited_to_current_analysis():
    from app.services.ai import _validate_response

    result = _validate_response(
        {
            "risk_level": "high",
            "confidence": 0.9,
            "behaviors": [
                {
                    "type": "ssh_bruteforce",
                    "name": "疑似 SSH 暴力破解",
                    "confidence": 0.9,
                    "evidence_ids": ["evidence-real-1", "evidence-invented"],
                    "evidence": ["日志证据"],
                    "analysis": "存在认证失败集中行为。",
                }
            ],
        },
        {"evidence-real-1"},
    )
    assert result["behaviors"][0].evidence_ids == ["evidence-real-1"]


def test_ai_judgement_is_structured_and_persisted(monkeypatch):
    response = client.post(
        "/api/logs/upload",
        files={"file": ("ai.log", make_ssh_log(), "text/plain")},
    )
    analysis_id = response.json()["analysis_id"]

    def fake_ai(result, records):
        assert records
        return {
            "risk_level": "high",
            "confidence": 0.93,
            "conclusion": "AI 认为当前证据高度支持失败认证后出现成功登录的可疑行为。",
            "recommendations": ["核对成功登录后的审计日志。"],
            "behaviors": [
                AiBehavior(
                    type="ssh_bruteforce_success",
                    name="疑似 SSH 暴力破解后成功登录",
                    confidence=0.93,
                    evidence=["短时间内大量失败认证", "随后出现成功登录"],
                    analysis="多个日志特征在时间上连续出现。",
                )
            ],
        }

    monkeypatch.setattr("app.main.request_ai_judgement", fake_ai)
    ai_response = client.post(f"/api/analysis/{analysis_id}/ai")
    assert ai_response.status_code == 200
    body = ai_response.json()
    assert body["ai_status"] == "completed"
    assert body["analysis_source"] == "rules_and_ai"
    assert body["confidence"] == 0.93
    assert body["ai_behaviors"][0]["type"] == "ssh_bruteforce_success"
    assert client.get(f"/api/analysis/{analysis_id}").json()["ai_status"] == "completed"


def test_ai_failure_keeps_local_result(monkeypatch):
    response = client.post(
        "/api/logs/upload",
        files={"file": ("ai-fallback.log", make_ssh_log(), "text/plain")},
    )
    analysis_id = response.json()["analysis_id"]

    def failing_ai(result, records, **_kwargs):
        raise RuntimeError("AI 服务暂时不可用")

    monkeypatch.setattr("app.main.request_ai_judgement", failing_ai)
    ai_response = client.post(f"/api/analysis/{analysis_id}/ai")
    assert ai_response.status_code == 200
    body = ai_response.json()
    assert body["ai_status"] == "unavailable"
    assert body["analysis_source"] == "rules"
    assert body["risk_level"] == "high"
    assert body["ai_error"] == "AI 服务暂时不可用"


def _sample_judgement() -> dict:
    return {
        "risk_level": "high",
        "confidence": 0.93,
        "conclusion": "AI 认为当前证据高度支持失败认证后出现成功登录的可疑行为。",
        "recommendations": ["核对成功登录后的审计日志。"],
        "behaviors": [
            AiBehavior(
                type="ssh_bruteforce_success",
                name="疑似 SSH 暴力破解后成功登录",
                confidence=0.93,
                evidence=["短时间内大量失败认证", "随后出现成功登录"],
                analysis="多个日志特征在时间上连续出现。",
            )
        ],
    }


def test_ai_task_start_polls_to_completed(monkeypatch):
    response = client.post(
        "/api/logs/upload",
        files={"file": ("ai-task.log", make_ssh_log(), "text/plain")},
    )
    analysis_id = response.json()["analysis_id"]

    def fake_ai(result, records, progress_cb=None, delta_cb=None):
        assert records
        if progress_cb:
            progress_cb("call_model")
        return _sample_judgement()

    monkeypatch.setattr("app.main.request_ai_judgement", fake_ai)

    start = client.post(f"/api/analysis/{analysis_id}/ai/start")
    assert start.status_code == 200
    task_id = start.json()["task_id"]

    payload = None
    deadline = time.time() + 5
    while time.time() < deadline:
        poll = client.get(f"/api/ai/tasks/{task_id}")
        assert poll.status_code == 200
        payload = poll.json()
        if payload["status"] != "running":
            break
        time.sleep(0.05)

    assert payload is not None
    assert payload["status"] == "completed"
    assert payload["progress"] == 100
    assert payload["result"]["ai_status"] == "completed"
    assert payload["result"]["ai_behaviors"][0]["type"] == "ssh_bruteforce_success"
    # 数据库里的结果也已更新
    assert client.get(f"/api/analysis/{analysis_id}").json()["ai_status"] == "completed"


def test_ai_task_unknown_id_returns_404():
    assert client.get("/api/ai/tasks/does-not-exist").status_code == 404


def test_ai_task_failure_propagates_error(monkeypatch):
    response = client.post(
        "/api/logs/upload",
        files={"file": ("ai-task-fail.log", make_ssh_log(), "text/plain")},
    )
    analysis_id = response.json()["analysis_id"]

    def failing_ai(result, records, progress_cb=None, delta_cb=None):
        raise RuntimeError("AI 服务暂时不可用")

    monkeypatch.setattr("app.main.request_ai_judgement", failing_ai)
    start = client.post(f"/api/analysis/{analysis_id}/ai/start")
    task_id = start.json()["task_id"]

    payload = None
    deadline = time.time() + 5
    while time.time() < deadline:
        payload = client.get(f"/api/ai/tasks/{task_id}").json()
        if payload["status"] != "running":
            break
        time.sleep(0.05)

    assert payload is not None
    assert payload["status"] == "failed"
    assert "AI 服务暂时不可用" in payload["error"]
    assert payload["result"] is None


def test_download_single_uploaded_file():
    content = make_ssh_log()
    response = client.post(
        "/api/logs/upload",
        files={"file": ("download-me.log", content, "text/plain")},
    )
    analysis_id = response.json()["analysis_id"]
    resp = client.get(f"/api/analysis/{analysis_id}/download")
    assert resp.status_code == 200
    assert "download-me.log" in resp.headers["content-disposition"]
    assert resp.content.decode("utf-8") == content
    manifest = client.get(f"/api/analysis/{analysis_id}/evidence-manifest")
    assert manifest.status_code == 200
    item = manifest.json()["files"][0]
    assert item["filename"] == "download-me.log"
    assert item["size_bytes"] == len(content)
    assert item["sha256"] == hashlib.sha256(content.encode("utf-8")).hexdigest()


def test_download_multiple_uploaded_files_returns_zip():
    response = client.post(
        "/api/logs/upload",
        files=[
            ("files", ("alpha.log", make_ssh_log(), "text/plain")),
            ("files", ("beta.log", make_ssh_log(failures=5, success=False), "text/plain")),
        ],
    )
    analysis_id = response.json()["analysis_id"]
    resp = client.get(f"/api/analysis/{analysis_id}/download")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/zip"
    with zipfile.ZipFile(io.BytesIO(resp.content)) as archive:
        assert archive.namelist() == ["alpha.log", "beta.log", "evidence-manifest.json"]
        assert archive.read("beta.log").decode("utf-8") == make_ssh_log(failures=5, success=False)
        manifest = json.loads(archive.read("evidence-manifest.json"))
        assert {item["filename"] for item in manifest["files"]} == {"alpha.log", "beta.log"}


def test_case_package_contains_evidence_and_reports():
    content = make_ssh_log()
    response = client.post(
        "/api/logs/upload",
        files={"file": ("case.log", content, "text/plain")},
    )
    analysis_id = response.json()["analysis_id"]
    resp = client.get(f"/api/analysis/{analysis_id}/case-package")
    assert resp.status_code == 200
    with zipfile.ZipFile(io.BytesIO(resp.content)) as archive:
        assert set(archive.namelist()) == {
            "evidence/case.log",
            "evidence-manifest.json",
            "report.json",
            "report.html",
        }
        manifest = json.loads(archive.read("evidence-manifest.json"))
        assert manifest["files"][0]["filename"] == "case.log"
        assert "report.json" in manifest["package_files"]
        assert '"risk_level"' in archive.read("report.json").decode("utf-8")
        assert "AI-LogInsight" in archive.read("report.html").decode("utf-8")
        assert manifest["record_count"] > 0
        assert manifest["record_ids"]
        assert manifest["evidence_ids"]
        assert manifest["events"]
        assert manifest["package_integrity"]
        integrity = {
            item["path"]: item["sha256"] for item in manifest["package_integrity"]
        }
        assert integrity["report.json"] == hashlib.sha256(
            archive.read("report.json")
        ).hexdigest()
        assert integrity["evidence/case.log"] == hashlib.sha256(
            archive.read("evidence/case.log")
        ).hexdigest()


def test_download_demo_log_returns_404():
    demo = client.post("/api/demo/analyze", json={"files": ["ssh/auth.log"]})
    assert demo.status_code == 200
    demo_id = demo.json()["analysis_id"]
    resp = client.get(f"/api/analysis/{demo_id}/download")
    assert resp.status_code == 404
    assert "演示日志" in resp.json()["detail"]


def test_ai_config_endpoint_reports_unconfigured_state(monkeypatch):
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    response = client.get("/api/ai/config")
    assert response.status_code == 200
    body = response.json()
    assert body["configured"] is False
    assert body["provider"] == "deepseek"
    assert body["api_key_present"] is False
    assert "deepseek" in body["provider_presets"]
    assert body["provider_presets"]["deepseek"]["base_url"] == "https://api.deepseek.com"
    assert "deepseek-chat" in body["provider_presets"]["deepseek"]["models"]


def test_demo_log_library_lists_supported_types_and_can_analyze_selected_files():
    listed = client.get("/api/demo/logs")
    assert listed.status_code == 200
    items = listed.json()
    categories = {item["category"] for item in items}
    assert {"ssh", "iis", "windows", "structured", "firewall"} <= categories

    selected = [item["path"] for item in items]
    analyzed = client.post("/api/demo/analyze", json={"files": selected})
    assert analyzed.status_code == 200
    body = analyzed.json()["result"]
    assert body["metadata"]["filename"] == f"{len(selected)} 个日志文件"
    assert set(body["metadata"]["source_files"]) == {f"demo-{item['name']}" for item in items}
    assert body["metadata"]["log_type"] == "mixed"


def test_demo_log_library_rejects_paths_outside_allowlist():
    response = client.post("/api/demo/analyze", json={"files": ["../.env"]})
    assert response.status_code == 400


def test_auth_demo_log_produces_local_high_risk_result_without_ai():
    response = client.post(
        "/api/demo/analyze",
        json={"files": ["structured/auth-events-demo.csv"]},
    )
    assert response.status_code == 200
    body = response.json()["result"]
    event = next(item for item in body["events"] if item["type"] == "auth_bruteforce_success")
    assert body["analysis_source"] == "rules"
    assert body["ai_status"] == "not_analyzed"
    assert event["risk_level"] == "high"
    assert event["count"] == 20
    assert event["source_ip"] == "203.0.113.90"
    assert event["rule_id"] == "auth.bruteforce.success"


def test_multiple_logs_are_merged_and_correlated():
    response = client.post(
        "/api/logs/upload",
        files=[
            ("files", ("auth.log", make_ssh_log(), "text/plain")),
            (
                "files",
                (
                    "web.log",
                    make_web_log("/.git/config", status=404),
                    "text/plain",
                ),
            ),
        ],
    )
    assert response.status_code == 200
    result = response.json()["result"]
    assert result["metadata"]["source_files"] == ["auth.log", "web.log"]
    assert result["metadata"]["filename"] == "2 个日志文件"
    assert result["metadata"]["total_lines"] == 22
    assert any(item["type"] == "ssh_bruteforce_success" for item in result["events"])
    assert any(item["type"] == "sensitive_path_access" for item in result["events"])
    ssh_event = next(item for item in result["events"] if item["type"] == "ssh_bruteforce_success")
    assert ssh_event["source_files"] == ["auth.log"]
    assert "同一来源 IP" in ssh_event["correlation_basis"]
    records = client.get(
        f"/api/analysis/{response.json()['analysis_id']}/records?page=1&page_size=10&source_ip=10.0.0.8"
    )
    assert records.status_code == 200
    assert records.json()["total"] == 21
    assert len(records.json()["items"]) == 10
    assert records.json()["items"][0]["source_file"] == "auth.log"
    assert records.json()["available_log_types"] == ["nginx_apache", "ssh"]

    filtered = client.get(
        f"/api/analysis/{response.json()['analysis_id']}/records?path=/.git&log_type=nginx_apache"
    )
    assert filtered.status_code == 200
    assert filtered.json()["total"] == 1
    assert filtered.json()["items"][0]["source_file"] == "web.log"

    focused = client.get(
        f"/api/analysis/{response.json()['analysis_id']}/records?record_id=record-1"
    )
    assert focused.status_code == 200
    assert focused.json()["total"] == 1
    assert focused.json()["items"][0]["record_id"] == "record-1"

    exported = client.get(
        f"/api/analysis/{response.json()['analysis_id']}/records/export?path=/.git"
    )
    assert exported.status_code == 200
    assert "source_file" in exported.text
    assert "web.log" in exported.text


def test_record_status_filter_matches_result_and_status_code():
    response = client.post(
        "/api/logs/upload",
        files=[
            ("files", ("auth.log", make_ssh_log(), "text/plain")),
            ("files", ("web.log", make_web_log("/.git/config", status=404), "text/plain")),
        ],
    )
    assert response.status_code == 200
    analysis_id = response.json()["analysis_id"]

    failures = client.get(f"/api/analysis/{analysis_id}/records?status=failure")
    assert failures.status_code == 200
    assert failures.json()["total"] == 20
    assert all(item["result"] == "failure" for item in failures.json()["items"])

    accepted = client.get(f"/api/analysis/{analysis_id}/records?status=success")
    assert accepted.status_code == 200
    assert accepted.json()["total"] == 1
    assert accepted.json()["items"][0]["result"] == "success"

    not_found = client.get(f"/api/analysis/{analysis_id}/records?status=404")
    assert not_found.status_code == 200
    assert not_found.json()["total"] == 1
    assert not_found.json()["items"][0]["status"] == "404"


def test_analysis_report_exports_json_and_html():
    response = client.post(
        "/api/logs/upload",
        files={"file": ("report.log", make_ssh_log(1), "text/plain")},
    )
    analysis_id = response.json()["analysis_id"]

    json_report = client.get(f"/api/analysis/{analysis_id}/report?format=json")
    assert json_report.status_code == 200
    assert json_report.headers["content-type"].startswith("application/json")
    assert '"risk_level"' in json_report.text

    html_report = client.get(f"/api/analysis/{analysis_id}/report?format=html")
    assert html_report.status_code == 200
    assert html_report.headers["content-type"].startswith("text/html")
    assert "AI-LogInsight" in html_report.text
    assert "事件时间线" in html_report.text

    invalid = client.get(f"/api/analysis/{analysis_id}/report?format=pdf")
    assert invalid.status_code == 400


def test_analysis_report_exports_siem_templates():
    """五套 SIEM 模板：字段名按各平台惯例，缺失字段不产出键（不允许幻觉）。"""

    response = client.post(
        "/api/logs/upload",
        files={"file": ("siem.log", make_ssh_log(1), "text/plain")},
    )
    analysis_id = response.json()["analysis_id"]
    assert response.json()["result"]["events"], "测试前提：至少触发一条检测"

    def get(fmt: str):
        export = client.get(f"/api/analysis/{analysis_id}/report?format={fmt}")
        assert export.status_code == 200, export.text
        return export

    # Splunk CIM：JSON 数组 + CIM 字段名
    splunk = json.loads(get("splunk").text)
    assert isinstance(splunk, list) and splunk
    assert splunk[0]["sourcetype"] == "loginsight:detection"
    assert splunk[0]["src"] == "10.0.0.8"
    assert "risk_level" in splunk[0]

    # Elastic ECS：NDJSON + ECS 字段名
    elastic_lines = get("elastic").text.splitlines()
    assert elastic_lines
    ecs = json.loads(elastic_lines[0])
    assert ecs["event"]["kind"] == "alert"
    assert ecs["source"]["ip"] == "10.0.0.8"

    # OpenSearch bulk：动作行与文档行成对，_index 带日期
    opensearch_lines = get("opensearch").text.splitlines()
    assert len(opensearch_lines) >= 2 and len(opensearch_lines) % 2 == 0
    action = json.loads(opensearch_lines[0])
    assert action["index"]["_index"].startswith("loginsight-detections-")

    # Timesketch：三要素齐全
    sketch = json.loads(get("timesketch").text.splitlines()[0])
    assert sketch["message"] and sketch["datetime"] and sketch["timestamp_desc"]
    assert sketch["data_type"] == "loginsight:detection"

    # SARIF 2.1.0：规则去重 + level 映射
    sarif = json.loads(get("sarif").text)
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "AI-LogInsight"
    assert run["results"]
    assert run["results"][0]["level"] in {"error", "warning", "note"}

    assert "attachment" in get("sarif").headers["content-disposition"]


def test_provider_selection_supports_openai_and_ollama(monkeypatch):
    from app.services.ai import _provider_settings

    monkeypatch.setenv("AI_PROVIDER", "openai_compatible")
    monkeypatch.setenv("OPENAI_BASE_URL", "https://example.test/v1")
    monkeypatch.setenv("OPENAI_MODEL", "example-model")
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    provider, base_url, model, api_key, present = _provider_settings()
    assert (provider, base_url, model, api_key, present) == (
        "openai_compatible",
        "https://example.test/v1",
        "example-model",
        "test-key",
        True,
    )

    monkeypatch.setenv("AI_PROVIDER", "ollama")
    monkeypatch.delenv("OLLAMA_API_KEY", raising=False)
    provider, base_url, model, api_key, present = _provider_settings()
    assert provider == "ollama"
    assert base_url.endswith("/v1")
    assert model == "llama3.1"
    assert present is True


def test_ai_connection_test_reports_unconfigured_without_call(monkeypatch):
    from app.services.ai import test_ai_connection

    monkeypatch.setenv("AI_PROVIDER", "deepseek")
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    result = test_ai_connection()
    assert result["configured"] is False
    assert result["reachable"] is False


def test_ai_connection_test_reports_reachable_provider(monkeypatch):
    from app.services import ai

    class FakeProvider:
        def complete(self, system_prompt, context, on_delta=None):
            assert context["purpose"] == "connection_test"
            return "ok"

    monkeypatch.setenv("AI_PROVIDER", "deepseek")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "test-key")
    monkeypatch.setattr(ai, "_create_provider", lambda: FakeProvider())
    result = ai.test_ai_connection()
    assert result["configured"] is True
    assert result["reachable"] is True


def test_openai_compatible_provider_posts_chat_completion(monkeypatch):
    import json
    from app.services.ai import OpenAICompatibleProvider

    captured = {}

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return b'{"choices":[{"message":{"content":"{\\"status\\":\\"ok\\"}"}}]}'

    def fake_urlopen(http_request, timeout):
        captured["url"] = http_request.full_url
        captured["headers"] = dict(http_request.headers)
        captured["payload"] = json.loads(http_request.data)
        return FakeResponse()

    monkeypatch.setattr("app.services.ai.request.urlopen", fake_urlopen)
    content = OpenAICompatibleProvider(
        "https://gateway.example/v1", "custom-model", "secret"
    ).complete("system", {"sample": True})
    assert content == '{"status":"ok"}'
    assert captured["url"] == "https://gateway.example/v1/chat/completions"
    assert captured["headers"]["Authorization"] == "Bearer secret"
    assert captured["payload"]["model"] == "custom-model"


def test_anthropic_provider_posts_messages_request(monkeypatch):
    import json
    from app.services.ai import AnthropicProvider

    captured = {}

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return b'{"content":[{"type":"text","text":"{\\"status\\":\\"ok\\"}"}]}'

    def fake_urlopen(http_request, timeout):
        captured["url"] = http_request.full_url
        captured["headers"] = dict(http_request.headers)
        captured["payload"] = json.loads(http_request.data)
        return FakeResponse()

    monkeypatch.setattr("app.services.ai.request.urlopen", fake_urlopen)
    content = AnthropicProvider(
        "https://api.anthropic.com", "claude-test", "secret"
    ).complete("system", {"sample": True})
    assert content == '{"status":"ok"}'
    assert captured["url"] == "https://api.anthropic.com/v1/messages"
    assert captured["headers"]["X-api-key"] == "secret"
    assert captured["payload"]["model"] == "claude-test"


def test_generic_provider_settings_and_alias(monkeypatch):
    from app.services.ai import _provider_settings

    monkeypatch.setenv("AI_PROVIDER", "custom")
    monkeypatch.setenv("AI_API_KEY", "generic-key")
    monkeypatch.setenv("AI_BASE_URL", "https://provider.example/v1")
    monkeypatch.setenv("AI_MODEL", "generic-model")
    assert _provider_settings() == (
        "openai_compatible",
        "https://provider.example/v1",
        "generic-model",
        "generic-key",
        True,
    )


def test_non_ascii_api_key_reports_readable_config_problem(monkeypatch):
    """真实事故回归：`.env` 里没替换的中文占位符 Key 曾让 11 条评测用例
    全部失败在 `'latin-1' codec can't encode characters` 上——报错指不到病因。
    现在必须给出可读原因，并且在配置检查里就把该配置视为不可用。
    """

    from app.services.ai import _api_key_problem, _create_provider, check_ai_config

    monkeypatch.setenv("AI_PROVIDER", "deepseek")
    monkeypatch.setenv("AI_BASE_URL", "https://api.deepseek.com/v1")
    monkeypatch.setenv("AI_MODEL", "deepseek-chat")
    monkeypatch.setenv("AI_API_KEY", "在此填写密钥xxx")

    problem = _api_key_problem("在此填写密钥xxx")
    assert problem and "非 ASCII" in problem
    assert _api_key_problem("sk-abcdef123456") is None

    status = check_ai_config()
    assert status.configured is False
    assert "非 ASCII" in status.message

    with pytest.raises(Exception) as excinfo:
        _create_provider()
    assert "非 ASCII" in str(excinfo.value)


def test_iis_log_is_recognized_and_web_rules_apply():
    response = client.post(
        "/api/logs/upload",
        files={"file": ("iis-access.log", make_iis_log(), "text/plain")},
    )
    assert response.status_code == 200
    body = response.json()["result"]
    assert body["metadata"]["log_type"] == "iis"
    event_types = {item["type"] for item in body["events"]}
    assert {"web_scan_candidate", "sensitive_path_access", "path_traversal_candidate"} <= event_types
    assert body["risk_level"] == "high"

    scan_event = next(item for item in body["events"] if item["type"] == "web_scan_candidate")
    assert scan_event["rule_id"] == "web.404_scan"
    assert scan_event["count"] == 22

    page = client.get(
        f"/api/analysis/{response.json()['analysis_id']}/records?log_type=iis&page_size=10"
    )
    assert page.status_code == 200
    payload = page.json()
    assert payload["available_log_types"] == ["iis"]
    assert payload["total"] == 22
    # IIS 解析出的目的 IP（s-ip）应落到记录字段
    assert payload["items"][0]["destination_ip"] == "10.0.0.5"
    assert payload["items"][0]["action"] == "GET"


def test_windows_rdp_log_is_recognized_and_detected():
    response = client.post(
        "/api/logs/upload",
        files={"file": ("Security-rdp.log", make_windows_log(), "text/plain")},
    )
    assert response.status_code == 200
    body = response.json()["result"]
    assert body["metadata"]["log_type"] == "windows_rdp"
    assert body["statistics"]["failed_login"] == 12
    assert body["statistics"]["successful_login"] == 1

    success_event = next(item for item in body["events"] if item["type"] == "rdp_bruteforce_success")
    assert success_event["rule_id"] == "rdp.bruteforce.success"
    assert success_event["risk_level"] == "high"
    assert "10.0.0.9" in success_event["summary"]
    assert success_event["count"] == 12

    privileged = next(item for item in body["events"] if item["type"] == "privileged_login")
    assert privileged["rule_id"] == "windows.privileged_logon"
    assert "RDP" in privileged["summary"]

    records = client.get(
        f"/api/analysis/{response.json()['analysis_id']}/records?status=4625&page_size=10"
    )
    assert records.status_code == 200
    assert records.json()["total"] == 12
    assert records.json()["items"][0]["action"] == "rdp_logon"


def test_json_event_log_is_recognized_and_uses_auth_rules():
    response = client.post(
        "/api/logs/upload",
        files={"file": ("vpn-events.json", make_json_event_log(), "application/json")},
    )
    assert response.status_code == 200
    body = response.json()["result"]
    assert body["metadata"]["log_type"] == "json"
    # result 字段已归一化：中文「失败」与英文 failure 都计入失败
    assert body["statistics"]["failed_login"] == 20
    assert body["statistics"]["successful_login"] == 1

    event_types = {item["type"] for item in body["events"]}
    assert "auth_bruteforce_success" in event_types
    # 通用结构化日志不应被标记成 SSH
    assert not any(name.startswith("ssh_") for name in event_types)

    event = next(item for item in body["events"] if item["type"] == "auth_bruteforce_success")
    assert event["rule_id"] == "auth.bruteforce.success"
    assert event["risk_level"] == "high"
    assert event["count"] == 20

    page = client.get(
        f"/api/analysis/{response.json()['analysis_id']}/records?log_type=json&page_size=10"
    )
    payload = page.json()
    assert payload["available_log_types"] == ["json"]
    assert payload["total"] == 21
    assert payload["items"][0]["destination_ip"] == "10.0.0.20"
    assert payload["items"][0]["source_ip"] == "198.51.100.30"
    assert payload["items"][0]["timestamp_iso"].startswith("2026-09-12T05:00:00")


def test_ndjson_and_semicolon_csv_events_are_supported():
    ndjson = "\n".join(
        [
            json.dumps({"time": "2026-09-12 08:00:00", "ip": "203.0.113.50", "action": "GET", "status": "200", "path": "/index.html"}),
            json.dumps({"time": "2026-09-12 08:00:05", "ip": "203.0.113.50", "action": "GET", "status": "404", "path": "/admin"}),
        ]
    )
    response = client.post(
        "/api/logs/upload",
        files={"file": ("events.ndjson", ndjson, "application/x-ndjson")},
    )
    assert response.status_code == 200
    json_body = response.json()["result"]
    assert json_body["metadata"]["log_type"] == "json"
    assert json_body["metadata"]["parsed_lines"] == 2
    assert {
        item["value"]: item["count"] for item in json_body["statistics"]["status_codes"]
    } == {"200": 1, "404": 1}

    csv_response = client.post(
        "/api/logs/upload",
        files={"file": ("auth-events.csv", make_csv_auth_log(), "text/csv")},
    )
    assert csv_response.status_code == 200
    csv_body = csv_response.json()["result"]
    assert csv_body["metadata"]["log_type"] == "csv"
    assert csv_body["statistics"]["failed_login"] == 20
    csv_event = next(item for item in csv_body["events"] if item["type"] == "auth_bruteforce_success")
    assert csv_event["rule_id"] == "auth.bruteforce.success"


def test_csv_web_events_reuse_web_rules_and_map_destination_ip():
    response = client.post(
        "/api/logs/upload",
        files={"file": ("web-events.csv", make_csv_web_log(), "text/csv")},
    )
    assert response.status_code == 200
    body = response.json()["result"]
    assert body["metadata"]["log_type"] == "csv"
    event_types = {item["type"] for item in body["events"]}
    assert {"web_scan_candidate", "sensitive_path_access"} <= event_types
    scan = next(item for item in body["events"] if item["type"] == "web_scan_candidate")
    assert scan["rule_id"] == "web.404_scan"
    assert scan["count"] == 21

    page = client.get(
        f"/api/analysis/{response.json()['analysis_id']}/records?status=404&page_size=50"
    )
    assert page.json()["total"] == 21
    assert page.json()["items"][0]["destination_ip"] == "10.0.0.5"


def test_pretty_printed_json_larger_than_sample_window_is_detected():
    """缩进格式的 JSON 常超过前 100 行采样窗口，检测必须基于完整文本。"""

    events = [
        {"timestamp": f"2026-09-12T11:00:{index:02d}+08:00", "src_ip": "203.0.113.77", "action": "GET", "status": "200", "path": f"/page-{index}"}
        for index in range(60)
    ]
    payload = json.dumps({"events": events}, ensure_ascii=False, indent=2)
    assert len(payload.splitlines()) > 100
    response = client.post(
        "/api/logs/upload",
        files={"file": ("pretty.json", payload, "application/json")},
    )
    assert response.status_code == 200
    body = response.json()["result"]
    assert body["metadata"]["log_type"] == "json"
    assert body["metadata"]["parsed_lines"] == 60


def test_plain_text_without_structured_fields_stays_generic():
    response = client.post(
        "/api/logs/upload",
        files={"file": ("notes.txt", "这是一段没有结构化字段的说明文本。\n第二行同样没有字段。", "text/plain")},
    )
    assert response.status_code == 200
    body = response.json()["result"]
    assert body["metadata"]["log_type"] == "generic"
    assert body["events"] == []
    assert body["risk_level"] == "info"


def test_windows_failures_below_threshold_do_not_alert():
    response = client.post(
        "/api/logs/upload",
        files={"file": ("Security-single.log", make_windows_log(failures=3, success=False), "text/plain")},
    )
    assert response.status_code == 200
    body = response.json()["result"]
    assert body["metadata"]["log_type"] == "windows_rdp"
    assert body["statistics"]["failed_login"] == 3
    assert body["events"] == []
    assert body["has_suspicious_behavior"] is False
    assert body["risk_level"] == "info"


def test_firewall_log_is_recognized_and_port_scan_is_detected():
    response = client.post(
        "/api/logs/upload",
        files={"file": ("firewall.log", make_firewall_log(), "text/plain")},
    )
    assert response.status_code == 200
    body = response.json()["result"]
    assert body["metadata"]["log_type"] == "firewall_waf"
    assert body["metadata"]["parsed_lines"] == 10
    event = next(item for item in body["events"] if item["type"] == "firewall_port_scan_candidate")
    assert event["rule_id"] == "firewall.port_scan"
    assert event["count"] == 10
    assert event["risk_level"] == "medium"
    assert event["evidence_items"][0]["destination_ip"] == "10.0.0.5"
    assert event["evidence_items"][0]["destination_port"] == "22"

    records = client.get(
        f"/api/analysis/{response.json()['analysis_id']}/records?log_type=firewall_waf"
    )
    assert records.status_code == 200
    assert records.json()["items"][0]["protocol"] == "TCP"


def test_firewall_port_scan_requires_threshold(monkeypatch):
    monkeypatch.setenv("FIREWALL_PORT_SCAN_THRESHOLD", "10")
    result = analyze_log("firewall-single.log", make_firewall_log(ports=9))
    assert result.events == []


def test_firewall_port_scan_can_be_disabled(monkeypatch):
    monkeypatch.setenv("RULE_FIREWALL_PORT_SCAN_ENABLED", "false")
    result = analyze_log("firewall-disabled.log", make_firewall_log())
    assert result.events == []


def test_sanitized_web_log_is_parsed_and_attack_signatures_detected():
    """脱敏（无引号、剥离 `/` `:`）的访问日志仍需被识别并命中 Web 攻击特征规则。"""

    response = client.post(
        "/api/logs/upload",
        files={"file": ("access.log", make_sanitized_web_log(), "text/plain")},
    )
    assert response.status_code == 200
    body = response.json()["result"]
    assert body["metadata"]["log_type"] == "nginx_apache"
    assert body["metadata"]["parsed_lines"] == 9

    event_types = {item["type"] for item in body["events"]}
    assert {
        "sql_injection_attempt",
        "xss_attempt",
        "command_injection_attempt",
        "sensitive_interface_probe",
        "webshell_probe",
        "offensive_tool_user_agent",
        "sensitive_path_access",
    } <= event_types
    assert body["risk_level"] == "high"

    injection = next(item for item in body["events"] if item["type"] == "sql_injection_attempt")
    assert injection["rule_id"] == "web.sql_injection"
    assert injection["source_ip"] == "198.51.100.27"
    assert injection["count"] == 2
    assert any("union" in line.lower() for line in injection["evidence"])

    page = client.get(
        f"/api/analysis/{response.json()['analysis_id']}/records?page_size=50"
    ).json()
    first = page["items"][0]
    assert first["timestamp_iso"] == "2026-09-16T09:01:12"
    assert first["status"] == "200"
    assert first["url"] is None


def test_standard_combined_web_log_still_parses():
    """标准 combined 格式（带引号）回归。"""

    response = client.post(
        "/api/logs/upload",
        files={"file": ("access.log", make_web_log("/index.html", status=200), "text/plain")},
    )
    assert response.status_code == 200
    body = response.json()["result"]
    assert body["metadata"]["log_type"] == "nginx_apache"
    assert body["metadata"]["parsed_lines"] == 1
    assert body["statistics"]["status_codes"] == [{"value": "200", "count": 1}]


def test_access_log_upload_succeeds_when_no_rule_matches():
    response = client.post(
        "/api/logs/upload",
        files={"file": ("access.log", make_web_log("/index.html", status=200), "text/plain")},
    )
    assert response.status_code == 200
    body = response.json()["result"]
    assert body["metadata"]["log_type"] == "nginx_apache"
    assert body["metadata"]["parsed_lines"] == 1
    assert body["events"] == []
    assert body["analysis_source"] == "rules"
    assert body["risk_level"] == "info"


def test_web_404_scan_respects_configured_time_window(monkeypatch):
    monkeypatch.setenv("WEB_404_THRESHOLD", "20")
    monkeypatch.setenv("WEB_404_WINDOW_SECONDS", "300")
    lines = [
        make_web_log("/old-a", index=index).replace("01:00:", "01:00:")
        for index in range(10)
    ] + [
        make_web_log("/old-b", index=index).replace("01:00:", "01:10:")
        for index in range(10)
    ]
    result = analyze_log("spread-404.log", "\n".join(lines))
    assert not any(event.type == "web_scan_candidate" for event in result.events)


def test_web_5xx_burst_is_a_medium_candidate_with_follow_up_guidance():
    content = "\n".join(make_web_log("/api/orders", status=500, index=index) for index in range(5))
    response = client.post(
        "/api/logs/upload",
        files={"file": ("server-errors.log", content, "text/plain")},
    )
    assert response.status_code == 200
    body = response.json()["result"]
    event = next(item for item in body["events"] if item["type"] == "web_server_error_burst")
    assert event["rule_id"] == "web.5xx_burst"
    assert event["risk_level"] == "medium"
    assert event["count"] == 5
    assert any("5xx" in item for item in body["recommendations"])


def test_evtx_event_xml_maps_auth_fields():
    from app.services.evtx import event_to_record

    record, is_auth = event_to_record(
        make_evtx_xml_event(4625, "administrator", "203.0.113.70", 10, "2026-09-16T03:00:00.500000Z")
    )
    assert is_auth is True
    assert record["action"] == "rdp_logon"
    assert record["result"] == "failure"
    assert record["username"] == "administrator"
    assert record["source_ip"] == "203.0.113.70"
    assert record["status"] == "4625"
    assert record["timestamp_iso"].startswith("2026-09-16T03:00:00")
    assert "Logon Type: 10" in record["raw"]


def test_evtx_non_auth_event_maps_to_generic_record():
    from app.services.evtx import event_to_record

    record, is_auth = event_to_record(
        make_evtx_xml_event(7045, "SYSTEM", "-", 0, "2026-09-16T04:00:00.000000Z")
    )
    assert is_auth is False
    assert record["action"] == "event"
    assert record["result"] is None
    assert record["status"] == "7045"
    assert record["source_ip"] is None


def test_evtx_xml_export_is_recognized_and_analysed():
    response = client.post(
        "/api/logs/upload",
        files={"file": ("Security-export.xml", make_evtx_xml_log(), "text/xml")},
    )
    assert response.status_code == 200
    body = response.json()["result"]
    assert body["metadata"]["log_type"] == "windows_evtx"
    assert body["metadata"]["parsed_lines"] == 11
    assert body["statistics"]["failed_login"] == 10
    assert body["statistics"]["successful_login"] == 1

    event = next(item for item in body["events"] if item["type"] == "rdp_bruteforce_success")
    assert event["rule_id"] == "rdp.bruteforce.success"
    assert event["risk_level"] == "high"
    assert any("4625" in line for line in event["evidence"])

    page = client.get(
        f"/api/analysis/{response.json()['analysis_id']}/records?status=4625&page_size=50"
    )
    assert page.json()["total"] == 10
    assert page.json()["items"][0]["action"] == "rdp_logon"


def test_evtx_binary_upload_uses_dedicated_parser(monkeypatch):
    import app.services.evtx as evtx_service

    records = [
        {
            "timestamp": f"2026-09-16 03:00:{index:02d}",
            "timestamp_iso": f"2026-09-16T03:00:{index:02d}+08:00",
            "source_ip": "203.0.113.71",
            "destination_ip": None,
            "username": "administrator",
            "action": "rdp_logon",
            "result": "failure",
            "status": "4625",
            "url": None,
            "raw": "Event ID: 4625 | Account Name: administrator | Logon Type: 10",
        }
        for index in range(10)
    ]
    records.append(
        {
            "timestamp": "2026-09-16 03:02:10",
            "timestamp_iso": "2026-09-16T03:02:10+08:00",
            "source_ip": "203.0.113.71",
            "destination_ip": None,
            "username": "administrator",
            "action": "rdp_logon",
            "result": "success",
            "status": "4624",
            "url": None,
            "raw": "Event ID: 4624 | Account Name: administrator | Logon Type: 10",
        }
    )
    monkeypatch.setattr(
        evtx_service,
        "parse_evtx_records_detailed",
        lambda content: (records, 1200, 3, 117),
    )

    response = client.post(
        "/api/logs/upload",
        files={"file": ("Security.evtx", b"ElfFile\x00" + b"\x00" * 32, "application/octet-stream")},
    )
    assert response.status_code == 200
    body = response.json()["result"]
    assert body["metadata"]["log_type"] == "windows_evtx"
    assert body["metadata"]["total_lines"] == 1200
    assert body["metadata"]["parsed_lines"] == 11
    assert any(item["type"] == "rdp_bruteforce_success" for item in body["events"])
    assert any(item["type"] == "privileged_login" for item in body["events"])
    # 未纳入检测的记录要能区分「解析失败」与「超出保留上限」，总数保持兼容
    coverage = body["coverage"]
    assert coverage["parse_failures"] == 120
    assert coverage["parse_errors"] == 3
    assert coverage["retention_drops"] == 117


def test_non_evtx_binary_upload_does_not_crash():
    response = client.post(
        "/api/logs/upload",
        files={"file": ("blob.bin", bytes(range(256)) * 4, "application/octet-stream")},
    )
    assert response.status_code == 200
    body = response.json()["result"]
    assert body["metadata"]["log_type"] == "generic"
    assert body["events"] == []


def test_evtx_binary_parser_uses_real_path_and_cleans_temp(monkeypatch):
    """回归：python-evtx 的 Evtx 需要真实文件路径（内部 mmap），不能传 BytesIO。"""

    import os

    import app.services.evtx as evtx_service
    from app.services.evtx import parse_evtx_records

    seen: dict[str, str] = {}

    class FakeEvtx:
        def __init__(self, filename: str):
            seen["filename"] = filename
            seen["type"] = type(filename).__name__

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def records(self):
            return iter([])

    monkeypatch.setattr(evtx_service, "Evtx", FakeEvtx)
    records, total, dropped = parse_evtx_records(b"ElfFile\x00" + b"\x00" * 32)

    assert seen["type"] == "str"
    assert seen["filename"].endswith(".evtx")
    assert not os.path.exists(seen["filename"])  # 临时文件已被清理
    assert records == []
    assert total == 0
    assert dropped == 0


def make_web_login_burst(failures: int = 4, success: bool = True, source_ip: str = "198.51.100.77") -> str:
    lines = [
        f"{source_ip} - - [16Sep20260912{31 + index} +0800] POST apilogin HTTP1.1 401 742 - python-requests2.32.5"
        for index in range(failures)
    ]
    if success:
        lines.append(
            f"{source_ip} - - [16Sep2026091239 +0800] POST apilogin HTTP1.1 200 1832 - python-requests2.32.5"
        )
    return "\n".join(lines)


def test_web_login_failure_burst_with_followup_success():
    response = client.post(
        "/api/logs/upload",
        files={"file": ("access.log", make_web_login_burst(), "text/plain")},
    )
    assert response.status_code == 200
    body = response.json()["result"]
    event = next(
        item for item in body["events"] if item["type"] == "web_authentication_failure_success"
    )
    assert event["rule_id"] == "web.auth_bruteforce.success"
    assert event["risk_level"] == "high"
    assert event["count"] == 4
    assert event["source_ip"] == "198.51.100.77"
    assert "apilogin" in event["summary"]


def test_web_login_failure_below_threshold_does_not_alert(monkeypatch):
    monkeypatch.setenv("WEB_AUTH_FAILURE_THRESHOLD", "4")
    response = client.post(
        "/api/logs/upload",
        files={"file": ("access.log", make_web_login_burst(failures=3, success=False), "text/plain")},
    )
    body = response.json()["result"]
    assert body["events"] == []
    assert body["risk_level"] == "info"


def make_app_log() -> str:
    lines = [
        f"2026-09-16 09:01:{index:02d},101 INFO  [http-nio-8080-exec-{index}] "
        f"c.e.order.OrderService - 订单创建成功 orderId=SO202609160{index:02d} amount={index}.50"
        for index in range(10)
    ]
    lines += [
        f"2026-09-16 09:02:{index:02d},204 WARN  [http-nio-8080-exec-{index}] "
        f"c.e.inventory.StockService - 库存扣减失败 sku=SKU1002{index} retry=1"
        for index in range(5)
    ]
    lines += [
        "2026-09-16 09:03:00,120 ERROR [http-nio-8080-exec-1] c.e.common.AlertNotifier - "
        "java.lang.OutOfMemoryError: Java heap space",
        "2026-09-16 09:03:41,233 WARN  [http-nio-8080-exec-2] c.e.gateway.SignatureFilter - "
        "检测到异常请求签名 source=203.0.113.45 uri=/api/order 疑似重放请求",
    ]
    return "\n".join(lines)


def test_generic_log_is_template_mined():
    response = client.post(
        "/api/logs/upload",
        files={"file": ("app.log", make_app_log(), "text/plain")},
    )
    assert response.status_code == 200
    result = response.json()["result"]
    assert result["metadata"]["log_type"] == "generic"
    assert result["metadata"]["parsed_lines"] == 0

    templates = result["templates"]
    assert templates, "generic 日志必须产出模板挖掘结果"
    assert templates[0]["count"] == 10
    assert templates[0]["ratio"] > 0.5
    assert "订单创建成功" in templates[0]["template"]
    assert templates[0]["rare"] is False
    rare = [item for item in templates if item["rare"]]
    assert len(rare) == 2
    assert any("OutOfMemoryError" in item["template"] for item in rare)
    assert any("source=<IP>" in item["template"] for item in rare)


def test_known_log_type_skips_template_mining():
    response = client.post(
        "/api/logs/upload",
        files={"file": ("auth.log", make_ssh_log(), "text/plain")},
    )
    assert response.status_code == 200
    assert response.json()["result"]["templates"] == []


def test_entity_profiles_link_same_ip_across_log_types():
    response = client.post(
        "/api/logs/upload",
        files=[
            ("files", ("auth.log", make_ssh_log(), "text/plain")),
            (
                "files",
                (
                    "web.log",
                    make_web_log("/.git/config", status=404).replace("10.0.0.9", "10.0.0.8"),
                    "text/plain",
                ),
            ),
        ],
    )
    assert response.status_code == 200
    result = response.json()["result"]

    entity = next(
        item for item in result["entities"] if item["kind"] == "source_ip" and item["value"] == "10.0.0.8"
    )
    assert entity["risk_level"] == "high"
    assert entity["event_count"] >= 2
    assert entity["source_files"] == ["auth.log", "web.log"]
    assert sorted(entity["log_types"]) == ["nginx_apache", "ssh"]
    assert "跨 2 类日志" in entity["summary"]
    assert entity["first_seen"] and entity["last_seen"]
    assert entity["rule_ids"]
    assert result["entities"][0]["value"] == "10.0.0.8"


def test_timeline_merges_events_and_evidence_in_time_order():
    response = client.post(
        "/api/logs/upload",
        files={"file": ("auth.log", make_ssh_log(), "text/plain")},
    )
    assert response.status_code == 200
    result = response.json()["result"]
    timeline = result["timeline"]
    assert timeline
    assert timeline[0]["kind"] == "event"
    assert any(item["kind"] == "evidence" for item in timeline)
    assert [item["timestamp_iso"] for item in timeline] == sorted(
        item["timestamp_iso"] for item in timeline
    )
    event_entries = [item for item in timeline if item["kind"] == "event"]
    assert len(event_entries) == len(result["events"])
    assert {item["rule_id"] for item in event_entries} >= {
        "ssh.bruteforce.success",
        "ssh.privileged_login",
    }
    assert all(item["record_id"] for item in event_entries)


def test_timeline_is_empty_without_events():
    response = client.post(
        "/api/logs/upload",
        files={"file": ("web.log", make_web_log("/index.html", status=200), "text/plain")},
    )
    assert response.status_code == 200
    result = response.json()["result"]
    assert result["events"] == []
    assert result["timeline"] == []


def test_ai_context_carries_templates_entities_and_timeline():
    from app.services.ai import build_ai_context

    generic = analyze_log("app.log", make_app_log())
    context = build_ai_context(generic, [])
    assert context["templates"][0]["template"]
    assert context["templates"][0]["count"] == 10

    ssh = analyze_log("auth.log", make_ssh_log())
    context = build_ai_context(ssh, [])
    assert context["entities"][0]["value"] == "10.0.0.8"
    assert context["timeline"]
    assert context["timeline"][0]["kind"] == "event"


def test_agent_tools_expose_read_only_log_context():
    from app.services.agent_tools import execute_tool

    result = analyze_log("auth.log", make_ssh_log())
    metadata = execute_tool("log_metadata", {}, result, [])
    assert metadata["log_type"] == "ssh"
    assert metadata["total_lines"] == 21
    assert "ssh" in metadata["summary"]

    statistics = execute_tool("log_statistics", {}, result, [])
    assert statistics["failed_login"] == 20
    assert statistics["successful_login"] == 1
    assert statistics["top_source_ips"][0]["value"] == "10.0.0.8"

    events = execute_tool("query_events", {"risk_level": "high"}, result, [])
    assert events["total"] >= 1
    assert all(item["risk_level"] == "high" for item in events["events"])
    assert events["events"][0]["rule_id"].startswith("ssh.")

    evidence = execute_tool("query_evidence", {"limit": 3}, result, [])
    assert evidence["total"] >= 3
    assert len(evidence["evidence"]) == 3
    assert evidence["evidence"][0]["evidence_id"]
    assert evidence["evidence"][0]["raw"]

    timeline = execute_tool("timeline", {"limit": 5}, result, [])
    assert timeline["total"] == len(result.timeline)
    assert len(timeline["entries"]) == 5
    assert timeline["entries"][0]["kind"] == "event"


def test_agent_tools_expose_behavior_deviations_and_exact_uncovered_records():
    from app.services.agent_tools import execute_tool

    normal = (
        '203.0.113.40 - - [12/Sep/2026:06:00:00 +0800] "GET /index.html HTTP/1.1" 200 5120 "-" "Mozilla/5.0"\n'
        '203.0.113.41 - - [12/Sep/2026:06:00:01 +0800] "GET /health HTTP/1.1" 200 5120 "-" "Mozilla/5.0"\n'
    )
    result = analyze_log("normal.log", normal)
    deviations = execute_tool("query_behavior_deviations", {}, result, result.metadata.model_dump())
    assert deviations["total"] >= 1
    assert deviations["deviations"][0]["basis"]

    records = [
        {"record_id": "record-1", "raw": "vendor event alpha"},
        {"record_id": "record-2", "raw": "vendor event beta"},
    ]
    uncovered = execute_tool("query_uncovered_records", {}, result, records)
    assert uncovered["total"] == 2
    assert {item["record_id"] for item in uncovered["records"]} == {"record-1", "record-2"}


def test_terminal_records_have_queryable_evidence_ids():
    from app.services.agent_tools import execute_tool

    result = analyze_log("sysmon.xml", "<Event><EventID>1</EventID></Event>")
    records = [{
        "record_id": "record-7",
        "evidence_id": "evidence-record-7",
        "log_type": "windows_evtx",
        "process_image": r"C:\Temp\drop.exe",
        "raw": "Image=C:\\Temp\\drop.exe",
    }]

    uncovered = execute_tool("query_uncovered_records", {}, result, records)
    assert uncovered["records"][0]["evidence_id"] == "evidence-record-7"

    evidence = execute_tool(
        "query_evidence", {"evidence_id": "evidence-record-7"}, result, records
    )
    assert evidence["total"] == 1
    assert evidence["evidence"][0]["process_image"].endswith("drop.exe")


def test_record_api_exposes_terminal_fields():
    from app.main import app
    from fastapi.testclient import TestClient

    client = TestClient(app)
    payload = (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
        '<Provider Name="Microsoft-Windows-Sysmon"/><EventID>1</EventID>'
        '<TimeCreated SystemTime="2025-08-05T09:01:16.4092700Z"/><Computer>WK001</Computer>'
        '</System><EventData><Data Name="Image">C:\\Temp\\drop.exe</Data>'
        '<Data Name="CommandLine">drop.exe -x</Data></EventData></Event>'
    )
    response = client.post(
        "/api/logs/upload",
        files={"file": ("sysmon.xml", payload, "application/xml")},
    )
    assert response.status_code == 200
    analysis_id = response.json()["analysis_id"]
    records = client.get(f"/api/analysis/{analysis_id}/records")
    assert records.status_code == 200
    item = records.json()["items"][0]
    assert item["process_image"] == r"C:\Temp\drop.exe"
    assert item["command_line"] == "drop.exe -x"
    assert item["target_asset"] == "WK001"
    assert item["event_id"] == "1"


def test_terminal_evidence_chains_group_host_behaviors_and_keep_evidence_ids():
    from app.services.correlation import build_terminal_evidence_chains

    records = [
        {
            "record_id": "record-1", "evidence_id": "evidence-record-1",
            "timestamp": "2026-09-12 01:00:00", "timestamp_iso": "2026-09-12T01:00:00+08:00",
            "target_asset": "WK001", "process_image": r"C:\Temp\drop.exe",
            "raw": "Image=C:\\Temp\\drop.exe",
        },
        {
            "record_id": "record-2", "evidence_id": "evidence-record-2",
            "timestamp": "2026-09-12 01:00:01", "timestamp_iso": "2026-09-12T01:00:01+08:00",
            "target_asset": "WK001", "target_filename": r"C:\Users\Public\payload.exe",
            "raw": "TargetFilename=C:\\Users\\Public\\payload.exe",
        },
        {
            "record_id": "record-3", "evidence_id": "evidence-record-3",
            "timestamp": "2026-09-12 01:00:02", "timestamp_iso": "2026-09-12T01:00:02+08:00",
            "target_asset": "WK001", "registry_key": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Updater",
            "raw": "TargetObject=HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
        },
        {
            "record_id": "record-4", "evidence_id": "evidence-record-4",
            "timestamp": "2026-09-12 01:00:03", "timestamp_iso": "2026-09-12T01:00:03+08:00",
            "target_asset": "WK001", "query_name": "cdn.example.test",
            "raw": "QueryName=cdn.example.test",
        },
        {
            "record_id": "record-5", "evidence_id": "evidence-record-5",
            "timestamp": "2026-09-12 01:00:04", "timestamp_iso": "2026-09-12T01:00:04+08:00",
            "target_asset": "WK001", "destination_ip": "203.0.113.5", "destination_port": "443",
            "raw": "DestinationIp=203.0.113.5 DestinationPort=443",
        },
        {
            "record_id": "record-6", "evidence_id": "evidence-record-6",
            "timestamp": "2026-09-12 01:00:05", "timestamp_iso": "2026-09-12T01:00:05+08:00",
            "target_asset": "WK002", "process_image": r"C:\Windows\System32\svchost.exe",
            "raw": "Image=C:\\Windows\\System32\\svchost.exe",
        },
    ]
    chains = build_terminal_evidence_chains(records, [])
    assert len(chains) == 2
    wk001 = next(item for item in chains if item["target_asset"] == "WK001")
    assert wk001["record_count"] == 5
    assert {node["kind"] for node in wk001["nodes"]} == {
        "process_created", "file_activity", "registry_change", "dns_query", "outbound_connection",
    }
    assert {node["evidence_id"] for node in wk001["nodes"]} == {
        f"evidence-record-{index}" for index in range(1, 6)
    }


def test_terminal_chain_builds_process_and_dns_relationships():
    from app.services.correlation import build_terminal_evidence_chains

    records = [
        {
            "record_id": "record-1", "evidence_id": "evidence-record-1",
            "timestamp": "2026-09-12 01:00:00", "timestamp_iso": "2026-09-12T01:00:00+08:00",
            "target_asset": "WK001", "process_image": r"C:\Windows\explorer.exe",
            "process_id": "100", "raw": "Image=explorer.exe ProcessId=100",
        },
        {
            "record_id": "record-2", "evidence_id": "evidence-record-2",
            "timestamp": "2026-09-12 01:00:01", "timestamp_iso": "2026-09-12T01:00:01+08:00",
            "target_asset": "WK001", "process_image": r"C:\Temp\drop.exe",
            "process_id": "200", "parent_process_id": "100",
            "parent_image": r"C:\Windows\explorer.exe",
            "raw": "Image=drop.exe ProcessId=200 ParentProcessId=100",
        },
        {
            "record_id": "record-3", "evidence_id": "evidence-record-3",
            "timestamp": "2026-09-12 01:00:02", "timestamp_iso": "2026-09-12T01:00:02+08:00",
            "target_asset": "WK001", "query_name": "cdn.example.test",
            "query_results": "203.0.113.5", "raw": "QueryName=cdn.example.test QueryResults=203.0.113.5",
        },
        {
            "record_id": "record-4", "evidence_id": "evidence-record-4",
            "timestamp": "2026-09-12 01:00:03", "timestamp_iso": "2026-09-12T01:00:03+08:00",
            "target_asset": "WK001", "destination_ip": "203.0.113.5",
            "destination_port": "443", "raw": "DestinationIp=203.0.113.5",
        },
    ]
    chain = build_terminal_evidence_chains(records, [])[0]
    relationships = chain["relationships"]
    assert {item["kind"] for item in relationships} == {"parent_process", "dns_to_connection"}
    assert {item["confidence"] for item in relationships} == {"strong"}
    assert all(item["from_evidence_id"] and item["to_evidence_id"] for item in relationships)


def test_terminal_chain_tool_filters_by_asset_and_kind():
    from app.services.agent_tools import execute_tool

    records = [
        {
            "record_id": "record-1", "evidence_id": "evidence-record-1",
            "timestamp": "2026-09-12 01:00:00", "timestamp_iso": "2026-09-12T01:00:00+08:00",
            "target_asset": "WK001", "process_image": r"C:\Temp\drop.exe", "raw": "drop",
        }
    ]
    result = analyze_log("sysmon.log", "<Event><EventID>1</EventID></Event>")
    from app.services.correlation import build_terminal_evidence_chains
    result.terminal_chains = build_terminal_evidence_chains(records, [])
    output = execute_tool(
        "query_terminal_chains", {"target_asset": "WK001", "kind": "process_created"}, result, records
    )
    assert output["total"] == 1
    assert output["chains"][0]["nodes"][0]["evidence_id"] == "evidence-record-1"


def test_terminal_chain_tool_drops_null_fields_and_duplicate_timestamp():
    """节点只下发有值的白名单字段：null 与重复的 timestamp_iso 都是纯浪费。

    实测一条链 100 个节点时原文 71 KB，其中过半是恒为 null 的字段。
    """

    import json

    from app.services.agent_tools import execute_tool
    from app.services.correlation import build_terminal_evidence_chains

    records = [
        {
            "record_id": "record-1", "evidence_id": "evidence-record-1",
            "timestamp": "2026-09-12 01:00:00", "timestamp_iso": "2026-09-12T01:00:00+08:00",
            "target_asset": "WK001", "target_filename": r"C:\Temp\a.exe",
            "raw": "file",
        }
    ]
    result = analyze_log("sysmon.log", "<Event><EventID>11</EventID></Event>")
    result.terminal_chains = build_terminal_evidence_chains(records, [])
    output = execute_tool("query_terminal_chains", {}, result, records)

    node = output["chains"][0]["nodes"][0]
    # 证据锚点必须保留
    assert node["evidence_id"] == "evidence-record-1"
    assert node["target_filename"] == r"C:\Temp\a.exe"
    # 该节点不涉及的字段不应以 null 形式出现
    assert node.get("destination_ip") is None
    assert "destination_ip" not in node
    assert "process_image" not in node
    # 与 timestamp 重复的 timestamp_iso 被丢弃
    assert "timestamp_iso" not in node
    # 整份输出里不应残留 null 字面量
    assert "null" not in json.dumps(output, ensure_ascii=False)


def test_terminal_chain_tool_caps_nodes_and_reports_the_cap():
    """单链节点数要有上限，否则一条 100 节点的链会独占整个工具预算。"""

    from app.services.agent_tools import MAX_CHAIN_NODES, execute_tool
    from app.services.correlation import build_terminal_evidence_chains

    records = [
        {
            "record_id": f"record-{index}", "evidence_id": f"evidence-record-{index}",
            "timestamp": f"2026-09-12 01:00:{index:02d}",
            "timestamp_iso": f"2026-09-12T01:00:{index:02d}+08:00",
            "target_asset": "WK001", "target_filename": rf"C:\Temp\n{index}.exe",
            "raw": f"file {index}",
        }
        for index in range(MAX_CHAIN_NODES + 25)
    ]
    result = analyze_log("sysmon.log", "<Event><EventID>11</EventID></Event>")
    result.terminal_chains = build_terminal_evidence_chains(records, [])
    output = execute_tool("query_terminal_chains", {}, result, records)

    assert output["node_limit_per_chain"] == MAX_CHAIN_NODES
    assert len(output["chains"][0]["nodes"]) == MAX_CHAIN_NODES


def test_terminal_chain_record_count_matches_returned_nodes_when_filtered_by_kind():
    """按 kind 过滤后 record_count 必须反映返回内容，不能继续报整链计数。"""

    from app.services.agent_tools import execute_tool
    from app.services.correlation import build_terminal_evidence_chains

    records = [
        {
            "record_id": "record-1", "evidence_id": "evidence-record-1",
            "timestamp": "2026-09-12 01:00:00", "timestamp_iso": "2026-09-12T01:00:00+08:00",
            "target_asset": "WK001", "process_image": r"C:\Temp\drop.exe", "raw": "proc",
        },
        {
            "record_id": "record-2", "evidence_id": "evidence-record-2",
            "timestamp": "2026-09-12 01:00:01", "timestamp_iso": "2026-09-12T01:00:01+08:00",
            "target_asset": "WK001", "query_name": "cdn.example.test",
            "query_results": "203.0.113.5", "raw": "dns",
        },
    ]
    result = analyze_log("sysmon.log", "<Event><EventID>1</EventID></Event>")
    result.terminal_chains = build_terminal_evidence_chains(records, [])

    unfiltered = execute_tool("query_terminal_chains", {}, result, records)
    filtered = execute_tool(
        "query_terminal_chains", {"kind": "process_created"}, result, records
    )

    chain_all = unfiltered["chains"][0]
    chain_filtered = filtered["chains"][0]
    assert len(chain_all["nodes"]) > len(chain_filtered["nodes"])
    # 过滤后计数与返回节点数一致，且摘要里点明了过滤条件
    assert chain_filtered["record_count"] == len(chain_filtered["nodes"])
    assert "仅 process_created 节点" in filtered["summary"]


def _query_records_fixture():
    """构造带完整解析字段的记录，用于验证 query_records 的字段投影。"""

    from app.services.agent_tools import execute_tool
    from app.services.analyzer import assign_record_ids, collect_records
    from app.services.parser import parse_log

    parsed = parse_log(make_ssh_log())
    records = assign_record_ids(collect_records(["auth.log"], [parsed]))
    result = analyze_log("auth.log", make_ssh_log())
    return result, records, execute_tool


def test_query_records_without_field_keeps_the_full_whitelist():
    """未指定 field 时要看全貌，不能顺手裁剪。"""

    from app.services.agent_tools import RECORD_QUERY_FIELDS

    result, records, execute_tool = _query_records_fixture()
    output = execute_tool("query_records", {"limit": 5}, result, records)
    keys = set(output["records"][0])
    assert keys <= set(RECORD_QUERY_FIELDS)
    assert "按查询字段收窄" not in output["summary"]


def test_query_records_narrowed_by_field_drops_unrelated_heavy_fields():
    """只查 `username` 就不该把 `raw` / `command_line` 一并带回来。"""

    result, records, execute_tool = _query_records_fixture()
    output = execute_tool(
        "query_records", {"field": "username", "contains": "root", "limit": 5}, result, records
    )

    assert output["records"], "该条件应有命中"
    for record in output["records"]:
        assert record.get("username"), "被查询字段本身必须保留"
        assert "raw" not in record, "查解析字段不该下发整条原文"
        assert "command_line" not in record, "无关大字段应被裁掉"
    assert "按查询字段收窄" in output["summary"]


def test_query_records_always_keep_the_evidence_anchor():
    """任何查询条件下 evidence_id / record_id 都不能丢，否则结论无法挂证据。"""

    from app.services.agent_tools import RECORD_QUERY_FIELDS

    result, records, execute_tool = _query_records_fixture()
    for field in RECORD_QUERY_FIELDS:
        output = execute_tool("query_records", {"field": field, "limit": 3}, result, records)
        for record in output["records"]:
            assert record.get("evidence_id"), f"field={field} 丢了 evidence_id"
            assert record.get("record_id"), f"field={field} 丢了 record_id"


def test_query_records_raw_and_parsed_fields_are_mutually_exclusive():
    """`raw` 与解析明细是同一件事的两种粒度，同时下发纯属重复计费。"""

    from app.services.agent_tools import _record_query_fields

    by_raw = _record_query_fields("raw")
    by_parsed = _record_query_fields("username")

    assert "raw" in by_raw
    assert "raw" not in by_parsed


def test_query_records_total_matched_is_independent_of_limit():
    """字段裁剪只影响下发体积，不能改变命中口径。"""

    result, records, execute_tool = _query_records_fixture()
    small = execute_tool("query_records", {"field": "username", "limit": 1}, result, records)
    large = execute_tool("query_records", {"field": "username", "limit": 500}, result, records)

    assert small["total_matched"] == large["total_matched"]
    assert small["records_returned"] == 1
    assert large["records_returned"] >= small["records_returned"]


def test_agent_tool_reports_unknown_name_without_raising():
    from app.services.agent_tools import execute_tool

    result = analyze_log("auth.log", make_ssh_log())
    output = execute_tool("delete_host", {"target": "10.0.0.8"}, result, [])
    assert "error" in output
    assert "delete_host" in output["summary"]
    assert "tool" not in output


def test_openai_provider_runs_tool_round_and_records_trace():
    from app.services.ai import OpenAICompatibleProvider

    result = analyze_log("auth.log", make_ssh_log())
    provider = OpenAICompatibleProvider("https://example.invalid/v1", "test-model", "key")
    requests: list[dict[str, object]] = []

    def fake_post(messages, tools=None, on_delta=None):
        requests.append({"messages": list(messages), "tools": tools})
        if len(requests) == 1:
            return {
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "content": None,
                            "tool_calls": [
                                {
                                    "id": "call-1",
                                    "type": "function",
                                    "function": {
                                        "name": "query_events",
                                        "arguments": json.dumps({"risk_level": "high"}),
                                    },
                                }
                            ],
                        }
                    }
                ]
            }
        return {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": json.dumps(
                            {
                                "risk_level": "high",
                                "confidence": 0.9,
                                "summary": "工具结果支持高风险结论。",
                                "behaviors": [],
                                "recommendations": [],
                            }
                        ),
                    }
                }
            ]
        }

    provider._post = fake_post
    content, trace = provider.complete_with_tools("system", {"events": []}, result, [])

    assert requests[0]["tools"], "工具定义必须随请求下发"
    assert len(trace) == 1
    assert trace[0]["tool"] == "query_events"
    assert trace[0]["arguments"] == {"risk_level": "high"}
    assert trace[0]["source"] == "model"
    assert trace[0]["summary"]
    assert requests[1]["messages"][-1]["role"] == "tool"
    assert json.loads(requests[1]["messages"][-1]["content"])["total"] >= 1
    assert json.loads(content)["risk_level"] == "high"


def test_exhausted_tool_round_does_not_bury_the_last_tool_result(monkeypatch):
    """轮次用尽时的收尾提示不能把最后一条 tool 结果挤出末尾。

    真实缺陷：原实现无条件追加「请直接输出最终 JSON 结论，不要再调用工具」，
    导致 `messages[-1]` 从 tool 结果变成这条 user 消息——模型看不到自己刚取回的
    证据就被要求作答，等于白调一轮工具。
    """

    from app.services import ai as ai_service
    from app.services.ai import OpenAICompatibleProvider

    # 收敛到 1 轮，制造「模型调了工具但轮次已用尽」的场景
    monkeypatch.setattr(ai_service, "_effective_tool_rounds", lambda: 1)

    result = analyze_log("auth.log", make_ssh_log())
    provider = OpenAICompatibleProvider("https://example.invalid/v1", "test-model", "key")
    requests: list[dict[str, object]] = []

    def fake_post(messages, tools=None, on_delta=None):
        requests.append({"messages": list(messages)})
        return {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": "call-1",
                                "type": "function",
                                "function": {
                                    "name": "query_events",
                                    "arguments": json.dumps({"risk_level": "high"}),
                                },
                            }
                        ],
                    }
                }
            ]
        }

    provider._post = fake_post
    provider.complete_with_tools("system", {"events": []}, result, [])

    final_messages = requests[-1]["messages"]
    assert final_messages[-1]["role"] == "tool", "tool 结果被收尾提示挤出了末尾"
    assert "summary" in json.loads(final_messages[-1]["content"])


def test_exhausted_round_appends_hint_when_model_already_stopped_calling_tools(monkeypatch):
    """模型已停止调用工具时，收尾提示仍要追加，避免无提示空转。"""

    from app.services import ai as ai_service
    from app.services.ai import OpenAICompatibleProvider

    # 2 轮预算，但模型第一轮就不调工具 → 无法早停（早停需无 calls，这里构造
    # 「第一轮调工具、第二轮不调」以走到轮次上限分支）
    monkeypatch.setattr(ai_service, "_effective_tool_rounds", lambda: 2)

    result = analyze_log("auth.log", make_ssh_log())
    provider = OpenAICompatibleProvider("https://example.invalid/v1", "test-model", "key")
    requests: list[dict[str, object]] = []

    def fake_post(messages, tools=None, on_delta=None):
        requests.append({"messages": list(messages)})
        return {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": json.dumps({"risk_level": "low", "behaviors": []}),
                    }
                }
            ]
        }

    provider._post = fake_post
    # 模型首轮即无 tool_calls → 走早停，不应出现收尾提示
    provider.complete_with_tools("system", {"events": []}, result, [])
    assert len(requests) == 1, "无工具调用时应早停，不再多发一轮"
    assert all(
        "输出最终 JSON 结论" not in str(m.get("content")) for m in requests[-1]["messages"]
    )


def test_ai_judgement_flags_unsupported_ip_claims(monkeypatch):
    from app.services import ai as ai_service

    class StubProvider:
        supports_tools = False

        def complete(self, system_prompt, context, on_delta=None):
            return json.dumps(
                {
                    "risk_level": "high",
                    "confidence": 0.8,
                    "summary": "来源 10.0.0.8 与 8.8.8.8 均存在可疑登录。",
                    "behaviors": [
                        {
                            "type": "ssh_bruteforce_success",
                            "name": "疑似暴力破解",
                            "confidence": 0.8,
                            "evidence": ["record-1 附近出现成功登录"],
                            "evidence_ids": ["evidence-1"],
                            "analysis": "攻击者来自 203.0.113.99 并使用了 record-999。",
                        }
                    ],
                    "recommendations": [],
                }
            )

    monkeypatch.setattr(ai_service, "_create_provider", lambda: StubProvider())
    result = analyze_log("auth.log", make_ssh_log())
    judgement = ai_service.request_ai_judgement(result, [])
    claims = judgement["unsupported_claims"]
    trace = judgement["tool_trace"]
    assert [item["tool"] for item in trace] == [
        name for name, _arguments in ai_service.AUTO_TOOL_PLAN
    ]
    assert {item["source"] for item in trace} == {"auto"}
    assert all(item["summary"] for item in trace)
    assert any("8.8.8.8" in item for item in claims)
    assert any("203.0.113.99" in item for item in claims)
    assert any("record-999" in item for item in claims)
    assert not any("10.0.0.8" in item for item in claims)
    assert not any("record-1" in item for item in claims)


def test_ai_tool_trace_and_claims_are_persisted(monkeypatch):
    response = client.post(
        "/api/logs/upload",
        files={"file": ("ai.log", make_ssh_log(), "text/plain")},
    )
    analysis_id = response.json()["analysis_id"]

    def fake_ai(result, records):
        return {
            "risk_level": "high",
            "confidence": 0.9,
            "conclusion": "AI 结合工具结果给出高风险结论。",
            "recommendations": ["核对来源 IP 归属。"],
            "behaviors": [],
            "tool_trace": [
                {
                    "tool": "query_events",
                    "arguments": {"risk_level": "high"},
                    "summary": "共 1 个事件",
                }
            ],
            "unsupported_claims": ["结论 引用了日志中不存在的 IP：8.8.8.8"],
        }

    monkeypatch.setattr("app.main.request_ai_judgement", fake_ai)
    body = client.post(f"/api/analysis/{analysis_id}/ai").json()
    assert body["ai_tool_trace"][0]["tool"] == "query_events"
    assert body["ai_unsupported_claims"] == ["结论 引用了日志中不存在的 IP：8.8.8.8"]
    assert client.get(f"/api/analysis/{analysis_id}").json()["ai_tool_trace"]


def test_ai_ledger_is_persisted_and_exportable(monkeypatch):
    response = client.post(
        "/api/logs/upload",
        files={"file": ("ai-ledger.log", make_ssh_log(), "text/plain")},
    )
    analysis_id = response.json()["analysis_id"]

    def fake_ai(result, records):
        return {
            "risk_level": "high",
            "confidence": 0.9,
            "conclusion": "AI 结合证据给出高风险结论。",
            "recommendations": [],
            "behaviors": [
                AiBehavior(
                    type="ssh_bruteforce_success",
                    name="疑似 SSH 暴力破解后成功登录",
                    confidence=0.9,
                    evidence=["失败后成功"],
                    evidence_ids=["record-1"],
                    analysis="失败认证后出现成功登录。",
                )
            ],
            "tool_trace": [
                {
                    "tool": "query_events",
                    "arguments": {"risk_level": "high"},
                    "summary": "共 1 个事件",
                    "source": "model",
                },
                {
                    "tool": "usage",
                    "source": "auto",
                    "summary": "",
                    "usage": {"prompt_tokens": 100, "completion_tokens": 20},
                },
            ],
            "unsupported_claims": ["结论 引用了日志中不存在的 IP：8.8.8.8"],
        }

    monkeypatch.setattr("app.main.request_ai_judgement", fake_ai)
    assert client.post(f"/api/analysis/{analysis_id}/ai").status_code == 200

    ledger = client.get(f"/api/analysis/{analysis_id}/ai/ledger").json()
    assert ledger["analysis_id"] == analysis_id
    assert ledger["status"] == "completed"
    assert ledger["evidence_ids"] == ["record-1"]
    assert ledger["usage"]["prompt_tokens"] == 100
    assert ledger["unsupported_claims"] == ["结论 引用了日志中不存在的 IP：8.8.8.8"]

    for fmt, marker in (("json", b"analysis_id"), ("html", "AI 研判审查台账".encode()), ("csv", b"tool")):
        exported = client.get(f"/api/analysis/{analysis_id}/ai/ledger/export?format={fmt}")
        assert exported.status_code == 200
        assert marker in exported.content


def test_rule_preview_runs_draft_without_writing_rule_file():
    draft = {
        "id": "preview.admin_path",
        "title": "预览规则",
        "description": "仅用于试运行",
        "level": "medium",
        "detection": {
            "where": [
                {"field": "url", "op": "contains", "value": "/admin"},
            ]
        },
        "event": {
            "type": "preview_admin_path",
            "name": "预览命中",
            "summary": "命中预览规则",
        },
    }
    log = '198.51.100.7 - - [12/Sep/2026:06:00:00 +0800] "GET /admin HTTP/1.1" 200 1 "-" "ua"\n'
    response = client.post(
        "/api/rules/preview",
        json={
            "rule": draft,
            "sample_log": log,
            "expected_rule_ids": ["preview.admin_path"],
        },
    )
    body = response.json()
    assert body["valid"] is True
    assert body["rule_ids"] == ["preview.admin_path"]
    assert body["event_count"] == 1
    assert body["true_positive"] == 1
    assert body["false_positive"] == 0
    assert body["false_negative"] == 0
    assert body["rollback_required"] is False
    assert all(item["id"] != "preview.admin_path" for item in client.get("/api/rules").json())


def test_rule_enable_override_is_audited():
    before = {item["id"]: item for item in client.get("/api/rules").json()}
    assert before["web.404_scan"]["enabled"] is True

    disabled = client.patch("/api/rules/web.404_scan/enabled?enabled=false")
    assert disabled.status_code == 200
    after_disable = {item["id"]: item for item in client.get("/api/rules").json()}
    assert after_disable["web.404_scan"]["enabled"] is False

    enabled = client.patch("/api/rules/web.404_scan/enabled?enabled=true")
    assert enabled.status_code == 200
    after_enable = {item["id"]: item for item in client.get("/api/rules").json()}
    assert after_enable["web.404_scan"]["enabled"] is True

    audit = client.get("/api/rules/audit").json()
    assert audit[0]["rule_id"] == "web.404_scan"
    assert audit[0]["action"] == "enable"
    assert any(item["action"] == "disable" for item in audit)


def test_rule_change_can_be_rolled_back_and_rollback_is_audited():
    """回滚把规则还原到「变更前」，并且回滚本身也进审计链（只增不改）。"""

    client.patch("/api/rules/web.404_scan/enabled?enabled=false")
    disable_entry = next(
        item
        for item in client.get("/api/rules/audit").json()
        if item["action"] == "disable" and item["rule_id"] == "web.404_scan"
    )

    rolled = client.post(f"/api/rules/audit/{disable_entry['id']}/rollback")
    assert rolled.status_code == 200
    rules = {item["id"]: item for item in client.get("/api/rules").json()}
    assert rules["web.404_scan"]["enabled"] is True

    audit = client.get("/api/rules/audit").json()
    assert audit[0]["action"] == "rollback"
    assert audit[0]["rule_id"] == "web.404_scan"
    assert audit[0]["before"] == "False"
    assert audit[0]["after"] == "True"
    # 被回滚的那条记录仍在链上，没有被改写
    assert any(item["id"] == disable_entry["id"] for item in audit)


def test_rollback_rejects_unknown_audit_entry():
    assert client.post("/api/rules/audit/999999/rollback").status_code == 404


def test_validate_response_accepts_provider_schema_drift():
    from app.services.ai import _validate_response

    payload = {
        "behaviors": [
            {
                "behavior_id": "privileged_login_success",
                "title": "高权限账户 root 成功登录",
                "description": "来源 IP 10.0.0.8 在 01:02:00 以 root 成功登录。",
                "severity": "medium",
                "confidence": 0.68,
                "evidence_ids": ["record-3", "evidence-not-exist"],
            }
        ],
        "risk_assessment": {
            "risk_level": "medium",
            "confidence": 0.68,
            "rationale": "存在一次高权限账户成功登录，但证据不足以判定为恶意。",
        },
        "recommendations": ["核实该登录是否符合预期运维窗口。"],
    }
    judgement = _validate_response(
        payload, {"evidence-privileged_login-1"}, {"record-3": "evidence-privileged_login-1"}
    )
    assert judgement["risk_level"] == "medium"
    assert judgement["confidence"] == 0.68
    assert judgement["conclusion"].startswith("存在一次高权限账户")
    behavior = judgement["behaviors"][0]
    assert behavior.type == "privileged_login_success"
    assert behavior.name == "高权限账户 root 成功登录"
    assert behavior.analysis.startswith("来源 IP 10.0.0.8")
    assert behavior.evidence_ids == ["evidence-privileged_login-1"]


def test_ai_judgement_keeps_real_model_output(monkeypatch):
    from app.services import ai as ai_service

    class StubProvider:
        supports_tools = False

        def complete(self, system_prompt, context, on_delta=None):
            return json.dumps(
                {
                    "behaviors": [
                        {
                            "behavior_id": "privileged_login_success",
                            "title": "高权限账户 root 成功登录",
                            "description": "来源 10.0.0.8 成功以 root 登录。",
                            "confidence": 0.7,
                            "evidence_ids": ["record-3"],
                        }
                    ],
                    "risk_assessment": {
                        "risk_level": "medium",
                        "confidence": 0.7,
                        "rationale": "需要核实该登录是否被授权。",
                    },
                    "recommendations": ["核对账号责任人与登录来源。"],
                }
            )

    monkeypatch.setattr(ai_service, "_create_provider", lambda: StubProvider())
    result = analyze_log("auth.log", make_ssh_log())
    judgement = ai_service.request_ai_judgement(result, [])
    assert judgement["risk_level"] == "medium"
    assert judgement["behaviors"][0].name == "高权限账户 root 成功登录"
    assert judgement["behaviors"][0].evidence_ids
    assert judgement["behaviors"][0].evidence_ids[0].startswith("evidence-")
    assert judgement["conclusion"] == "需要核实该登录是否被授权。"
    assert judgement["unsupported_claims"] == []


def test_grounding_accepts_ips_present_in_unflagged_records(monkeypatch):
    from app.services import ai as ai_service

    class StubProvider:
        supports_tools = False

        def complete(self, system_prompt, context, on_delta=None):
            return json.dumps(
                {
                    "risk_level": "medium",
                    "confidence": 0.6,
                    "summary": "203.0.113.21 的访问未被规则命中，但仍出现在日志中。",
                    "behaviors": [],
                    "recommendations": [],
                }
            )

    monkeypatch.setattr(ai_service, "_create_provider", lambda: StubProvider())
    records = [
        {
            "record_id": "record-1",
            "source_ip": "203.0.113.21",
            "destination_ip": "10.0.0.5",
            "timestamp": "2026-09-17 09:00:03",
            "timestamp_iso": "2026-09-17T09:00:03",
            "url": "/download",
        }
    ]
    result = analyze_log("auth.log", make_ssh_log())
    judgement = ai_service.request_ai_judgement(result, records)
    assert not any("203.0.113.21" in item for item in judgement["unsupported_claims"])

    records[0]["source_ip"] = "10.0.0.99"
    judgement = ai_service.request_ai_judgement(result, records)
    assert any("203.0.113.21" in item for item in judgement["unsupported_claims"])


def test_insights_endpoint_returns_timeseries_and_attack_chain():
    response = client.post(
        "/api/logs/upload",
        files={"file": ("insights.log", make_ssh_log(), "text/plain")},
    )
    analysis_id = response.json()["analysis_id"]

    insights = client.get(f"/api/analysis/{analysis_id}/insights")
    assert insights.status_code == 200
    body = insights.json()

    # 时间序列：SSH 日志有时间戳，应产生至少 1 个桶，且计数>0
    assert len(body["timeseries"]) >= 1
    assert sum(bucket["count"] for bucket in body["timeseries"]) >= 1
    assert any(bucket["failed_login"] > 0 for bucket in body["timeseries"])

    # 攻击链：失败认证后成功登录 → 初始访问，且 root 特权登录 → 权限提升
    assert len(body["attack_chains"]) >= 1
    chain = body["attack_chains"][0]
    tactics = {stage["tactic"] for stage in chain["stages"]}
    assert "初始访问" in tactics
    assert "权限提升" in tactics
    order = [stage["tactic"] for stage in chain["stages"]]
    assert order.index("初始访问") < order.index("权限提升")


def test_insights_attack_chain_maps_bruteforce_to_credential_access():
    response = client.post(
        "/api/logs/upload",
        files={"file": ("insights-bf.log", make_ssh_log(success=False), "text/plain")},
    )
    analysis_id = response.json()["analysis_id"]
    body = client.get(f"/api/analysis/{analysis_id}/insights").json()
    assert len(body["attack_chains"]) >= 1
    tactics = {stage["tactic"] for chain in body["attack_chains"] for stage in chain["stages"]}
    assert "凭据访问" in tactics


def test_insights_unknown_analysis_returns_404():
    assert client.get("/api/analysis/nope/insights").status_code == 404


def test_database_log_detection_and_field_mapping():
    from app.services.parser import parse_log

    cases = {
        "mysql": (
            "2026-09-17T10:00:00.000000Z\t1 Connect\troot@10.0.0.8 on appdb\n"
            "2026-09-17T10:00:01.000000Z\t1 Query\tSELECT * FROM users WHERE id = 1\n",
            ("10.0.0.8", "root", "login"),
        ),
        "postgresql": (
            "2026-09-17 10:00:00.123 CST [12345] LOG:  connection authorized: user=postgres database=appdb\n"
            "2026-09-17 10:00:01.123 CST [12345] [54321] FATAL:  password authentication failed for user \"postgres\"\n",
            (None, "postgres", "login"),
        ),
        "mongodb": (
            '{"t":{"$date":"2026-09-17T02:00:00.000+00:00"},"s":"I","c":"ACCESS","id":20249,"ctx":"conn1","msg":"Authentication failed","attr":{"user":"admin","db":"admin","remote":"10.0.0.8:5001"}}\n',
            ("10.0.0.8", "admin", "login"),
        ),
        "redis": (
            "1234:M 17 Sep 2026 10:00:00.123 # Invalid password for user 'default'\n",
            (None, "default", "login"),
        ),
        "sqlserver": (
            "2026-09-17 10:00:00.00 Logon       Login failed for user 'sa'. Reason: Password did not match. [CLIENT: 10.0.0.8]\n",
            ("10.0.0.8", "sa", "login"),
        ),
        "oracle": (
            "Thu Sep 17 10:00:00 2026\nORA-01017: invalid username/password; logon denied\n",
            (None, None, "login"),
        ),
    }

    for expected_type, (text, (ip, user, action)) in cases.items():
        parsed = parse_log(text)
        assert parsed.log_type == expected_type, (expected_type, parsed.log_type)
        assert parsed.parsed_lines >= 1
        record = parsed.records[0]
        assert record["source_ip"] == ip, (expected_type, record["source_ip"])
        assert record["username"] == user, (expected_type, record["username"])
        assert record["action"] == action, (expected_type, record["action"])


def test_database_query_records_put_sql_into_url():
    from app.services.parser import parse_log

    text = "2026-09-17T10:00:01.000000Z\t1 Query\tSELECT * FROM users WHERE id = 1\n"
    parsed = parse_log(text)
    record = parsed.records[0]
    assert record["action"] == "query"
    assert record["url"] == "SELECT * FROM users WHERE id = 1"


def test_ai_structured_verdict_normalizes_and_grounds(monkeypatch):
    from app.services import ai as ai_service

    # 归一化：顶层直接给字段，也兼容 structured/verdict 子对象
    verdict = ai_service._build_structured_verdict(
        {
            "summary": "x",
            "structured": {
                "event_time": "2026-09-17 10:00",
                "attack_source_ip": "203.0.113.7",
                "target_asset": "db-01",
                "involved_account": "root",
                "abnormal_behavior": "暴力破解后成功登录",
                "related_logs": ["auth.log"],
                "attack_type": "SSH 暴力破解",
                "risk_level": "high",
                "judgment_basis": "20 次失败 + 1 次成功",
                "success_indicator": "是",
                "recommended_actions": ["封禁来源 IP"],
            },
        }
    )
    assert verdict is not None
    assert verdict.attack_source_ip == "203.0.113.7"
    assert verdict.involved_account == "root"
    assert verdict.risk_level == "high"
    assert verdict.success_indicator == "是"
    assert verdict.recommended_actions == ["封禁来源 IP"]
    # 全部缺失 → None
    assert ai_service._build_structured_verdict({"summary": "x"}) is None

    # 落地：AI 返回结构化研判后写入 AnalysisResult
    response = client.post(
        "/api/logs/upload",
        files={"file": ("sv.log", make_ssh_log(), "text/plain")},
    )
    analysis_id = response.json()["analysis_id"]

    def fake_ai(result, records):
        return {
            "risk_level": "high",
            "confidence": 0.9,
            "conclusion": "疑似 SSH 暴力破解后成功登录。",
            "recommendations": ["封禁来源 IP"],
            "behaviors": [],
            "structured_verdict": StructuredVerdict(
                event_time="2026-09-12 01:00",
                attack_source_ip="10.0.0.8",
                involved_account="root",
                abnormal_behavior="短时间内大量认证失败后成功登录",
                attack_type="SSH 暴力破解",
                risk_level="high",
                judgment_basis="20 次失败后 1 次成功",
                success_indicator="是",
                recommended_actions=["封禁来源 IP"],
            ),
        }

    monkeypatch.setattr("app.main.request_ai_judgement", fake_ai)
    body = client.post(f"/api/analysis/{analysis_id}/ai").json()
    verdict = body["structured_verdict"]
    assert verdict is not None
    assert verdict["attack_source_ip"] == "10.0.0.8"
    assert verdict["attack_type"] == "SSH 暴力破解"
    assert verdict["success_indicator"] == "是"


def test_grounding_accepts_target_host_referenced_by_ip():
    """目标主机的 IP 常直接写在资产字段里，引用它不算编造 IP。

    域控导出就是这种情况（资产 = 10.0.0.11），此前会被判成「引用了日志中不存在的 IP」——
    对正确结论的误报。
    """

    from app.services.ai import _check_grounding
    from app.services.analyzer import analyze_log

    result = analyze_log(
        "a.log",
        '203.0.113.7 - - [21/Sep/2026:09:10:00 +0800] "GET /.env HTTP/1.1" 403 1 "-" "curl/8.0"',
    )
    records = [
        {
            "target_asset": "10.0.0.11",
            "record_id": "record-1",
            "evidence_id": "evidence-record-1",
        }
    ]
    assert _check_grounding(
        {"conclusion": "目标主机 10.0.0.11 存在异常登录", "behaviors": []}, result, records
    ) == []
    assert _check_grounding(
        {"conclusion": "来源 8.8.8.8 存在异常登录", "behaviors": []}, result, records
    ) == ["结论 引用了日志中不存在的 IP：8.8.8.8"]


def test_grounding_accepts_targets_that_only_appear_in_raw_text():
    """目标/来源只写在日志原文里时不算编造。

    access.log 的组合日志把站点写在 Referer（`"http://192.168.200.51/"`），
    auth.log 的 sshd 主机名（`ip-10-0-10-4`）都没被提成结构化字段，只在 `raw` 里。
    此前两者都被报成「引用了日志中不存在的主机/IP」——对正确结论的误报。
    """

    from app.models import StructuredVerdict
    from app.services.ai import _check_grounding
    from app.services.analyzer import analyze_log

    web_log = (
        '192.168.200.2 - - [03/Aug/2023:08:24:29 +0000] '
        '"GET /images/style.css HTTP/1.1" 200 1906 "http://192.168.200.51/" "Mozilla/5.0"'
    )
    web_result = analyze_log("access.log", web_log)
    web_records = [{"record_id": "record-1", "evidence_id": "evidence-record-1", "raw": web_log}]
    judgement = {
        "conclusion": "站点 192.168.200.51 被探测，来源 192.168.200.2。",
        "behaviors": [],
        "structured_verdict": StructuredVerdict(
            target_asset="192.168.200.51（由 Referer 推断）",
            attack_source_ip="192.168.200.2",
        ),
    }
    assert _check_grounding(judgement, web_result, web_records) == []

    ssh_log = (
        "Sep 22 01:36:48 ip-10-0-10-4 sshd[818]: "
        "Accepted password for root from 117.10.133.145 port 60753 ssh2"
    )
    ssh_result = analyze_log("auth.log", ssh_log)
    ssh_records = [{"record_id": "record-1", "evidence_id": "evidence-record-1", "raw": ssh_log}]
    assert _check_grounding(
        {
            "conclusion": "主机 ip-10-0-10-4 出现高权限登录。",
            "behaviors": [],
            "structured_verdict": StructuredVerdict(target_asset="ip-10-0-10-4"),
        },
        ssh_result,
        ssh_records,
    ) == []

    # 原文兜底不能把检查放空：差一个字符的主机名仍要判为不存在。
    assert _check_grounding(
        {
            "conclusion": "主机 ip-10-0-10-40 出现高权限登录。",
            "behaviors": [],
            "structured_verdict": StructuredVerdict(target_asset="ip-10-0-10-40"),
        },
        ssh_result,
        ssh_records,
    ) == ["目标资产 引用了日志中不存在的主机：ip-10-0-10-40"]
