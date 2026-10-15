"""检测覆盖度与结论措辞。

产品底线：**没有判据时不能说「没发现问题」**。
本文件锁定三类结论与对应的覆盖度统计，以及攻击链级场景语料的完整性。
"""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app
from app.services.analyzer import analyze_log, analyze_parsed_logs
from app.services.parser import ParsedLog
from app.services.rule_quality import evaluate, load_corpus

client = TestClient(app)

SCENARIO_FAMILY = "攻击链场景"
SCENARIO_DIR = Path(__file__).resolve().parents[1] / "evaluation" / "scenarios"


def _scenario_log(name: str) -> str:
    return (SCENARIO_DIR / name).read_text(encoding="utf-8", errors="replace")

SYSMON_CHAIN_RULES = {
    "windows.lolbin_download",
    "windows.masquerade_extension",
    "windows.credential_file_access",
    "windows.suspicious_executable_in_temp",
    "windows.archive_with_password",
    "windows.payload_cleanup",
    "windows.registry_certificate_store",
    "windows.suspicious_dns_query",
    "windows.discovery_command",
    "windows.payload_outbound_connection",
    "windows.registry_bulk_write",
}


def _empty_event(name: str, payload: str):
    response = client.post(
        "/api/logs/upload",
        files={"file": (name, payload, "text/plain")},
    )
    assert response.status_code == 200, response.text
    return response.json()["result"]


def test_covered_log_without_events_reports_no_anomaly():
    """有判据、规则跑过、无命中 → 才允许输出「未发现异常」。"""

    normal = (
        '203.0.113.40 - - [12/Sep/2026:06:00:00 +0800] "GET /index.html HTTP/1.1" 200 5120 "-" "Mozilla/5.0"\n'
        '203.0.113.40 - - [12/Sep/2026:06:00:01 +0800] "GET /static/app.js HTTP/1.1" 200 20480 "-" "Mozilla/5.0"\n'
    )
    result = analyze_log("normal.log", normal)
    assert not result.events
    assert result.coverage.limitation is None
    assert result.coverage.total_records == 2
    assert result.coverage.evaluable_records == 2
    assert result.coverage.covered_records == 0
    assert result.confidence == 0.35
    assert "没有发现" in result.conclusion
    assert "无法" not in result.conclusion


def test_records_without_judging_fields_cannot_be_evaluated():
    """记录里只有原文、没有行为字段时，结论必须是「无法确认」。"""

    parsed = ParsedLog(
        log_type="generic",
        confidence=0.35,
        total_lines=2,
        parsed_lines=2,
        records=[{"raw": "op=rotate target=kv-7"}, {"raw": "op=rotate target=kv-8"}],
    )
    result = analyze_parsed_logs(["vendor.log"], [parsed])
    assert not result.events
    assert result.coverage.total_records == 2
    assert result.coverage.evaluable_records == 0
    assert result.coverage.covered_records == 0
    assert result.coverage.limitation is not None
    assert "不含可用于判定的行为字段" in result.coverage.limitation
    assert "无法确认" in result.conclusion
    assert result.confidence == 0.2
    assert "已排查无问题" in result.summary


def test_unparsable_lines_are_counted_and_downgrade_conclusion():
    """无法识别的文本行要被计数，不能静默变成「没有异常」。"""

    result = analyze_log("vendor.log", "@@@ a=1\n@@@ a=2\n")
    assert not result.events
    assert result.coverage.total_records == 0
    assert result.coverage.parse_failures == 2
    # 文本日志没有保留上限，未纳入的记录全部计入解析失败
    assert result.coverage.parse_errors == 2
    assert result.coverage.retention_drops == 0
    assert len(result.coverage.parse_error_details) == 2
    assert result.coverage.parse_error_details[0]["source_file"] == "vendor.log"
    assert result.coverage.parse_error_details[0]["line_number"] == 1
    assert "@@@ a=1" in result.coverage.parse_error_details[0]["raw_preview"]
    assert result.coverage.limitation is not None
    assert "未纳入检测" in result.coverage.limitation
    assert "无法确认" in result.conclusion


def test_evtx_unparsable_event_is_counted_not_silently_dropped():
    """EVTX 中无法映射的事件必须计数；可修复的裸 & 仍应被解析出来。"""

    header = (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
        '<Provider Name="Microsoft-Windows-Sysmon"/><EventID>1</EventID>'
        '<TimeCreated SystemTime="2025-08-05T09:01:16.4092700Z"/><Computer>WK001</Computer></System>'
        '<EventData>'
    )
    repairable = (
        header
        + '<Data Name="Image">C:\\Windows\\System32\\cmd.exe</Data>'
        + '<Data Name="CommandLine">cmd /c "echo a" &amp; whoami</Data></EventData></Event>\n'
    )
    broken = (
        header
        + '<Data Name="Image">C:\\Windows\\System32\\cmd.exe</Data>'
        + '<Data Name="CommandLine">cmd /c "echo a<b" & exit</Data></EventData></Event>\n'
    )
    result = analyze_log("Sysmon.xml", repairable + broken)
    assert result.coverage.total_records == 1
    assert result.coverage.parse_failures == 1
    assert result.coverage.parse_errors == 1
    assert result.coverage.retention_drops == 0
    assert result.coverage.evaluable_records == 1
    assert len(result.coverage.parse_error_details) == 1
    assert result.coverage.parse_error_details[0]["line_number"] == 2
    assert "XML" in result.coverage.parse_error_details[0]["reason"]


def test_coverage_is_exposed_by_upload_api():
    body = _empty_event("vendor.log", "@@@ a=1\n")
    coverage = body["coverage"]
    assert coverage["parse_failures"] == 1
    assert coverage["parse_errors"] == 1
    assert coverage["retention_drops"] == 0
    assert coverage["limitation"]
    assert coverage["total_records"] == 0
    assert "无法确认" in body["conclusion"]
    # 报告导出同样要带上覆盖度与不足说明（HTML 报告，不是默认的 JSON）
    report = client.get(f"/api/analysis/{body['id']}/report?format=html")
    assert report.status_code == 200
    assert "检测覆盖：0/0 条记录命中规则" in report.text
    assert "检测覆盖不足" in report.text
    assert "检测覆盖不完整" in report.text
    # 报告里未纳入检测的记录要显示拆分数字，总数仍保留
    assert "未纳入检测 1 条（解析失败 1 条）" in report.text
    assert "解析失败详情" in report.text


def test_html_report_includes_coverage_for_analyzed_log():
    """有事件的分析报告也要展示检测覆盖度。"""

    result = _empty_event("normal.log", '203.0.113.40 - - [12/Sep/2026:06:00:00 +0800] "GET /a HTTP/1.1" 200 1 "-" "Mozilla/5.0"\n')
    report = client.get(f"/api/analysis/{result['id']}/report?format=html")
    assert report.status_code == 200
    assert "检测覆盖：0/1 条记录命中规则" in report.text
    assert "检测覆盖不足" not in report.text
    assert "未发现" in report.text


def test_scenario_corpus_locks_the_full_attack_chain():
    """整份真实日志的场景用例：链上任一环节漏检都必须让门禁变红。"""

    cases = {
        case["name"]: case
        for case in load_corpus()
        if case["family"].startswith(SCENARIO_FAMILY)
    }
    assert set(cases) == {
        "scenario-sysmon-intrusion-chain",
        "scenario-nginx-sensitive-file-probe",
    }
    assert {item["rule"] for item in cases["scenario-sysmon-intrusion-chain"]["expect"]} == (
        SYSMON_CHAIN_RULES
    )
    assert {item["rule"] for item in cases["scenario-nginx-sensitive-file-probe"]["expect"]} == {
        "web.path_traversal",
        "web.sensitive_file_access.success",
        "web.sensitive_interface",
    }

    report = evaluate()
    scenario_results = [case for case in report.cases if case.name in cases]
    assert len(scenario_results) == len(cases)
    for case in scenario_results:
        assert case.ok, f"{case.name} 场景链未全部命中：{case.details}"


def test_scenario_logs_produce_expected_coverage_numbers():
    """场景日志的覆盖度统计稳定，便于核对「还有多少记录没有规则覆盖」。"""

    result = analyze_log(
        "sysmon-intrusion-chain.log", _scenario_log("sysmon-intrusion-chain.log")
    )
    assert len(result.events) == 13
    assert result.coverage.total_records == 42
    assert result.coverage.evaluable_records == 42
    assert result.coverage.parse_failures == 0
    assert result.coverage.covered_records == 34
    assert result.coverage.limitation is None


def test_syslog_prefix_is_stripped_and_inner_web_line_parsed():
    """syslog / 容器日志前缀要剥掉，内层访问日志按 Web 解析，时间戳取自前缀。"""

    from app.services.parser import parse_log

    log = "\n".join(
        [
            '2026-09-21T08:15:03+08:00 WARN  app01 nginx[2148]: 203.0.113.88 - - "GET /.env HTTP/1.1" 403 421 "-" "security-test-client/1.0"',
            '2026-09-21T08:15:04+08:00 INFO  app01 nginx[2148]: 203.0.113.88 - - "GET /products HTTP/1.1" 200 9127 "-" "Mozilla/5.0"',
        ]
    )
    parsed = parse_log(log)
    assert parsed.log_type == "syslog"
    assert parsed.parse_failures == 0
    assert len(parsed.records) == 2
    first = parsed.records[0]
    assert first["source_ip"] == "203.0.113.88"
    assert first["url"] == "/.env"
    assert first["status"] == "403"
    assert first["target_asset"] == "app01"
    # 时间戳来自外层前缀，不能丢
    assert first["timestamp"] == "2026-09-21T08:15:03+08:00"
    assert first["timestamp_iso"] is not None


def test_web_line_without_inline_timestamp_is_parsed():
    """访问日志行没有 `[时间]` 字段时（时间由外层提供）同样要能解析。"""

    from app.services.parser import _parse_web_line, parse_log

    line = '203.0.113.88 - - "GET /admin HTTP/1.1" 403 421 "-" "curl/8.0"'
    record = _parse_web_line(line, "2026-09-21T08:15:03+08:00", "2026-09-21T08:15:03+08:00")
    assert record is not None
    assert record["url"] == "/admin"
    assert record["status"] == "403"
    # 单独一份无时间戳的访问日志也应被识别成 Web 日志，而不是 generic
    assert parse_log(line).log_type == "nginx_apache"


def test_syslog_app_security_signals_are_detected():
    """应用自身记录的安全信号要能被检出，而不是只留一条原始记录。"""

    from pathlib import Path as _Path

    log = (
        _Path(__file__).resolve().parents[1]
        / "evaluation"
        / "scenarios"
        / "syslog-app-security.log"
    ).read_text(encoding="utf-8", errors="replace")
    result = analyze_log("syslog-app-security.log", log)
    assert result.metadata.log_type == "syslog"
    assert result.coverage.total_records == 276
    assert result.coverage.parse_failures == 0
    detected = {event.rule_id for event in result.events}
    assert {
        "web.sensitive_path",
        "web.sensitive_interface",
        "app.sensitive_path_probe",
        "app.auth_threshold_block",
        "app.restricted_resource_access",
    } <= detected
    assert result.risk_level == "medium"


def test_syslog_line_without_prefix_is_counted_not_silently_dropped():
    """剥壳日志里混入的不合规行必须计入解析失败并给出原因。"""

    from app.services.parser import parse_log

    log = "\n".join(
        [
            '2026-09-21T08:15:03+08:00 WARN  app01 nginx[2148]: 203.0.113.88 - - "GET / HTTP/1.1" 200 1 "-" "ua"',
            "这一行没有 syslog 前缀，应该被计为解析失败",
            '2026-09-21T08:15:04+08:00 WARN  app01 nginx[2148]: 203.0.113.88 - - "GET /a HTTP/1.1" 200 1 "-" "ua"',
            '2026-09-21T08:15:05+08:00 WARN  app01 nginx[2148]: 203.0.113.88 - - "GET /b HTTP/1.1" 200 1 "-" "ua"',
        ]
    )
    parsed = parse_log(log)
    assert parsed.log_type == "syslog"
    assert parsed.parse_failures == 1
    assert parsed.parse_error_details[0]["line_number"] == 2
    assert "syslog 前缀" in str(parsed.parse_error_details[0]["reason"])


def test_windows_event_kv_log_is_parsed_and_attack_detected():
    """Windows 事件日志的键值化导出要能解析，并把凭据攻击链检出来。"""

    log = _scenario_log("windows-event-kv.log")
    result = analyze_log("windows-event-kv.log", log)
    assert result.metadata.log_type == "windows_event"
    assert result.coverage.total_records == 306
    # 文件尾部有一条被截断的行，必须如实计入解析失败而不是静默丢弃，
    # 而且要说清是「文件不完整」而不是「格式不支持」——用户据此判断该修哪一头
    assert result.coverage.parse_failures == 1
    assert "疑似被截断" in str(result.coverage.parse_error_details[0]["reason"])
    # 行为字段（Process= / ServiceFile= / Service=）必须被映射出来，否则大批记录会被
    # 误判成「不含可用于判定的行为字段」，把解析缺陷伪装成检测能力不足
    assert result.coverage.evaluable_records == 306
    detected = {event.rule_id for event in result.events}
    assert {"windows.account_lockout", "windows.service_install"} <= detected
    # 这份日志里的关键防护服务都处于 Running，防御规避规则不得开火
    assert "windows.protection_service_stopped" not in detected
    assert result.risk_level == "medium"


def test_windows_event_kv_only_maps_result_for_auth_events():
    """非认证事件的 Result/Status 不能混进「认证失败 / 成功」统计。"""

    from app.services.parser import parse_log

    log = "\n".join(
        [
            r'2026-09-21T08:00:22+08:00 INFO  WIN-SRV-01 System EventID=7045 ServiceName="BackupAgent" ServiceFile="C:\Program Files\BackupAgent\agent.exe" StartupType="Auto"',
            '2026-09-21T08:00:28+08:00 INFO  WIN-SRV-01 Application EventID=1000 Process="BackupAgent.exe" PID=4216 Action="ScheduledBackup" Result="Success"',
            '2026-09-21T08:20:17+08:00 WARN  WIN-SRV-01 Security EventID=4625 LogonType=10 Account="Administrator" SourceAddress="198.51.100.77" Status="0xC000006D"',
            '2026-09-21T08:00:13+08:00 INFO  WIN-SRV-01 Security EventID=4624 LogonType=2 Account="j.chen" SourceAddress="192.0.2.42" Status="Success"',
        ]
    )
    parsed = parse_log(log)
    assert parsed.log_type == "windows_event"
    assert parsed.parse_failures == 0
    by_event = {record["event_id"]: record for record in parsed.records}

    service = by_event["7045"]
    assert service["result"] is None and service["action"] == "event"
    application = by_event["1000"]
    assert application["result"] is None and application["action"] == "event"
    failure = by_event["4625"]
    assert failure["result"] == "failure"
    assert failure["action"] == "rdp_logon"
    assert failure["source_ip"] == "198.51.100.77"
    assert failure["target_asset"] == "WIN-SRV-01"
    success = by_event["4624"]
    assert success["result"] == "success"
    assert success["action"] == "logon"


def test_windows_event_kv_maps_process_and_service_file_fields():
    """键值导出里的 Process / PID / ServiceFile / Service 必须映射成行为字段。

    否则「可判定记录」占比被严重低估，结论会降级成「检测覆盖不足」——
    那是解析缺陷，不是检测能力不足，两者不能混为一谈。
    """

    from app.services.analyzer import _is_evaluable
    from app.services.parser import parse_log

    log = "\n".join(
        [
            '2026-09-21T08:00:04+08:00 INFO  WIN-SRV-01 System EventID=7036 Service="Windows Event Log" State="Running"',
            '2026-09-21T08:00:28+08:00 INFO  WIN-SRV-01 Application EventID=1000 Process="BackupAgent.exe" PID=4216 Action="ScheduledBackup" Result="Success"',
            r'2026-09-21T08:00:22+08:00 INFO  WIN-SRV-01 System EventID=7045 ServiceName="BackupAgent" ServiceFile="C:\Program Files\BackupAgent\agent.exe" StartupType="Auto"',
        ]
    )
    parsed = parse_log(log)
    assert parsed.parse_failures == 0
    by_event = {record["event_id"]: record for record in parsed.records}

    application = by_event["1000"]
    assert application["process_image"] == "BackupAgent.exe"
    assert application["process_id"] == "4216"
    assert _is_evaluable(application) is True

    service = by_event["7045"]
    assert service["target_filename"] == r"C:\Program Files\BackupAgent\agent.exe"
    assert _is_evaluable(service) is True

    # 服务状态事件：此前没有任何规则消费它的字段，故当时保持「不可判定」；
    # 自 windows.protection_service_stopped 起 Service / State 成为判据，随之改为可判定
    state_change = by_event["7036"]
    assert state_change["service_name"] == "Windows Event Log"
    assert state_change["service_state"] == "Running"
    assert _is_evaluable(state_change) is True


def test_protection_service_stopped_rule_boundaries():
    """「关键防护服务被停止」的判据边界：只认防护类服务 + Stopped。

    两类都不能报：同一个服务处于 Running；非防护服务被停止（Windows Search、
    Print Spooler 这类在企业里被停属运维常态）。判据放太宽会把日常运维当攻击。
    """

    from app.services.detector import detect_events_with_coverage
    from app.services.parser import parse_log

    def hits(line: str) -> set[str]:
        parsed = parse_log(line)
        records = [
            {**record, "log_type": parsed.log_type, "record_id": f"record-{index}"}
            for index, record in enumerate(parsed.records, start=1)
        ]
        events, _ = detect_events_with_coverage(records)
        return {event.rule_id for event in events}

    def state_line(service: str, state: str) -> str:
        return (
            f'2026-09-21T09:10:02+08:00 INFO  WIN-DC-02 Security EventID=7036 '
            f'Service="{service}" State="{state}"'
        )

    guard_services = [
        "Windows Defender Antivirus Service",
        "Windows Defender Firewall",
        "Microsoft Defender Antivirus Network Inspection Service",
        "Windows Security Service",
        "Security Center",
        "Windows Event Log",
        "Sysmon64",
        "Windows Defender 防火墙",
        "安全中心",
        "Windows 事件日志",
    ]
    for service in guard_services:
        assert "windows.protection_service_stopped" in hits(state_line(service, "Stopped")), service

    benign_lines = [
        state_line("Windows Defender Antivirus Service", "Running"),
        state_line("Windows Search", "Stopped"),
        state_line("Print Spooler", "Stopped"),
        state_line("Windows Update", "Stopped"),
        state_line("BackupAgent", "Stopped"),
        state_line("Windows Time", "Stopped"),
    ]
    for line in benign_lines:
        assert "windows.protection_service_stopped" not in hits(line), line
