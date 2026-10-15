"""EVTX 标准字段解析：`<System>` 事件头与 `<EventData>` 全部 `<Data Name="…">`。

这组测试守的是「按标准 EVTX 格式把事件数据真正解析出来」这条线：
Sigma 的 Windows 规则用的就是日志里的标准字段名，解析器必须原样把它们落进记录，
否则规则要么被整条跳过、要么落成永远不命中的判据。
"""

from __future__ import annotations

from app.services.evtx import event_to_record
from app.services.rules_engine import build_rule, evaluate_rule
from app.services.sigma_import import convert_rule


def make_event(system: str = "", event_data: str = "", event_id: str = "1") -> str:
    return (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        "<System>"
        '<Provider Name="Microsoft-Windows-Sysmon"/>'
        f"<EventID>{event_id}</EventID>"
        '<TimeCreated SystemTime="2026-01-01T00:00:00.000000Z"/>'
        f"{system}"
        "</System>"
        f"<EventData>{event_data}</EventData>"
        "</Event>"
    )


def test_event_data_fields_keep_their_standard_names():
    record, _ = event_to_record(
        make_event(event_data='<Data Name="OriginalFileName">evil.exe</Data>')
    )
    assert record is not None
    assert record["OriginalFileName"] == "evil.exe"


def test_all_event_data_fields_are_kept_not_just_the_mapped_ones():
    record, _ = event_to_record(
        make_event(
            event_data=(
                '<Data Name="Image">C:\\a.exe</Data>'
                '<Data Name="ParentCommandLine">cmd.exe /c whoami</Data>'
                '<Data Name="Details">Something</Data>'
                '<Data Name="IntegrityLevel">High</Data>'
            )
        )
    )
    assert record is not None
    assert record["ParentCommandLine"] == "cmd.exe /c whoami"
    assert record["Details"] == "Something"
    assert record["IntegrityLevel"] == "High"
    # 语义别名仍在（全流程通用判据）
    assert record["process_image"] == "C:\\a.exe"


def test_system_header_fields_are_mapped():
    record, _ = event_to_record(
        make_event(
            system=(
                "<Channel>Microsoft-Windows-Sysmon/Operational</Channel>"
                "<Level>4</Level>"
                "<Task>1</Task>"
                "<Opcode>0</Opcode>"
                "<Keywords>0x8000000000000000</Keywords>"
                "<EventRecordID>42</EventRecordID>"
                "<Computer>WIN-SRV01</Computer>"
            )
        )
    )
    assert record is not None
    assert record["channel"] == "Microsoft-Windows-Sysmon/Operational"
    assert record["provider"] == "Microsoft-Windows-Sysmon"
    assert record["level"] == "4"
    assert record["task"] == "1"
    assert record["opcode"] == "0"
    assert record["keywords"] == "0x8000000000000000"
    assert record["event_record_id"] == "42"
    assert record["target_asset"] == "WIN-SRV01"


def test_unnamed_data_is_collected_under_data():
    record, _ = event_to_record(
        make_event(event_data="<Data>&lt;string&gt;first&lt;/string&gt;</Data>")
    )
    assert record is not None
    assert record["Data"] == "<string>first</string>"


def test_empty_and_placeholder_values_are_not_stored():
    record, _ = event_to_record(
        make_event(
            event_data=(
                '<Data Name="Details"></Data>'
                '<Data Name="Provider_Name">-</Data>'
                '<Data Name="Signed">N/A</Data>'
            )
        )
    )
    assert record is not None
    assert "Details" not in record
    assert "Provider_Name" not in record
    assert "Signed" not in record


def test_auth_event_carries_standard_fields_and_keeps_summary():
    record, is_auth = event_to_record(
        make_event(
            event_id="4624",
            event_data=(
                '<Data Name="TargetUserName">administrator</Data>'
                '<Data Name="LogonType">10</Data>'
                '<Data Name="IpAddress">203.0.113.70</Data>'
                '<Data Name="LogonProcessName">User32</Data>'
                '<Data Name="WorkstationName">WIN-SRV01</Data>'
            ),
        )
    )
    assert is_auth is True
    assert record is not None
    assert record["LogonProcessName"] == "User32"
    assert record["WorkstationName"] == "WIN-SRV01"
    assert record["username"] == "administrator"
    assert "Logon Type: 10" in record["raw"]


def test_raw_carries_channel_and_standard_fields_as_evidence():
    record, _ = event_to_record(
        make_event(
            system="<Channel>Microsoft-Windows-Sysmon/Operational</Channel>",
            event_data='<Data Name="OriginalFileName">evil.exe</Data>',
        )
    )
    assert record is not None
    assert "Channel: Microsoft-Windows-Sysmon/Operational" in record["raw"]
    assert "OriginalFileName: evil.exe" in record["raw"]


def test_sigma_rule_on_standard_field_matches_real_record(monkeypatch):
    """端到端：Sigma 字段 → 转换器 → 真实记录 → 命中。

    这是整条链路的回归点——`scope:` 补丁时代这条规则落成 `raw equals "evil.exe"`，
    永远不命中。
    """

    # conftest 默认关闭社区规则全局开关，这里要验证真实启用状态
    monkeypatch.setenv("RULE_SIGMA_IMPORTED_ENABLED", "true")
    document = {
        "title": "Probe OriginalFileName",
        "id": "00000000-0000-0000-0000-000000000001",
        "logsource": {"product": "windows", "category": "process_creation"},
        "detection": {
            "selection": {"OriginalFileName": "evil.exe"},
            "condition": "selection",
        },
    }
    record, _ = event_to_record(
        make_event(event_data='<Data Name="OriginalFileName">evil.exe</Data>')
    )
    assert record is not None
    record["log_type"] = "windows_evtx"
    rule = build_rule(convert_rule(document), source="sigma")
    assert evaluate_rule(rule, [record])


def test_sigma_predicate_targets_the_standard_field_directly():
    document = {
        "title": "Probe Details",
        "id": "00000000-0000-0000-0000-000000000002",
        "logsource": {"product": "windows", "category": "process_creation"},
        "detection": {"selection": {"Details": "Something"}, "condition": "selection"},
    }
    where = convert_rule(document)["detection"]["where"]
    assert {"field": "Details", "op": "equals", "value": "Something"} in where


def test_sigma_declared_transform_is_written_into_the_rule():
    """声明了变换的字段必须把 `transform` 落盘，否则归一化会静默丢失。"""

    document = {
        "title": "Probe Url Decode",
        "id": "00000000-0000-0000-0000-000000000003",
        "logsource": {"category": "webserver"},
        "detection": {"selection": {"cs-uri-stem": "/admin"}, "condition": "selection"},
    }
    where = convert_rule(document)["detection"]["where"]
    assert {"op": "equals", "field": "url", "transform": "url_decode", "value": "/admin"} in where
