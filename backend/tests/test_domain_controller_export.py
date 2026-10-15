from __future__ import annotations

import io
import zipfile

from app.services.analyzer import analyze_parsed_logs
from app.services.parser import parse_upload


def _xlsx(rows: list[list[str]]) -> bytes:
    ns = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<worksheet xmlns="{ns}"><sheetData>',
    ]
    for row_number, values in enumerate(rows, start=1):
        cells = []
        for column, value in enumerate(values):
            ref = chr(ord("A") + column)
            escaped = (
                value.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
            )
            cells.append(f'<c r="{ref}{row_number}" t="inlineStr"><is><t>{escaped}</t></is></c>')
        lines.append(f'<row r="{row_number}">{"".join(cells)}</row>')
    lines.append("</sheetData></worksheet>")
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("xl/workbook.xml", f'<workbook xmlns="{ns}"/>')
        archive.writestr("xl/worksheets/sheet1.xml", "".join(lines))
    return output.getvalue()


HEADERS = [
    "首次发现时间", "最近发现时间", "风险等级", "登录类型", "源IP",
    "登录用户", "服务类型", "影响资产", "资产状态", "发生次数",
    "处置状态", "处置方式", "事件ID",
]


def test_domain_controller_xlsx_is_parsed_and_detected():
    content = _xlsx([
        ["查询条件"],
        HEADERS,
        ["2026-09-15 00:00:13", "2026-09-16 23:59:55", "高危", "异常IP",
         "10.0.0.80", "ws-0156$", "SMB", "10.0.0.10(DC01)",
         "在线", "25", "待处置", "-", "event-1"],
        ["2026-09-15 01:00:00", "2026-09-16 22:00:00", "高危", "异常时间",
         "10.0.0.11", "dc02$", "SMB", "10.0.0.10(DC01)",
         "在线", "3388", "待处置", "-", "event-2"],
    ])
    parsed = parse_upload(content)

    assert parsed.log_type == "windows_auth_export"
    assert parsed.parsed_lines == 2
    assert parsed.records[0]["source_ip"] == "10.0.0.80"
    assert parsed.records[0]["username"] == "ws-0156$"
    assert parsed.records[0]["occurrence_count"] == "25"
    assert parsed.records[0]["result"] is None

    result = analyze_parsed_logs(["domain.xlsx"], [parsed])
    events = {event.rule_id: event for event in result.events}
    assert events["windows.auth_export.suspicious_ip"].count == 25
    assert events["windows.auth_export.abnormal_time"].count == 3388
    assert result.metadata.log_type == "windows_auth_export"


def test_broken_domain_controller_xlsx_reports_failure():
    parsed = parse_upload(b"PK\x03\x04not-an-xlsx")
    assert parsed.log_type == "generic"

    parsed = parse_upload(
        _xlsx([HEADERS, ["", "", "高危", "异常IP", "10.0.0.1"]])
    )
    assert parsed.log_type == "windows_auth_export"
    assert parsed.parsed_lines == 0
    assert parsed.parse_failures == 1
