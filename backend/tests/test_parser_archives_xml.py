"""压缩包上传（zip / gzip / bzip2）与通用 XML 解析的针对性测试。

对应 AGENTS.md §33：新增日志类型必须带正常 / 异常 / 边界用例。
"""

from __future__ import annotations

import bz2
import gzip
import io
import zipfile

from app.services.parser import parse_log, parse_upload

SSH_LINE = (
    "Sep 14 08:00:00 host sshd[1234]: Failed password for root "
    "from 10.0.0.1 port 22 ssh2"
)
WEB_LINE = (
    '203.0.113.9 - - [14/Oct/2026:08:00:00 +0800] "GET /.git/config HTTP/1.1" '
    '404 1 "-" "ua"'
)

XML_LOG = """<?xml version="1.0"?>
<Log>
  <Event>
    <Timestamp>2026-10-14T08:00:00Z</Timestamp>
    <SourceAddress>203.0.113.9</SourceAddress>
    <User>admin</User>
    <Action>login</Action>
    <Result>failed</Result>
  </Event>
  <Event>
    <Timestamp>2026-10-14T08:01:00Z</Timestamp>
    <SourceAddress>203.0.113.9</SourceAddress>
    <User>admin</User>
    <Action>login</Action>
    <Result>success</Result>
  </Event>
</Log>"""


def test_parse_log_generic_xml_maps_standard_fields():
    result = parse_log(XML_LOG)
    assert result.log_type == "xml"
    assert len(result.records) == 2
    assert result.parse_failures == 0
    first = result.records[0]
    assert first["timestamp_iso"] == "2026-10-14T08:00:00+00:00"
    assert first["source_ip"] == "203.0.113.9"
    assert first["username"] == "admin"
    assert first["action"] == "login"
    assert first["result"] == "failure"
    # 原样收下的字段保留，raw 是元素原文（供关键字匹配）
    assert first["SourceAddress"] == "203.0.113.9"
    assert "<Timestamp>" in (first["raw"] or "")


def test_parse_log_evtx_xml_still_routed_to_windows_evtx():
    evtx_xml = (
        '<Events><Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        "<System><EventID>4624</EventID></System></Event></Events>"
    )
    assert parse_log(evtx_xml).log_type == "windows_evtx"


def test_parse_upload_gzip_and_bzip2_unpack_to_inner_log():
    for compress in (gzip.compress, bz2.compress):
        result = parse_upload(compress((WEB_LINE + "\n").encode()))
        assert result.log_type == "nginx_apache"
        assert len(result.records) == 1
        assert result.records[0]["url"] == "/.git/config"


def test_parse_upload_zip_merges_members_and_counts_failures():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("ssh.log", SSH_LINE + "\n")
        archive.writestr("web.log", WEB_LINE + "\n")
        archive.writestr("broken.bin", b"PK\x03\x04garbage-not-a-zip")
    result = parse_upload(buffer.getvalue())
    # 两个成员的记录拼接；损坏成员计入失败并留明细（带成员名，多成员时可定位）
    assert len(result.records) == 2
    assert result.parse_failures == 1
    assert any(item.get("source") == "broken.bin" for item in result.parse_error_details)


def test_parse_upload_zip_skips_macos_metadata_silently():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("web.log", WEB_LINE + "\n")
        archive.writestr("__MACOSX/web.log", "junk")
    result = parse_upload(buffer.getvalue())
    assert len(result.records) == 1
    assert result.parse_failures == 0


def test_parse_upload_unwraps_nested_zip_in_gzip():
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as archive:
        archive.writestr("ssh.log", SSH_LINE + "\n")
    result = parse_upload(gzip.compress(inner.getvalue()))
    assert result.log_type == "ssh"
    assert len(result.records) == 1
    assert result.records[0]["source_ip"] == "10.0.0.1"


def test_parse_upload_stops_recursing_beyond_depth_limit():
    # 4 层嵌套超过 ARCHIVE_MAX_DEPTH：最内层按文本兜底，不炸栈
    payload = (WEB_LINE + "\n").encode()
    for _ in range(4):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("inner.log", payload)
        payload = buffer.getvalue()
    result = parse_upload(payload)
    assert result.records == []
