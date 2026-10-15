"""记录内存瘦身的回归网：值去重与「不再复制记录字典」两条约定。

背景：单条记录原本会在解析、组装、编号三个阶段各被复制一次完整字典（约 300 字节/条），
大日志下峰值内存成倍抬高。这里锁的是约定本身（重复值共享对象 / 就地组装），
不是具体数字——数字由 `scripts/bench_large_log.py` 负责量。
"""

from __future__ import annotations

from app.services.analyzer import assign_record_ids, collect_records
from app.services.parser import parse_log, reset_value_pool

LOG = "\n".join(
    [
        '203.0.113.7 - - [21/Sep/2026:09:10:00 +0800] "GET /a HTTP/1.1" 200 1 "-" "curl/8.0"',
        '203.0.113.7 - - [21/Sep/2026:09:10:00 +0800] "GET /b HTTP/1.1" 200 1 "-" "curl/8.0"',
    ]
)


def fresh(text: str) -> str:
    """造一个内容相同但对象不同的字符串（字符串字面量会被复用，测不出共享与否）。"""

    return text.encode().decode()


def test_repeated_field_values_share_one_object():
    """同一 IP / UA / 状态码在同一份日志里反复出现时，应共享同一个字符串对象。"""

    records = parse_log(LOG).records
    first, second = records[0], records[1]
    for field in ("source_ip", "user_agent", "status", "action", "timestamp"):
        assert first[field] == second[field]
        assert first[field] is second[field], field
    # raw 是逐条正文，近乎唯一，不做去重
    assert first["raw"] is not second["raw"]


def test_pooling_stops_for_high_cardinality_fields(monkeypatch):
    """取值种类超过上限即停止去重：否则去重表本身会变成新的内存负担。"""

    from app.services import parser

    monkeypatch.setattr(parser, "VALUE_POOL_LIMIT", 2)
    reset_value_pool()
    records = [parser._share({"url": fresh(value)}) for value in ("aa", "aa", "bb", "cc", "cc")]
    # 上限内：相同取值共享对象
    assert records[0]["url"] is records[1]["url"]
    # 出现第 3 种取值后该字段停止去重，取值仍然正确，只是不再共享
    assert records[3]["url"] == records[4]["url"]
    assert records[3]["url"] is not records[4]["url"]


def test_value_pool_does_not_leak_across_parses():
    """每次解析都要重置去重表，避免上一次分析的字符串被滞留。"""

    first = parse_log(LOG).records[0]["source_ip"]
    second = parse_log(LOG).records[0]["source_ip"]
    assert first == second
    assert first is not second


def test_record_assembly_mutates_in_place_instead_of_copying():
    """组装与编号必须就地改，不能为每条记录再造一份字典 / 一个新列表。"""

    parsed = parse_log(LOG)
    records = collect_records(["a.log"], [parsed])
    assert records[0] is parsed.records[0]
    assert records[0]["source_file"] == "a.log"
    assert records[0]["log_type"] == parsed.log_type

    returned = assign_record_ids(records)
    assert returned is records
    assert records[0]["record_id"] == "record-1"
    assert records[0]["evidence_id"] == "evidence-record-1"
