"""⑦ 压力场景：模型不按约定输出、以及解析器遇到非英语日志时的真实反应。

这一组用例回答的是同一个问题：**当输入不在「正常路径」上时，系统是降级还是崩掉？**

覆盖 5 个子项：

1. 模型返回非约定形状（未知字段、类型错位、NaN）——不能崩，也不能静默丢数据；
2. 过度自信——无意义的值不能被放大成「最高置信度」，高置信度也不能免检；
3. 多轮工具调用——模型永不停止时必须有硬上限；
4. 长上下文证据遗漏——采样必须显式声明「不是全部」，否则模型会把样本当全集；
5. 多语言日志——Web 日志与语言无关，syslog 消息体依赖英文关键词（**已知边界**，如实钉住）。

期望值全部来自实测（见 `_probe_stress.py` 的探测结果），不是推测。
"""

from __future__ import annotations

import json

import pytest

from app.models import AiBehavior
from app.services import ai as ai_service
from app.services.ai import (
    _coerce_confidence,
    _compact_context_text,
    _validate_response,
    build_ai_context,
)
from app.services.analyzer import analyze_log, assign_record_ids, collect_records
from app.services.parser import parse_log

RISK_LEVELS = {"critical", "high", "medium", "low", "info"}


def _parse_for_test(filename: str, lines: list[str]):
    """与生产路径同一口径地解析日志：解析 → 收集 → 编号。"""

    parsed = parse_log("\n".join(lines))
    return assign_record_ids(collect_records([filename], [parsed]))


# ==========================================================================
# 1. 模型返回非约定形状：不崩、不静默丢数据
# ==========================================================================


@pytest.mark.parametrize("bad_risk", ["CRITICAL", "HIGH", "severe", 5, ["high"], None, ""])
def test_invalid_risk_level_is_downgraded_not_fatal(bad_risk):
    """风险等级取值非法时必须降级为 info，而不是抛 ValidationError。

    大写是最常见的一种：LLM 极爱输出 `"HIGH"`。此前顶层会被归一化，但
    `_build_structured_verdict` 把**原始值**交给 pydantic Literal，构造时就抛错，
    写在构造之后的那段兜底永远执行不到（死代码）——整轮 AI 研判随之失败。
    """

    result = _validate_response({"risk_level": bad_risk, "summary": "x"})

    assert result["risk_level"] in RISK_LEVELS
    assert result["risk_level"] == "info"


def test_invalid_risk_level_inside_structured_is_downgraded_not_fatal():
    payload = {"structured": {"abnormal_behavior": "扫描行为", "risk_level": "CRITICAL"}}

    verdict = _validate_response(payload)["structured_verdict"]

    assert verdict is not None
    assert verdict.risk_level == "info"
    # 其余字段不受影响：降级只针对风险等级，不能把整张卡片丢掉
    assert verdict.abnormal_behavior == "扫描行为"


@pytest.mark.parametrize(
    "field,bad_value",
    [
        ("event_time", 20260929),
        ("attack_source_ip", 123),
        ("target_asset", ["a", "b"]),
        ("involved_account", 99),
        ("abnormal_behavior", {"x": 1}),
        ("attack_type", True),
        ("judgment_basis", 3.14),
    ],
)
def test_non_string_value_in_verdict_field_is_ignored_not_fatal(field, bad_value):
    """语义字符串字段收到数字/数组时按「未提供」处理。

    模型偶尔把账号写成数字（`"involved_account": 0`）、把时间写成 epoch。
    直接交给 pydantic 会让**整次分析失败**，代价远大于丢掉一个字段。
    """

    payload = {"structured": {field: bad_value, "success_indicator": "keep"}}

    verdict = _validate_response(payload)["structured_verdict"]

    assert verdict is not None
    assert getattr(verdict, field) is None
    assert verdict.success_indicator == "keep"


def test_nan_confidence_is_not_turned_into_maximum_confidence():
    """NaN 必须变成 0.0，不能变成 1.0。

    `json.loads` 默认接受非标准的 `NaN` 字面量，而 `min(1.0, nan)` 返回 1.0 ——
    一个无意义的值会被放大成「最高置信度」，正好和「不允许过度自信」相反。
    """

    assert _validate_response(json.loads('{"confidence": NaN}'))["confidence"] == 0.0
    assert _coerce_confidence(float("nan")) == 0.0


def test_nan_confidence_in_a_behavior_is_also_neutralised():
    payload = json.loads('{"behaviors": [{"name": "n", "confidence": NaN}]}')

    behaviors = _validate_response(payload)["behaviors"]

    assert len(behaviors) == 1
    assert behaviors[0].confidence == 0.0


@pytest.mark.parametrize("value,expected", [(1.5, 1.0), (-1, 0.0), (0.42, 0.42), ("0.42", 0.42)])
def test_confidence_is_clamped_into_unit_interval(value, expected):
    assert _validate_response({"confidence": value})["confidence"] == expected


def test_evidence_given_as_a_single_string_is_kept_whole():
    """模型把 evidence 写成单个字符串时，不能逐字符拆开。

    直接迭代字符串会得到 `['1', '0', '.', ...]`，界面上就会出现
    `1 0 . 0 . 0 . 1` 这种证据 —— 比丢掉它更糟，因为它看起来像证据。
    """

    payload = {"behaviors": [{"name": "n", "evidence": "10.0.0.1"}]}

    behaviors = _validate_response(payload)["behaviors"]

    assert behaviors[0].evidence == ["10.0.0.1"]


def test_unparseable_behavior_confidence_keeps_the_behavior():
    """置信度写不成数字时保留整条行为，只把置信度置 0。

    此前 `float("high")` 抛错被 `except Exception: continue` 吞掉，
    **整条行为被静默丢弃** —— 丢的是一条真实发现，代价远超一个置信度。
    顶层对同类问题一直是「回退 0.0」，这里与之一致。
    """

    payload = {"behaviors": [{"name": "n", "confidence": "high", "analysis": "a"}]}

    behaviors = _validate_response(payload)["behaviors"]

    assert len(behaviors) == 1
    assert behaviors[0].confidence == 0.0
    assert behaviors[0].analysis == "a"


def test_evidence_ids_given_as_a_single_string_is_parsed_and_diagnosed():
    """裸字符串形式的 evidence_ids 要按单项处理，并进入「引用不存在证据」诊断。"""

    payload = {"behaviors": [{"name": "n", "evidence_ids": "e-1"}]}

    resolved = _validate_response(payload, valid_evidence_ids={"e-1"})
    assert resolved["behaviors"][0].evidence_ids == ["e-1"]
    assert resolved["dropped_evidence_ids"] == []

    rejected = _validate_response(payload, valid_evidence_ids=set())
    assert rejected["behaviors"][0].evidence_ids == []
    assert rejected["dropped_evidence_ids"] == ["e-1"]


# ==========================================================================
# 2. 模型引用不存在字段：白名单式读取，未知字段不得泄漏
# ==========================================================================


def test_unknown_top_level_fields_do_not_leak_into_the_result():
    """`_validate_response` 是白名单：模型自造的字段不能被带进研判结果。

    否则模型编一个 `"internal_debug"` 就能往结果里塞任意内容，
    而结果会被前端直接渲染。
    """

    payload = {
        "risk_level": "high",
        "summary": "异常",
        "attack_technique": "T1110",
        "mitre_id": "T1110",
        "iocs": ["1.2.3.4"],
        "internal_debug": {"secret": 1},
    }

    result = _validate_response(payload)

    for invented in ("attack_technique", "mitre_id", "iocs", "internal_debug"):
        assert invented not in result
    assert set(result) == {
        "risk_level",
        "confidence",
        "conclusion",
        "recommendations",
        "behaviors",
        "structured_verdict",
        "dropped_evidence_ids",
    }


def test_unknown_behavior_fields_are_ignored_not_rejected():
    """行为里的未知键要被忽略，而不是让整条行为消失。"""

    payload = {
        "behaviors": [
            {"name": "n", "type": "t", "analysis": "a", "confidence": 0.5, "sigma_rule": "x"}
        ]
    }

    behaviors = _validate_response(payload)["behaviors"]

    assert len(behaviors) == 1
    assert set(AiBehavior.model_fields) >= set(vars(behaviors[0]))


@pytest.mark.parametrize("junk", ["str", 42, None, ["a"]])
def test_non_dict_behavior_entries_are_skipped(junk):
    assert _validate_response({"behaviors": [junk]})["behaviors"] == []


def test_empty_behavior_object_becomes_a_placeholder():
    """**已知粗糙边缘**：空对象 `{}` 会生成一条占位行为，而不是被丢弃。

    `isinstance(item, dict)` 对 `{}` 成立，于是走默认值得到
    `unknown_behavior / confidence=0.0 / analysis=""` —— 一条没有任何内容、
    也对应不到任何日志证据的条目。它置信度为 0 且无分析，不构成误导性结论，
    但它会计入「行为条数」，而 P2 评测的召回下界正是按条数判定的。

    这里把现状钉住，是为了让「要不要丢弃空对象」这个决定有据可依；
    改动前请先确认评测召回口径不受影响。
    """

    behaviors = _validate_response({"behaviors": [{}]})["behaviors"]

    assert len(behaviors) == 1
    assert behaviors[0].type == "unknown_behavior"
    assert behaviors[0].confidence == 0.0
    assert behaviors[0].analysis == ""
    assert behaviors[0].evidence == []


# ==========================================================================
# 3. 过度自信：高置信度不免检
# ==========================================================================


def test_high_confidence_does_not_exempt_a_fabricated_claim_from_grounding():
    """置信度再高，编造的 IP 一样要被溯源抓到。

    置信度是「结论有多自信」，不是「证据有多充分」；两者混为一谈时，
    模型只要自称 0.99 就能免检。
    """

    from app.services.ai import _check_grounding

    log = (
        '203.0.113.10 - - [29/Sep/2026:09:10:00 +0800] '
        '"GET /.env HTTP/1.1" 403 12 "-" "curl/8.0"'
    )
    result = analyze_log("access.log", log)
    records = _parse_for_test("access.log", [log])

    judgement = _validate_response(
        {
            "risk_level": "critical",
            "confidence": 0.99,
            "summary": "攻击来源为 10.9.9.9。",
        }
    )
    claims = _check_grounding(judgement, result, records)

    assert any("10.9.9.9" in claim for claim in claims), claims


def test_confidence_above_one_cannot_be_claimed():
    assert _validate_response({"confidence": 1.5})["confidence"] == 1.0


# ==========================================================================
# 4. 多轮工具调用：硬上限
# ==========================================================================


def _tool_calls_body(index: int) -> dict:
    return {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [
                        {
                            "id": f"c{index}",
                            "type": "function",
                            "function": {"name": "log_metadata", "arguments": "{}"},
                        }
                    ],
                }
            }
        ]
    }


def test_tool_round_cap_is_enforced_when_the_model_never_stops(monkeypatch):
    """模型每轮都要求调工具时，必须在轮次上限处收口。

    没有硬上限就等于把成本与延迟交给模型决定 —— 一个陷入循环的模型可以无限调用工具。
    走到上限后还要补一次「收尾」请求，把已取回的证据收敛成结论。
    """

    from app.services.ai import OpenAICompatibleProvider

    monkeypatch.setenv("AI_MAX_TOOL_ROUNDS", "2")
    monkeypatch.setenv("AI_PROMPT_CACHE", "false")

    posts: list[int] = []

    def always_asks_for_a_tool(*args, **kwargs):
        posts.append(len(posts) + 1)
        return _tool_calls_body(len(posts))

    monkeypatch.setattr(ai_service, "_request_json", always_asks_for_a_tool)

    provider = OpenAICompatibleProvider("https://api.deepseek.com", "m", "k")
    result = _parse_for_test(
        "access.log",
        ['203.0.113.10 - - [29/Sep/2026:09:00:00 +0800] "GET /health HTTP/1.1" 200 1 "-" "curl/8"'],
    )

    _content, trace = provider.complete_with_tools(ai_service.SYSTEM_PROMPT, {"metadata": {}}, result, [])

    # 2 轮工具轮 + 1 次收尾请求
    assert len(posts) == 3, posts
    # 每轮的调用都留在轨迹里，便于事后核对成本
    assert len([entry for entry in trace if entry.get("source") == "model"]) == 2


def test_tool_round_cap_scales_with_the_configured_limit(monkeypatch):
    from app.services.ai import OpenAICompatibleProvider

    monkeypatch.setenv("AI_PROMPT_CACHE", "false")

    for limit in (1, 3):
        monkeypatch.setenv("AI_MAX_TOOL_ROUNDS", str(limit))
        posts: list[int] = []

        def always_asks_for_a_tool(*args, **kwargs):
            posts.append(len(posts) + 1)
            return _tool_calls_body(len(posts))

        monkeypatch.setattr(ai_service, "_request_json", always_asks_for_a_tool)
        provider = OpenAICompatibleProvider("https://api.deepseek.com", "m", "k")
        result = _parse_for_test(
            "access.log",
            ['203.0.113.10 - - [29/Sep/2026:09:00:00 +0800] "GET /health HTTP/1.1" 200 1 "-" "curl/8"'],
        )
        provider.complete_with_tools(ai_service.SYSTEM_PROMPT, {"metadata": {}}, result, [])

        assert len(posts) == limit + 1, (limit, posts)


# ==========================================================================
# 5. 长上下文证据遗漏：采样必须声明「不是全部」
# ==========================================================================


def test_sample_note_declares_that_it_is_not_the_whole_log():
    """上下文里的样本必须显式说明「不是全部」，并给出继续取数的工具。

    否则模型会把「样本里有 200 条」当成「日志只有 200 条」，
    进而漏掉样本之外的证据却自称已看全。
    """

    lines = [
        f'203.0.113.{i % 250} - - [29/Sep/2026:09:00:{i % 60:02d} +0800] "GET /a HTTP/1.1" 200 {i} "-" "curl/8"'
        for i in range(300)
    ]
    log = "\n".join(lines)
    result = analyze_log("access.log", log)
    records = _parse_for_test("access.log", lines)

    context = build_ai_context(result, records)
    note = context["records_sample_note"]

    assert f"records_total={len(records)}" in note
    assert "not_all" in note
    assert "more=query_records" in note


def test_truncated_raw_text_is_visibly_marked():
    """被截断的原文要留下痕迹，不能让模型以为看到的是完整行。"""

    long_text = "A" * 5000

    compacted = _compact_context_text(long_text)

    assert len(compacted) < len(long_text)
    assert "[已截断]" in compacted
    assert compacted.startswith("A")
    assert compacted.endswith("A")


def test_short_raw_text_is_left_untouched():
    assert _compact_context_text("short line") == "short line"


# ==========================================================================
# 6. 多语言日志：如实钉住能力边界
# ==========================================================================


@pytest.mark.parametrize(
    "line,expected_url",
    [
        (
            '203.0.113.10 - admin [29/Sep/2026:09:10:00 +0800] "GET /.env HTTP/1.1" 403 12 "-" '
            '"Mozilla/5.0 (de-DE)"',
            "/.env",
        ),
        (
            '203.0.113.11 - - [29/Sep/2026:09:11:00 +0800] "GET /../../etc/passwd HTTP/1.1" 400 0 "-" '
            '"curl/8.0"',
            "/../../etc/passwd",
        ),
    ],
)
def test_web_log_parsing_is_language_independent(line, expected_url):
    """Web 日志靠字段位置与 URL 特征识别，与语言无关——德语/中文 UA 照样解析。

    这不是「支持多语言」的实现，而是格式决定的：combined 格式的语义在位置上，
    不在词语里。
    """

    parsed = parse_log(line)

    assert parsed.log_type == "nginx_apache"
    assert parsed.parsed_lines == 1
    assert parsed.records[0]["url"] == expected_url


def test_syslog_body_recognition_depends_on_english_keywords():
    """**已知能力边界**：syslog 消息体靠英文关键词匹配，非英语消息会落到 generic。

    这里不是在断言「这样没问题」，而是把边界钉死：德语 / 中文的 sshd 日志
    目前解析不出任何记录。改动解析器时这条会失败，从而提醒更新边界说明。
    """

    english = "Sep 29 09:10:00 host sshd[1]: Failed password for root from 10.0.0.1 port 22 ssh2"
    german = (
        "Sep 29 09:10:00 host sshd[1]: Fehlgeschlagene Passwortauthentifizierung fuer root "
        "von 10.0.0.1 port 22 ssh2"
    )
    chinese = "Sep 29 09:10:00 host sshd[1]: 来自 10.0.0.1 的用户 root 认证失败"

    parsed_en = parse_log(english)
    assert parsed_en.log_type == "ssh"
    assert parsed_en.parsed_lines == 1
    assert parsed_en.records[0]["source_ip"] == "10.0.0.1"
    assert parsed_en.records[0]["username"] == "root"

    for non_english in (german, chinese):
        parsed = parse_log(non_english)
        assert parsed.log_type == "generic"
        assert parsed.parsed_lines == 0


def test_web_remote_user_is_not_extracted_so_grounding_falls_back_to_raw():
    """解析器把 Web 日志的 username 写死为 None，溯源必须回退查原文。

    这条是 `test_ai_grounding.py::test_real_account_in_verdict_is_not_reported`
    的解析层对应断言：如果哪天解析器开始提取 remote_user，这里会失败，
    提醒把溯源逻辑收回到结构化字段（更严格）。
    """

    parsed = parse_log(
        '203.0.113.10 - admin [29/Sep/2026:09:10:00 +0800] "GET /.env HTTP/1.1" 403 12 "-" "curl/8.0"'
    )

    assert parsed.records[0]["username"] is None
    assert "admin" in parsed.records[0]["raw"]
