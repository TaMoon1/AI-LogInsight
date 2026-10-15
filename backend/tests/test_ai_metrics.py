"""成本 × 质量联合指标（P3 ①②③）。

这个文件主要钉三件容易做错的事：

1. **估算不能当账单**。服务端不会告诉你「第 3 个事件花了多少 token」，
   所以逐事件 / 逐证据的体量只能是按上下文字节数分摊的估算。它和真实账单
   在数据结构上就是分开的字段，不共用键——混在一起会让成本优化得出错误结论。
2. **缺账单是 `None`，不是 0**。「服务端没回传用量」与「用量为零」是两件事。
3. **不可评估不记满分**。一条证据都没下发时，引用覆盖率是 `None`，不是 1.0。
   与 P2 的「无行为时引用覆盖率不可评估」同源。
"""

from __future__ import annotations

import json

import pytest

from app.services import ai as ai_service
from app.services.ai_metrics import (
    BYTES_PER_TOKEN,
    ContextBreakdown,
    PriceTable,
    build_metrics,
    estimate_cost,
    estimate_tokens,
    measure_context,
)


class _Result:
    """`measure_context` 只用到 `result.events[].evidence_items`。"""

    def __init__(self, evidence_counts: list[int]) -> None:
        self.events = [
            type("E", (), {"evidence_items": [object()] * count}) for count in evidence_counts
        ]


def _context(events: list[dict], **extra) -> dict:
    return {"events": events, **extra}


def _event(name: str, evidence_ids: list[str], risk_level: str = "medium") -> dict:
    return {
        "name": name,
        "risk_level": risk_level,
        "evidence_items": [{"id": eid, "raw": f"raw-{eid}"} for eid in evidence_ids],
    }


# --------------------------------------------------------------------------
# 估算
# --------------------------------------------------------------------------


def test_estimate_tokens_uses_two_bytes_per_token():
    """口径与 `docs/ai-token-cost.md` §1 一致：中文 JSON 约 2 字节 = 1 token。"""

    assert BYTES_PER_TOKEN == 2.0
    assert estimate_tokens("a" * 200) == 100


def test_estimate_tokens_rounds_up_and_handles_empty():
    assert estimate_tokens("") == 0
    assert estimate_tokens("a") == 1  # 0.5 → 1，宁可高估不低估
    assert estimate_tokens("abc") == 2


def test_estimate_tokens_counts_utf8_bytes_not_characters():
    """中文一个字 3 字节，按字符数算会低估三分之一。"""

    assert estimate_tokens("中") == 2  # 3 字节 / 2 → 1.5 → 2
    assert estimate_tokens("中") > estimate_tokens("a")


# --------------------------------------------------------------------------
# 成本
# --------------------------------------------------------------------------


def test_unconfigured_prices_yield_no_cost_and_say_why():
    """**不内置厂商价格**：没配就没有数字，并且说明怎么配。

    写死价格会悄悄算出错的成本，而且没人会注意到——比不给数字更糟。
    """

    assert PriceTable().configured is False
    assert estimate_cost({"prompt_tokens": 1000, "completion_tokens": 100}, PriceTable()) is None
    assert "AI_PRICE_INPUT_PER_M" in PriceTable().note


def test_cost_uses_configured_prices():
    prices = PriceTable(input_per_m=2.0, output_per_m=8.0)

    cost = estimate_cost({"prompt_tokens": 1_000_000, "completion_tokens": 500_000}, prices)

    assert cost == pytest.approx(2.0 + 4.0)


def test_cache_hits_use_their_own_price_when_configured():
    prices = PriceTable(input_per_m=10.0, output_per_m=0.0, cache_hit_per_m=1.0)

    cost = estimate_cost(
        {"prompt_tokens": 1_000_000, "completion_tokens": 0, "cache_hit_tokens": 600_000},
        prices,
    )

    # 400k 未命中 × 10 + 600k 命中 × 1 = 4 + 0.6
    assert cost == pytest.approx(4.6)


def test_cache_hits_fall_back_to_input_price_when_not_configured():
    """没单独配缓存价就按输入价算——保守估计，宁可高估不低估。"""

    prices = PriceTable(input_per_m=10.0, output_per_m=0.0)

    cost = estimate_cost(
        {"prompt_tokens": 1_000_000, "completion_tokens": 0, "cache_hit_tokens": 600_000},
        prices,
    )

    assert cost == pytest.approx(10.0)


def test_cost_is_none_without_usage_or_without_token_counts():
    prices = PriceTable(input_per_m=1.0, output_per_m=1.0)

    assert estimate_cost(None, prices) is None
    assert estimate_cost({}, prices) is None
    # 缺一项就算不出来，不能拿半份数据凑一个数字
    assert estimate_cost({"prompt_tokens": 100}, prices) is None


def test_cache_hits_are_capped_at_prompt_tokens():
    """命中数大于输入数时不能算出负成本。"""

    prices = PriceTable(input_per_m=10.0, output_per_m=0.0, cache_hit_per_m=1.0)

    cost = estimate_cost(
        {"prompt_tokens": 100, "completion_tokens": 0, "cache_hit_tokens": 999}, prices
    )

    assert cost == pytest.approx(0.0001)


# --------------------------------------------------------------------------
# 上下文体量与归属
# --------------------------------------------------------------------------


def test_measure_context_reports_bytes_and_estimated_tokens():
    context = _context([_event("e", ["ev-1"])])

    breakdown = measure_context(context, _Result([1]))

    assert breakdown.context_bytes == len(json.dumps(context, ensure_ascii=False).encode("utf-8"))
    assert breakdown.estimated_input_tokens == estimate_tokens(json.dumps(context, ensure_ascii=False))


def test_event_tokens_align_with_context_events_by_index():
    """事件上下文字典里没有稳定 id，所以按顺序给出，与 `context["events"]` 一一对应。"""

    context = _context([_event("甲", ["ev-1"]), _event("乙", ["ev-2"])])

    breakdown = measure_context(context, _Result([1, 1]))

    assert [item["index"] for item in breakdown.event_tokens] == [0, 1]
    assert [item["name"] for item in breakdown.event_tokens] == ["甲", "乙"]
    assert all(item["tokens"] > 0 for item in breakdown.event_tokens)


def test_evidence_sent_counts_items_not_unique_ids():
    """同一条证据出现在多个事件里时，分母要按**条数**算。

    按 id 去重会把分母算小，覆盖率就会虚高——最坏情况超过 100%。
    """

    context = _context([_event("甲", ["ev-1"]), _event("乙", ["ev-1"])])

    breakdown = measure_context(context, _Result([1, 1]))

    assert breakdown.evidence_sent == 2  # 不是 1
    assert list(breakdown.evidence_tokens) == ["ev-1"]


def test_truncation_rate_counts_evidence_that_never_reached_the_context():
    context = _context([_event("甲", ["ev-1"])])

    breakdown = measure_context(context, _Result([4]))

    assert breakdown.evidence_available == 4
    assert breakdown.evidence_sent == 1
    assert breakdown.evidence_truncated == 3
    assert breakdown.evidence_truncation_rate == pytest.approx(0.75)


def test_truncation_rate_is_none_when_there_is_no_evidence():
    """没有任何证据时截断率不可评估，不记 0（0 会被读成「一条都没截断」）。"""

    breakdown = measure_context(_context([]), _Result([0]))

    assert breakdown.evidence_truncation_rate is None


def test_coverage_is_none_when_no_evidence_was_sent():
    """**不可评估不记满分**。一条证据都没下发时覆盖率是 None，不是 1.0。"""

    metrics = _metrics(context=_context([]), result=_Result([0]), referenced=[])

    assert metrics.evidence_coverage is None
    assert metrics.evidence_omission_rate is None


def test_omission_rate_is_the_complement_of_coverage():
    context = _context([_event("甲", ["ev-1", "ev-2", "ev-3", "ev-4"])])

    metrics = _metrics(context=context, result=_Result([4]), referenced=["ev-1"])

    assert metrics.evidence_coverage == pytest.approx(0.25)
    assert metrics.evidence_omission_rate == pytest.approx(0.75)


# --------------------------------------------------------------------------
# 分轮拆分
# --------------------------------------------------------------------------


def _metrics(*, context: dict, result, referenced: list[str], trace=None, prices=None):
    return build_metrics(
        context=context,
        result=result,
        tool_trace=trace or [],
        evidence_referenced=referenced,
        duration_ms=12.5,
        prices=prices or PriceTable(),
    )


def test_split_rounds_separates_first_round_from_tool_rounds():
    trace = [
        {
            "tool": "usage",
            "usage": {
                "rounds": 2,
                "prompt_tokens": 2200,
                "completion_tokens": 40,
                "cache_hit_tokens": 1000,
                "by_round": [
                    {"round": 1, "prompt_tokens": 1000, "completion_tokens": 10},
                    {"round": 2, "prompt_tokens": 1200, "completion_tokens": 30},
                ],
            },
        }
    ]

    metrics = _metrics(context=_context([]), result=_Result([0]), referenced=[], trace=trace)

    assert metrics.tokens_total == 2240
    assert metrics.tokens_first_round == 1010
    assert metrics.tokens_tool_rounds == 1230
    assert metrics.cache_hit_tokens == 1000
    assert metrics.rounds == 2


def test_split_rounds_does_not_pass_the_total_off_as_the_first_round():
    """**没有分轮明细时首轮为 None，不拿总数冒充**。

    冒充会让「首轮成本」恒等于总成本，看起来像后续轮次不花钱，
    正好把多轮历史裁剪的收益藏起来。
    """

    trace = [{"tool": "usage", "usage": {"rounds": 3, "prompt_tokens": 5000, "completion_tokens": 50}}]

    metrics = _metrics(context=_context([]), result=_Result([0]), referenced=[], trace=trace)

    assert metrics.tokens_total == 5050
    assert metrics.tokens_first_round is None
    assert metrics.tokens_tool_rounds is None


def test_metrics_survive_a_trace_without_usage():
    metrics = _metrics(context=_context([]), result=_Result([0]), referenced=[])

    assert metrics.tokens_total is None
    assert metrics.rounds == 0
    assert metrics.estimated_cost is None


# --------------------------------------------------------------------------
# payload：估算与账单分开，缺账不填 0
# --------------------------------------------------------------------------


def test_payload_keeps_estimates_and_billing_in_separate_blocks():
    trace = [
        {
            "tool": "usage",
            "usage": {
                "rounds": 1,
                "prompt_tokens": 100,
                "completion_tokens": 20,
                "by_round": [{"round": 1, "prompt_tokens": 100, "completion_tokens": 20}],
            },
        }
    ]
    metrics = _metrics(
        context=_context([_event("甲", ["ev-1"])]), result=_Result([1]), referenced=["ev-1"], trace=trace
    )

    payload = metrics.to_payload()

    # 账单在 tokens 下，估算在 context 下，不共用键
    assert payload["tokens"]["total"] == 120
    assert "estimated" not in payload["tokens"]
    assert payload["context"]["estimated_input_tokens"] > 0
    assert payload["context"]["bytes"] > 0
    assert "total" not in payload["context"]


def test_payload_writes_null_for_missing_billing():
    payload = _metrics(context=_context([]), result=_Result([0]), referenced=[]).to_payload()

    assert payload["tokens"]["total"] is None
    assert payload["tokens"]["first_round"] is None
    assert payload["cost"]["estimated"] is None


def test_payload_is_json_serialisable():
    metrics = _metrics(context=_context([_event("甲", ["ev-1"])]), result=_Result([1]), referenced=["ev-1"])

    text = json.dumps(metrics.to_payload(), ensure_ascii=False)

    assert "context" in text


# --------------------------------------------------------------------------
# 端到端接线
# --------------------------------------------------------------------------


def _log() -> str:
    return "\n".join(
        f'203.0.113.{i % 250} - - [29/Sep/2026:09:0{i % 10}:00 +0800] '
        f'"GET /.env HTTP/1.1" 403 {i} "-" "curl/8"'
        for i in range(20)
    )


def _run_judgement(monkeypatch, answer: dict):
    from unittest.mock import patch

    from app.services.analyzer import analyze_log, assign_record_ids, collect_records
    from app.services.parser import parse_log

    log = _log()
    parsed = parse_log(log)
    records = assign_record_ids(collect_records(["access.log"], [parsed]))
    result = analyze_log("access.log", log)
    raw = json.dumps(answer, ensure_ascii=False)

    class _Provider:
        supports_tools = False
        last_usage = {"rounds": 1, "prompt_tokens": 900, "completion_tokens": 60}

        def complete(self, *args, **kwargs):  # noqa: ANN002, ANN003
            return raw

    with (
        patch.object(ai_service, "_create_provider", lambda: _Provider()),
        patch.object(ai_service, "_run_auto_tools", lambda _r, _c: ({}, [])),
    ):
        return ai_service.request_ai_judgement(result, records)


def test_judgement_carries_metrics(monkeypatch):
    judgement = _run_judgement(
        monkeypatch,
        {
            "risk_level": "medium",
            "confidence": 0.7,
            "summary": "敏感路径探测",
            "behaviors": [{"type": "t", "name": "n", "confidence": 0.7, "evidence": ["raw"],
                           "evidence_ids": [], "analysis": "a"}],
        },
    )

    metrics = judgement["metrics"]

    assert metrics["duration_ms"] > 0
    assert metrics["tokens"]["total"] == 960
    assert metrics["context"]["bytes"] > 0
    assert metrics["context"]["evidence_sent"] > 0
    assert metrics["context"]["event_tokens"]


def test_previous_metrics_never_leak_into_the_next_context():
    """上一次研判的成本指标不能进下一次的上下文。

    它对模型毫无意义（白花钱），而且会让模型看到上一轮的结论痕迹。
    """

    from app.services.analyzer import analyze_log
    from app.services.ai import build_ai_context

    result = analyze_log("access.log", _log())
    result = result.model_copy(update={"ai_metrics": {"tokens": {"total": 12345}}})

    context = build_ai_context(result, [])

    assert "ai_metrics" not in context
    assert "12345" not in json.dumps(context, ensure_ascii=False)


def test_ledger_carries_metrics_and_shows_them():
    from app.services.ai_ledger import build_ai_ledger, render_ledger_html
    from app.services.analyzer import analyze_log

    result = analyze_log("access.log", _log())
    result = result.model_copy(update={"ai_metrics": {"tokens": {"total": 960}}})

    ledger = build_ai_ledger(result, "completed")

    assert ledger.metrics == {"tokens": {"total": 960}}
    html = render_ledger_html(ledger)
    assert "成本 × 质量指标" in html
    assert "960" in html
    # 台账里必须说清哪些是估算，避免把分摊值当账单
    assert "估算" in html


def test_ledger_without_metrics_renders_a_dash():
    from app.services.ai_ledger import build_ai_ledger, render_ledger_html
    from app.services.analyzer import analyze_log

    ledger = build_ai_ledger(analyze_log("access.log", _log()), "unavailable")

    assert ledger.metrics is None
    assert "成本 × 质量指标" in render_ledger_html(ledger)


def test_context_breakdown_defaults_are_safe():
    breakdown = ContextBreakdown()

    assert breakdown.evidence_truncation_rate is None
    assert breakdown.event_tokens == []
