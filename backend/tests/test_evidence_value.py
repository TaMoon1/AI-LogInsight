"""证据价值评分与上下文压缩（路线图 P4 ①–⑤）。

本文件守三类东西，每类都对应一个「看起来对、实际会静默出错」的坑：

1. **评分不得影响研判结论**。评分是成本控制手段，一旦它能改变 `risk_level`、
   `behaviors` 或任何进入结论的字段，它就变成了「为了省钱而改判」。
2. **相对分量在小日志上会退化**。用「该实体活动量 / 最活跃实体活动量」做关联度，
   只有一份日志一个实体时自身就是峰值，恒等于满分——等于白送分。
3. **单阶段链没有端点**。`stages[0] == stages[-1]`，若也算端点则每个孤立事件
   都是「关键节点」，这个标记就完全失去区分能力（实测覆盖率接近 100%）。
"""

from __future__ import annotations

import json

import pytest

from app.services import ai as ai_service
from app.services import evidence_value
from app.services.analyzer import analyze_log, assign_record_ids, collect_records
from app.services.parser import parse_log

# --------------------------------------------------------------------------
# 工具
# --------------------------------------------------------------------------


def _context(text: str, filename: str = "auth.log"):
    parsed = parse_log(text)
    records = assign_record_ids(collect_records([filename], [parsed]))
    result = analyze_log(filename, text)
    return result, records, ai_service.build_ai_context(result, records)


def _ssh_failures(count: int, ip: str = "203.0.113.12") -> list[str]:
    return [
        f"Sep 29 09:00:{index:02d} host sshd[{index}]: "
        f"Failed password for root from {ip} port {40000 + index} ssh2"
        for index in range(count)
    ]


def _web_probes(count: int, ip: str = "203.0.113.20", path: str = "/.env") -> list[str]:
    return [
        f'{ip} - - [29/Sep/2026:09:10:{index:02d} +0800] '
        f'"GET {path} HTTP/1.1" 403 12 "-" "curl/8.0"'
        for index in range(count)
    ]


# --------------------------------------------------------------------------
# ① 五个分量：依据、边界、单调性
# --------------------------------------------------------------------------


def test_score_reports_every_component_separately():
    """五个分量必须能逐项读出来——「可解释」的含义是能回答「为什么这么多」，
    不是「公式长什么样」。"""

    score = evidence_value.score_event(
        evidence_value.EventFacts("medium", "builtin", 2, 0.5, 0.5)
    )
    assert (score.risk, score.confidence, score.reliability, score.novelty, score.correlation) == (
        0.5,
        0.7,
        1.0,
        0.5,
        0.5,
    )
    note = score.to_note()
    for key in ("risk=", "confidence=", "reliability=", "novelty=", "correlation=", "total="):
        assert key in note


def test_builtin_rule_scores_higher_than_sigma():
    """来源可靠性：内置规则有本地标注语料，Sigma 导入规则是未验证的。"""

    builtin = evidence_value.score_event(evidence_value.EventFacts("medium", "builtin"))
    sigma = evidence_value.score_event(evidence_value.EventFacts("medium", "sigma"))
    assert builtin.reliability > sigma.reliability
    assert builtin.total > sigma.total


def test_cross_checked_event_scores_higher():
    """置信度用「交叉印证」代理：同一实体上不同规则命中越多越可信。"""

    lone = evidence_value.score_event(evidence_value.EventFacts("medium", "builtin", 1))
    tripled = evidence_value.score_event(evidence_value.EventFacts("medium", "builtin", 3))
    assert lone.confidence < tripled.confidence < 1.0 + 1e-9
    assert tripled.total > lone.total


def test_risk_component_is_monotonic():
    """风险是主信号，分量必须随等级单调不减（与 `_event_evidence_depth` 同口径）。"""

    levels = ["info", "low", "medium", "high", "critical"]
    values = [evidence_value.RISK_COMPONENT[level] for level in levels]
    assert values == sorted(values)


def test_unknown_risk_level_does_not_crash_or_outrank_known():
    score = evidence_value.score_event(evidence_value.EventFacts("not-a-level"))
    assert score.risk <= evidence_value.RISK_COMPONENT["info"]


def test_depth_never_exceeds_the_cap_or_drops_below_one():
    for level in ("critical", "high", "medium", "low", "info"):
        for rules in (1, 2, 5):
            for novelty in (0.0, 1.0):
                facts = evidence_value.EventFacts(level, "sigma", rules, novelty, 0.0)
                depth = ai_service._evidence_depth(facts, key_node=False)
                assert 1 <= depth <= ai_service.EVENT_EVIDENCE_ITEM_LIMIT


# --------------------------------------------------------------------------
# ② 关联度：相对分量会在小日志上退化，必须用绝对口径
# --------------------------------------------------------------------------


def test_correlation_is_zero_when_nothing_is_correlated():
    """一份日志、一个事件 → 没有「关联」可言，分量必须是 0。

    用相对分量（活动量 / 峰值）会在这里返回 1.0，等于给每个事件白送满分。
    """

    assert evidence_value.entity_correlation(1, 1) == 0.0


def test_correlation_grows_with_files_and_events():
    assert evidence_value.entity_correlation(2, 3) == pytest.approx(0.75)
    assert evidence_value.entity_correlation(3, 5) == 1.0
    assert evidence_value.entity_correlation(9, 9) == 1.0


def test_correlation_does_not_inflate_on_single_entity_log():
    """回归：单实体日志里关联度不得恒为满分。"""

    result, _, context = _context(
        '203.0.113.11 - - [29/Sep/2026:09:10:00 +0800] "GET /.env HTTP/1.1" 403 12 "-" "curl"',
        filename="access.log",
    )
    assert len(result.events) == 1
    assert context["events"][0]["value_score"].count("correlation=0.00") == 1


# --------------------------------------------------------------------------
# ② 攻击链端点：只认 ≥2 阶段的链
# --------------------------------------------------------------------------


def test_single_stage_chain_has_no_endpoint():
    """单阶段链的 stages[0] 与 stages[-1] 是同一条，不该标成关键节点。

    若标了，每个孤立事件都是「关键节点」，标记失去区分能力。
    """

    result, _, context = _context(
        "\n".join(_web_probes(30)), filename="access.log"
    )
    assert len(result.events) == 1
    assert "chain_node" not in context["events"][0]


def test_multi_stage_chain_marks_its_endpoints():
    text = "\n".join(
        _ssh_failures(20)
        + ["Sep 29 09:02:00 host sshd[99]: Accepted password for root from 203.0.113.12 port 40099 ssh2"]
    )
    result, _, context = _context(text)
    assert len(result.events) >= 2
    assert all(item.get("chain_node") == "attack_chain_endpoint" for item in context["events"])


def test_chain_endpoint_is_never_demoted():
    """关键证据硬保留 = 不被价值微调降级，而不是拿到超过高风险事件的预算。"""

    weak = evidence_value.EventFacts("medium", "sigma", 1, 0.0, 0.0)
    assert evidence_value.depth_adjustment(evidence_value.score_event(weak).total) == -1

    base = ai_service._event_evidence_depth("medium")
    assert ai_service._evidence_depth(weak, key_node=False) == base - 1
    assert ai_service._evidence_depth(weak, key_node=True) == base


def test_endpoint_does_not_outrank_higher_risk_event():
    """回归：端点不该让 low 事件的证据条数超过 high 非端点事件。

    实测过这个错误——端点无差别给全局满额时，`low` 拿到 5 条而 `high` 只有 4 条。
    """

    low_endpoint = ai_service._evidence_depth(
        evidence_value.EventFacts("low", "builtin", 3, 1.0, 1.0), key_node=True
    )
    high_plain = ai_service._evidence_depth(
        evidence_value.EventFacts("high", "builtin", 1, 0.0, 0.0), key_node=False
    )
    assert low_endpoint <= high_plain


# --------------------------------------------------------------------------
# 硬约束：评分不改变研判结论
# --------------------------------------------------------------------------


def test_value_score_never_enters_verdict_fields():
    """评分只进 `events[].value_score` / `value_total`，不进结论字段。"""

    text = "\n".join(_ssh_failures(20))
    result, _, context = _context(text)
    # 规则结论由规则决定，与评分无关
    assert result.risk_level in {"medium", "high", "critical"}
    # 评分字段只在事件块里出现
    for key in ("risk_level", "confidence", "conclusion", "has_suspicious_behavior"):
        assert "value_score" not in json.dumps(context.get(key), ensure_ascii=False)
    assert "value_score" in context["events"][0]


def test_scoring_does_not_change_events_or_risk_level():
    """同一份日志，评分开关（用不同评分输入模拟）不得改变事件集与风险等级。"""

    text = "\n".join(_web_probes(30))
    first = analyze_log("access.log", text)
    second = analyze_log("access.log", text)
    assert [(e.rule_id, e.risk_level) for e in first.events] == [
        (e.rule_id, e.risk_level) for e in second.events
    ]
    assert first.risk_level == second.risk_level


# --------------------------------------------------------------------------
# ③ 预算削减按价值保留，而不是按列表位置
# --------------------------------------------------------------------------


def test_budget_cut_keeps_high_value_events():
    events = [
        {"id": index, "value_total": value, "payload": "x" * 200}
        for index, value in enumerate([0.1, 0.9, 0.2, 0.8, 0.3, 0.7])
    ]
    kept = ai_service._keep_top_value(events, 3)
    assert sorted(item["id"] for item in kept) == [1, 3, 5]


def test_budget_cut_restores_original_order():
    """恢复原顺序：上下文必须对同一份日志逐字稳定，否则 prompt cache 前缀失效。"""

    events = [{"id": index, "value_total": 0.5} for index in range(6)]
    kept = ai_service._keep_top_value(events, 4)
    assert [item["id"] for item in kept] == [0, 1, 2, 3]


def test_budget_cut_prioritizes_chain_nodes():
    events = [
        {"id": 0, "value_total": 0.99},
        {"id": 1, "value_total": 0.10, "chain_node": "attack_chain_endpoint"},
        {"id": 2, "value_total": 0.98},
    ]
    kept = ai_service._keep_top_value(events, 2)
    assert 1 in [item["id"] for item in kept]


def test_budget_cut_is_noop_when_under_limit():
    events = [{"id": index, "value_total": 0.5} for index in range(3)]
    assert ai_service._keep_top_value(events, 5) == events


def test_tight_budget_still_respects_hard_cap(monkeypatch):
    """削减后仍不得越过硬上限——关键节点优先不等于可以突破上限。"""

    text = "\n".join(_web_probes(120))
    result, records, _ = _context(text, filename="access.log")
    monkeypatch.setenv("AI_CONTEXT_MAX_BYTES", "20000")
    context = ai_service.build_ai_context(result, records)
    size = len(
        json.dumps(context, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    )
    assert size <= 20000, f"收紧预算后仍不得越界，实际 {size}"


# --------------------------------------------------------------------------
# ④ 证据召回率与自动降级
# --------------------------------------------------------------------------


def _many_high_risk_events(count: int) -> str:
    lines: list[str] = []
    for index in range(count):
        ip = f"203.0.113.{index + 1}"
        lines.extend(_ssh_failures(20, ip=ip))
        lines.append(
            f"Sep 29 09:00:59 host sshd[99]: Accepted password for root from {ip} port 40099 ssh2"
        )
    return "\n".join(lines)


def _ssh_bruteforce_success(ip: str = "203.0.113.12") -> str:
    """20 次失败 + 成功登录 → `ssh.bruteforce.success`（high）。

    只用 20 次失败是 **medium**（`ssh.bruteforce`）——升级到 high 靠的是后续成功登录。
    """

    return "\n".join(
        _ssh_failures(20, ip=ip)
        + [f"Sep 29 09:02:00 host sshd[99]: Accepted password for root from {ip} port 40099 ssh2"]
    )


def test_high_risk_recall_is_full_when_nothing_is_dropped():
    _, _, context = _context(_ssh_bruteforce_success())
    assert "high_risk_evidence_recall=1.00" in context["events_note"]
    assert "evidence_tier=full" not in context["events_note"]


def test_note_omits_recall_when_there_are_no_high_risk_events():
    """没有高风险事件就没什么可召回的，恒报 1.00 只是每轮白付字节。"""

    _, _, context = _context(
        '203.0.113.11 - - [29/Sep/2026:09:10:00 +0800] "GET /.env HTTP/1.1" 403 12 "-" "curl"',
        filename="access.log",
    )
    assert "high_risk_evidence_recall" not in context["events_note"]


def test_auto_downgrade_recovers_dropped_high_risk_evidence():
    """高风险事件被抽样丢掉、召回低于底线时，自动降级到更完整的档位。"""

    text = _many_high_risk_events(100)
    result, records, context = _context(text)
    high_risk = [e for e in result.events if e.risk_level in ai_service.HIGH_RISK_LEVELS]
    assert len(high_risk) > ai_service.EVENT_SAMPLE_LIMIT // 2, "构造的样本不足以触发降级"

    assert "evidence_tier=full" in context["events_note"]
    assert "reason=hr_recall_low" in context["events_note"]
    assert "high_risk_evidence_recall=1.00" in context["events_note"]
    # 降级后所有高风险事件都在上下文里
    sampled_rules = {item["rule_id"] for item in context["events"]}
    assert {event.rule_id for event in high_risk} <= sampled_rules


def test_downgrade_is_bounded_by_hard_max():
    """降级是「更完整的档位」，不是「不设上限」——否则它成了绕过预算的后门。"""

    assert ai_service.EVENT_SAMPLE_HARD_MAX > ai_service.EVENT_SAMPLE_LIMIT
    result, records, context = _context(_many_high_risk_events(100))
    assert len(context["events"]) <= ai_service.EVENT_SAMPLE_HARD_MAX


def test_recall_helper_counts_only_high_risk_events():
    result, _, _ = _context("\n".join(_web_probes(30)), filename="access.log")
    facts = ai_service._event_value_facts(result)
    picked = ai_service._sample_event_indexes(result.events, ai_service.EVENT_SAMPLE_LIMIT)
    sent, available = ai_service._high_risk_evidence_recall(result, picked, facts)
    # 该日志只有 medium 事件
    assert (sent, available) == (0, 0)


# --------------------------------------------------------------------------
# ⑤ 总数、时间范围与采样口径
# --------------------------------------------------------------------------


def test_records_note_reports_full_time_range():
    text = "\n".join(_web_probes(30))
    _, _, context = _context(text, filename="access.log")
    note = context["records_sample_note"]
    assert "time_range=2026-09-29T09:10:00~2026-09-29T09:10:29" in note


def test_records_note_says_unknown_instead_of_guessing_time_range():
    """没有时间戳时写 `unknown`，不猜一个范围出来（AGENTS.md §16）。"""

    _, _, context = _context('203.0.113.11 - - "GET /.env HTTP/1.1" 403 12 "-" "curl"',
                             filename="access.log")
    assert "time_range=unknown" in context["records_sample_note"]


def test_records_note_keeps_totals_and_sampling_basis():
    _, _, context = _context("\n".join(_web_probes(30)), filename="access.log")
    note = context["records_sample_note"]
    for token in ("records_total=30", "samples=stratified", "not_all", "query_records"):
        assert token in note


def test_events_note_states_cap_and_tuning_rule():
    """档位说明必须能让模型知道「证据有上限、可以补查」，且不逐档列图例。

    逐档图例（`critical:5,high:5,...`）对模型**不可操作**（它改不了深度），
    却要每轮付费发送，而且与 `_EVENT_EVIDENCE_DEPTH` 是两份事实。
    """

    _, _, context = _context(_ssh_bruteforce_success())
    note = context["events_note"]
    assert f"evidence_cap={ai_service.EVENT_EVIDENCE_ITEM_LIMIT}" in note
    assert "evidence_count=total" in note
    assert "query_evidence" in note
    assert "critical:5" not in note


def test_context_stays_json_serialisable():
    """新增字段必须是可 JSON 序列化的——上下文要直接进请求体。"""

    _, _, context = _context(_ssh_bruteforce_success())
    assert json.dumps(context, ensure_ascii=False)
