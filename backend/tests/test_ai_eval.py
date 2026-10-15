"""AI 评测检查器与样本集的门禁测试。

重点不是「好结论能通过」，而是**坏结论一定被拦住**——一个永远返回通过的门禁
比没有门禁更糟，因为它会让人误以为有安全网。
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.models import AiBehavior
from app.services import ai as ai_service
from app.services.ai_eval import (
    AiCase,
    CaseOutcome,
    EvalReport,
    Finding,
    check_judgement,
    evaluate,
    load_cases,
    render_markdown,
)

CASES = load_cases()

#: 完整集的确定性报告只算一次。它会跑两遍 3000 行的规模用例，重复计算纯属浪费——
#: 两条测试都要看它，缓存后一致性断言几乎是免费的。
_FULL_REPORT = None


def _full_report():
    global _FULL_REPORT
    if _FULL_REPORT is None:
        from scripts.eval_ai import make_deterministic_judge

        _FULL_REPORT = evaluate(CASES, make_deterministic_judge())
    return _FULL_REPORT


def _case(**expect) -> AiCase:
    return AiCase(
        name="unit-case",
        family="单元测试",
        note="",
        filename="access.log",
        log="203.0.113.1 - - [29/Sep/2026:09:00:00 +0800] \"GET /health HTTP/1.1\" 200 12 \"-\" \"Mozilla/5.0\"",
        expect=expect,
    )


def _behaviour(*evidence_ids: str) -> AiBehavior:
    return AiBehavior(
        type="test_behavior",
        name="测试行为",
        confidence=0.8,
        evidence=["日志中存在对应记录"],
        evidence_ids=list(evidence_ids),
        analysis="依据本次日志中的结构化事件判断。",
    )


def _judgement(**overrides) -> dict:
    base = {
        "risk_level": "medium",
        "confidence": 0.8,
        "conclusion": "存在 203.0.113.1 的异常探测行为。",
        "recommendations": [],
        "behaviors": [_behaviour("evidence-record-1")],
        "structured_verdict": None,
        "dropped_evidence_ids": [],
        "unsupported_claims": [],
    }
    base.update(overrides)
    return base


def _findings(judgement: dict, case: AiCase, raw: str | None = None) -> dict[str, Finding]:
    return {item.check: item for item in check_judgement(judgement, case, raw_output=raw)}


# --------------------------------------------------------------------------
# 样本集完整性
# --------------------------------------------------------------------------


def test_dataset_loads_with_expected_coverage():
    """11 条用例覆盖路线图要求的 9 类场景。"""

    names = {case.name for case in CASES}
    assert len(CASES) == 11
    assert {
        "normal-health-check",  # 正常
        "obvious-sensitive-path",  # 明显异常
        "insufficient-evidence",  # 证据不足
        "correlated-failures-then-success",  # 多事件关联
        "benign-monitor-polling",  # 误报
        "no-timestamp-but-visible-anomaly",  # 无时间戳
        "missing-status-code",  # 缺失字段
        "truncated-mid-line",  # 截断
        "one-anomaly-among-thousands",  # 大日志
    } <= names


def test_every_case_parses_without_silent_loss():
    """除显式声明 `unparseable` 的用例外，记录数必须与日志行数一致。

    静默解析失败会让期望值失去意义——我曾因为模板里生成了非法 IP
    （`198.51.100.3000`）导致 3000 行只解析出 999 条，若没有这条断言就会
    带着坏数据下结论。
    """

    from app.services.ai_eval import build_case_context

    for case in CASES:
        _, records = build_case_context(case)
        lines = len(case.log.splitlines())
        if case.unparseable:
            assert not records, f"{case.name} 声明了 unparseable，却解析出 {len(records)} 条记录"
            continue
        assert len(records) == lines, f"{case.name}: {lines} 行只解析出 {len(records)} 条记录"


def test_every_case_declares_expectation():
    """没有期望的用例等于没标——不允许存在。"""

    for case in CASES:
        assert case.expect, f"{case.name} 未声明 expect"
        assert "suspicious" in case.expect, f"{case.name} 未声明 suspicious"


# --------------------------------------------------------------------------
# 反向验证：坏结论必须被拦住
# --------------------------------------------------------------------------


def test_invalid_json_fails_gate():
    case = _case(suspicious=True)
    findings = _findings(_judgement(), case, raw="这不是 JSON")
    assert not findings["json_valid"].passed
    assert findings["json_valid"].gating


def test_json_array_is_not_accepted():
    """顶层是数组而非对象也算非法——下游全部按对象取键。"""

    case = _case(suspicious=True)
    findings = _findings(_judgement(), case, raw='["a", "b"]')
    assert not findings["json_valid"].passed


def test_bogus_evidence_id_fails_gate():
    """模型引用了日志中不存在的证据编号 → 门禁失败。"""

    case = _case(suspicious=True, risk_levels=["medium"], min_behaviors=1)
    findings = _findings(_judgement(dropped_evidence_ids=["evidence-record-999"]), case)
    assert not findings["evidence_exists"].passed
    assert findings["evidence_exists"].gating


def test_forbidden_risk_level_fails_gate():
    """严重风险等级错误：把正常行为报成 high → 门禁失败。"""

    case = _case(suspicious=False, risk_levels=["info", "low"], forbid_risk_levels=["high", "critical"])
    findings = _findings(
        _judgement(risk_level="high", behaviors=[_behaviour("evidence-record-1")]), case
    )
    assert not findings["risk_level_severe"].passed
    assert findings["risk_level_severe"].gating


def test_missing_recall_fails_gate():
    """异常用例该报的没报（漏报）必须失败。"""

    case = _case(suspicious=True, min_behaviors=1, risk_levels=["high"])
    findings = _findings(_judgement(behaviors=[]), case)
    assert not findings["behavior_recall"].passed
    assert findings["behavior_recall"].gating


def test_false_alarm_on_benign_case_fails_gate():
    """不该报的报了（误报）也必须失败——由风险等级判定，不看行为条数。"""

    case = _case(suspicious=False, risk_levels=["info", "low"], forbid_risk_levels=["high", "critical"])
    findings = _findings(_judgement(risk_level="high"), case)
    assert not findings["risk_level_acceptable"].passed
    assert not findings["risk_level_severe"].passed


def test_low_confidence_deviation_on_benign_log_is_not_a_false_alarm():
    """关键回归：正常日志上的一条低置信度「行为偏离」不算误报。

    这条测试来自真实模型输出的纠正——模型对单条正常健康检查给出了
    `risk_level=info` / `confidence=0.35`，并附一条 `behavior_deviation`
    （明说「属统计性偏离而非攻击特征」）。这正是本项目 P1-16 设计的行为偏离。
    早期版本按行为条数判定可疑，会在这种情况下假失败。
    """

    case = _case(suspicious=False, risk_levels=["info", "low"], forbid_risk_levels=["high", "critical"])
    judgement = _judgement(
        risk_level="info",
        confidence=0.35,
        behaviors=[
            AiBehavior(
                type="behavior_deviation",
                name="低频来源地址访问健康检查路径",
                confidence=0.3,
                evidence=["日志中存在对应记录"],
                evidence_ids=["evidence-record-1"],
                analysis="属统计性偏离而非攻击特征，无法据此确认恶意。",
            )
        ],
    )
    outcome = CaseOutcome(
        name=case.name,
        family=case.family,
        note="",
        suspicious_expected=False,
        suspicious_actual=True,
        risk_level="info",
        confidence=0.35,
        behavior_count=1,
        citation_coverage=1.0,
        unsupported_claims=[],
        findings=check_judgement(judgement, case),
    )
    assert outcome.passed, [f.detail for f in outcome.gating_failures]


def test_benign_case_annotations_are_self_consistent():
    """数据集自洽：标了 suspicious=false 的用例，可接受等级不得包含 high/critical。"""

    for case in CASES:
        if case.suspicious:
            continue
        assert not (set(case.risk_levels) & {"high", "critical"}), (
            f"{case.name} 标注自相矛盾：suspicious=false 却接受 {case.risk_levels}"
        )


def test_anomalous_case_annotations_are_self_consistent():
    """数据集自洽：标了 suspicious=true 的用例，可接受等级不得只有 info/low。"""

    for case in CASES:
        if not case.suspicious:
            continue
        assert set(case.risk_levels) - {"info", "low"}, (
            f"{case.name} 标注自相矛盾：suspicious=true 却只接受 {case.risk_levels}"
        )


def test_risk_level_outside_acceptable_set_fails_gate():
    case = _case(suspicious=True, risk_levels=["high"], min_behaviors=1)
    findings = _findings(_judgement(risk_level="low"), case)
    assert not findings["risk_level_acceptable"].passed


def test_missing_evidence_keyword_fails_gate():
    """结论没提到标注的关键实体 → 召回不足，失败。"""

    case = _case(suspicious=True, risk_levels=["medium"], min_behaviors=1, evidence_keywords=["203.0.113.99"])
    findings = _findings(_judgement(), case)
    assert not findings["evidence_keywords"].passed


def test_invalid_risk_level_value_is_flagged():
    case = _case(suspicious=True, min_behaviors=1)
    findings = _findings(_judgement(risk_level="catastrophic"), case)
    assert not findings["risk_level_valid"].passed


def test_unsupported_claims_flagged():
    case = _case(suspicious=True, min_behaviors=1, risk_levels=["medium"])
    findings = _findings(_judgement(unsupported_claims=["结论引用了日志中不存在的 IP：10.9.9.9"]), case)
    assert not findings["grounding"].passed


# --------------------------------------------------------------------------
# 关键原则：不可评估 ≠ 通过
# --------------------------------------------------------------------------


def test_zero_behaviors_is_unevaluable_not_perfect():
    """没有行为可引用证据时，覆盖率必须是 None（不可评估），不能是 1.0。

    否则「什么都没输出」会被当成满分——这正是假阳性最常见的来源。
    """

    case = _case(suspicious=False, risk_levels=["info", "low"])
    outcome = CaseOutcome(
        name=case.name,
        family=case.family,
        note="",
        suspicious_expected=False,
        suspicious_actual=False,
        risk_level="info",
        confidence=0.2,
        behavior_count=0,
        citation_coverage=None,
        unsupported_claims=[],
        findings=check_judgement(_judgement(risk_level="info", confidence=0.2, behaviors=[]), case),
    )
    assert outcome.citation_coverage is None
    assert outcome.passed

    markdown = render_markdown(EvalReport(outcomes=[outcome]))
    assert "n/a" in markdown
    assert "不可评估" in markdown


def test_partial_citation_coverage_is_reported():
    """一半行为有引用 → 覆盖率 50%，不是 100%。"""

    case = _case(suspicious=True, min_behaviors=1, risk_levels=["medium"])
    judgement = _judgement(behaviors=[_behaviour("evidence-record-1"), _behaviour()])
    findings = _findings(judgement, case)
    assert "50%" in findings["citation_coverage"].detail


# --------------------------------------------------------------------------
# 门禁语义
# --------------------------------------------------------------------------


def test_non_gating_finding_does_not_block_release():
    """非门禁项（如覆盖率、无依据声明）只记录，不单独阻断。"""

    case = _case(suspicious=True, min_behaviors=1, risk_levels=["medium"])
    judgement = _judgement(behaviors=[_behaviour()], unsupported_claims=["凭空断言"])
    findings = check_judgement(judgement, case)
    assert not next(f for f in findings if f.check == "citation_coverage").passed
    assert not next(f for f in findings if f.check == "grounding").passed
    assert all(not f.gating for f in findings if f.check in {"citation_coverage", "grounding"})

    outcome = CaseOutcome(
        name="x",
        family="f",
        note="",
        suspicious_expected=True,
        suspicious_actual=True,
        risk_level="medium",
        confidence=0.8,
        behavior_count=1,
        citation_coverage=0.0,
        unsupported_claims=["凭空断言"],
        findings=findings,
    )
    assert outcome.passed, "非门禁项不应导致用例失败"


def test_deterministic_baseline_passes_all_cases():
    """确定性基线（规则结论换个措辞）应当全过；不过说明标注或检查器有问题。"""

    report = _full_report()
    assert len(report.outcomes) == len(CASES)
    assert not report.gate_failed, [o.name for o in report.failed]


# --------------------------------------------------------------------------
# 最小回归集（smoke）：Prompt / AI 代码一改就该跑，随 pytest 自动执行
# --------------------------------------------------------------------------


def test_smoke_set_runs_automatically_and_passes():
    """最小回归集随 pytest 自动执行——这是「自动执行最小回归集」的落点。

    项目没有 CI 配置，pytest 就是唯一的门禁机制，所以自动执行必须挂在测试里，
    而不是指望有人记得手动跑脚本。
    """

    from scripts.eval_ai import make_deterministic_judge

    smoke = load_cases(smoke_only=True)
    assert smoke, "最小回归集不能为空"
    report = evaluate(smoke, make_deterministic_judge())
    assert not report.gate_failed, [o.name for o in report.failed]


def test_smoke_set_is_a_strict_subset():
    """最小回归集必须小于完整集，否则「分层」没有意义。"""

    smoke = load_cases(smoke_only=True)
    assert 0 < len(smoke) < len(CASES), f"最小回归集 {len(smoke)} 条 / 完整集 {len(CASES)} 条"


def test_smoke_set_excludes_scale_cases():
    """规模用例不进最小回归集——3000 行体量大，属于完整评测。"""

    smoke_names = {case.name for case in load_cases(smoke_only=True)}
    assert "one-anomaly-among-thousands" not in smoke_names
    assert "all-benign-at-scale" not in smoke_names


def test_smoke_set_stays_small():
    """守卫：最小回归集必须保持小。

    否则有人把每条用例都标上 `smoke: true`，分层就悄悄失效了——
    而失效的方式是「变慢」而不是「报错」，没人会注意到。
    """

    smoke = load_cases(smoke_only=True)
    assert len(smoke) <= 8, f"最小回归集已膨胀到 {len(smoke)} 条，分层失去意义"


def test_smoke_set_covers_every_core_failure_mode():
    """最小回归集必须覆盖各类核心失败模式，否则回归价值不足。

    漏掉任何一类，对应的退化就会在无人察觉的情况下溜过去。
    """

    smoke_names = {case.name for case in load_cases(smoke_only=True)}
    assert {
        "normal-health-check",  # 误报
        "obvious-sensitive-path",  # 漏报
        "insufficient-evidence",  # 无证据时编造
        "correlated-failures-then-success",  # 多事件关联
        "truncated-mid-line",  # 边界/截断
    } <= smoke_names


def test_smoke_and_full_agree_on_smoke_cases():
    """同一批用例在最小集与完整集下的结论必须一致。

    否则「跑 smoke 过了」就不能作为「完整集也会过」的证据。
    完整集结果取自缓存，这条断言几乎不额外花时间。
    """

    smoke_names = {case.name for case in load_cases(smoke_only=True)}
    full = {o.name: o for o in _full_report().outcomes}
    for name in smoke_names:
        assert full[name].passed, f"{name} 在完整集中失败，但在最小集中通过"


def test_judge_exception_is_recorded_not_swallowed():
    """单条用例研判抛异常必须记为失败，不能被吞掉当成通过。"""

    def boom(_case, _result, _records):
        raise RuntimeError("模型超时")

    report = evaluate(CASES[:2], boom)
    assert len(report.outcomes) == 2
    assert report.gate_failed
    assert all("模型超时" in f.detail for o in report.outcomes for f in o.gating_failures)


# --------------------------------------------------------------------------
# 可观测性：静默丢弃的证据编号
# --------------------------------------------------------------------------


def test_dropped_evidence_ids_are_observable_end_to_end():
    """模型引用不存在的证据编号时，必须留下可观测痕迹。

    此前 `_normalize_evidence_ids` 静默丢弃，导致「引用了不存在的证据」完全不可见。
    """

    from app.services.ai_eval import build_case_context

    case = next(c for c in CASES if c.name == "obvious-sensitive-path")
    result, records = build_case_context(case)
    answer = {
        "risk_level": "medium",
        "confidence": 0.8,
        "summary": "存在敏感路径探测。",
        "behaviors": [
            {
                "type": "probe",
                "name": "敏感路径探测",
                "confidence": 0.8,
                "evidence": ["日志中存在 /.env 探测"],
                "evidence_ids": ["evidence-record-1", "evidence-record-999"],
                "analysis": "URL 命中敏感路径。",
            }
        ],
        "recommendations": [],
    }

    class FakeProvider:
        supports_tools = False
        last_usage = {"rounds": 1, "prompt_tokens": 10, "completion_tokens": 5}

        def complete(self, system_prompt, context, on_delta=None):
            return json.dumps(answer, ensure_ascii=False)

    from unittest.mock import patch

    with (
        patch.object(ai_service, "_create_provider", lambda: FakeProvider()),
        patch.object(ai_service, "_run_auto_tools", lambda _r, _rec: ({}, [])),
    ):
        judgement = ai_service.request_ai_judgement(result, records)

    assert judgement["dropped_evidence_ids"] == ["evidence-record-999"]
    # 行为本身仍然保留合法引用（运行时依旧宽容），但痕迹可查
    assert judgement["behaviors"][0].evidence_ids == ["evidence-record-1"]

    findings = {f.check: f for f in check_judgement(judgement, case, raw_output=json.dumps(answer))}
    assert not findings["evidence_exists"].passed


def test_valid_evidence_ids_are_not_reported_as_dropped():
    """合法引用不得被误报为丢弃——否则门禁会天天假失败。"""

    from app.services.ai_eval import build_case_context

    case = next(c for c in CASES if c.name == "obvious-sensitive-path")
    result, records = build_case_context(case)
    answer = {
        "risk_level": "medium",
        "confidence": 0.8,
        "summary": "存在敏感路径探测。",
        "behaviors": [
            {
                "type": "probe",
                "name": "敏感路径探测",
                "confidence": 0.8,
                "evidence": ["日志中存在 /.env 探测"],
                "evidence_ids": ["evidence-record-1"],
                "analysis": "URL 命中敏感路径。",
            }
        ],
        "recommendations": [],
    }

    class FakeProvider:
        supports_tools = False
        last_usage = {"rounds": 1, "prompt_tokens": 10, "completion_tokens": 5}

        def complete(self, system_prompt, context, on_delta=None):
            return json.dumps(answer, ensure_ascii=False)

    from unittest.mock import patch

    with (
        patch.object(ai_service, "_create_provider", lambda: FakeProvider()),
        patch.object(ai_service, "_run_auto_tools", lambda _r, _rec: ({}, [])),
    ):
        judgement = ai_service.request_ai_judgement(result, records)

    assert judgement["dropped_evidence_ids"] == []


# --------------------------------------------------------------------------
# 报告渲染
# --------------------------------------------------------------------------


def test_report_lists_gating_failures():
    case = _case(suspicious=True, min_behaviors=1, risk_levels=["high"])
    outcome = CaseOutcome(
        name="failing-case",
        family="单元测试",
        note="这条应该失败",
        suspicious_expected=True,
        suspicious_actual=False,
        risk_level="info",
        confidence=0.1,
        behavior_count=0,
        citation_coverage=None,
        unsupported_claims=[],
        findings=check_judgement(_judgement(behaviors=[]), case),
    )
    # 用真实的 EvalReport 而不是鸭子类型替身：报告渲染现在要读
    # `confusion` / `accuracy` 等派生属性，替身缺一个就炸——而炸的是测试的
    # 假设，不是被测代码。
    report = EvalReport(outcomes=[outcome])
    markdown = render_markdown(report)
    assert "failing-case" in markdown
    assert "behavior_recall" in markdown
    assert "门禁：**失败**" in markdown
