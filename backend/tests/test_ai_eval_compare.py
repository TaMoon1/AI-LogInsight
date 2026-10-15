"""多模型 / 多 Prompt 对比与评测产物（P2 ③）。

两条最容易写错的口径，这里都用测试钉死：

1. **缺账单显示 `n/a` 而不是 0**。「服务端没回传用量」和「用量为零」是两件事，
   填 0 会让成本对比得出反向结论——报告说 A 比 B 便宜，其实只是 A 没测到。
2. **引用覆盖率只在可评估用例上求平均**。不可评估（无行为）的用例不参与，也不当 0，
   否则「什么都没输出」会把平均值拉低成假象。

对比表的价值在于**暴露分歧**：同一份日志上两个模型给出不同风险等级，
比「通过率都是满分」信息量大得多。因此这里也用反向验证确认它真的会标出分歧。
"""

from __future__ import annotations

import json
import time

import pytest

from app.models import AiBehavior
from app.services import ai as ai_service
from app.services.ai_eval import (
    AiCase,
    CaseOutcome,
    EvalReport,
    Finding,
    RunResult,
    build_artifact,
    evaluate,
    render_comparison,
    write_artifact,
)

# --------------------------------------------------------------------------
# 构造用例与判据
# --------------------------------------------------------------------------

LOG = '203.0.113.10 - - [29/Sep/2026:09:10:00 +0800] "GET /.env HTTP/1.1" 403 12 "-" "curl/8.0"'


def _case(name: str = "c1", *, expect: dict | None = None) -> AiCase:
    return AiCase(
        name=name,
        family="测试家族",
        note="",
        filename=f"{name}.log",
        log=LOG,
        expect=expect or {},
    )


def _judgement(
    risk_level: str = "medium",
    confidence: float = 0.5,
    *,
    behaviors: int = 1,
    evidence_ids: list[str] | None = None,
    usage: dict | None = None,
    dropped: list[str] | None = None,
) -> dict:
    """构造一份研判结果。默认第一条行为带证据引用，其余不带。"""

    refs = evidence_ids if evidence_ids is not None else ["evidence-1"]
    items = [
        AiBehavior(
            type="t",
            name=f"行为{index}",
            confidence=confidence,
            evidence=["raw"],
            evidence_ids=refs if index == 0 else [],
            analysis="分析",
        )
        for index in range(behaviors)
    ]
    trace = []
    if usage is not None:
        trace.append({"tool": "usage", "source": "auto", "summary": "", "usage": usage})
    return {
        "risk_level": risk_level,
        "confidence": confidence,
        "conclusion": "结论",
        "behaviors": items,
        "tool_trace": trace,
        "dropped_evidence_ids": dropped or [],
        "unsupported_claims": [],
    }


def _judge(payload: dict, *, sleep: float = 0.0, seen_prompts: list[str] | None = None):
    def judge(case, result, records):  # noqa: ANN001
        if seen_prompts is not None:
            seen_prompts.append(ai_service.SYSTEM_PROMPT)
        if sleep:
            time.sleep(sleep)
        return payload, json.dumps(
            {
                "risk_level": payload["risk_level"],
                "confidence": payload["confidence"],
                "summary": "结论",
            },
            ensure_ascii=False,
        )

    return judge


def _run(label: str, payload: dict, cases: list[AiCase] | None = None, **kwargs) -> RunResult:
    return RunResult(
        label=label,
        report=evaluate(cases or [_case()], _judge(payload, **kwargs)),
        conditions={"判据": "测试"},
    )


# --------------------------------------------------------------------------
# 遥测：耗时 / 用量 / 证据引用
# --------------------------------------------------------------------------


def test_outcome_records_duration_usage_and_evidence_refs():
    report = evaluate(
        [_case()],
        _judge(_judgement(usage={"prompt_tokens": 120, "completion_tokens": 30})),
    )

    outcome = report.outcomes[0]
    assert outcome.duration_ms > 0
    assert outcome.usage == {"prompt_tokens": 120, "completion_tokens": 30}
    assert outcome.evidence_refs == ["evidence-1"]


def test_duration_measures_only_the_judge_call():
    """耗时只计判据本身，不含解析与规则分析。

    解析和规则分析与模型无关，混进来会让不同模型的耗时不可比——
    评测的意义就是比模型，口径一混结论就废了。
    """

    report = evaluate([_case()], _judge(_judgement(), sleep=0.05))

    assert report.outcomes[0].duration_ms >= 50


def test_missing_usage_stays_empty_not_zero():
    report = evaluate([_case()], _judge(_judgement(usage=None)))

    assert report.outcomes[0].usage == {}
    assert RunResult(label="x", report=report).tokens is None


def test_dropped_evidence_ids_are_recorded():
    report = evaluate([_case()], _judge(_judgement(dropped=["ghost-1"])))

    assert report.outcomes[0].dropped_evidence_ids == ["ghost-1"]


def test_failed_judge_still_records_duration():
    """判据抛错时也要记耗时——失败本身是有信息量的观测。"""

    def exploding(case, result, records):  # noqa: ANN001
        time.sleep(0.03)
        raise RuntimeError("模型挂了")

    report = evaluate([_case()], exploding)

    assert report.outcomes[0].duration_ms >= 30
    assert report.outcomes[0].usage == {}
    assert not report.outcomes[0].passed


# --------------------------------------------------------------------------
# RunResult 聚合口径
# --------------------------------------------------------------------------


def test_tokens_are_none_when_no_case_has_a_bill():
    """一条账单都没有时返回 None。**不返回 0**。"""

    run = _run("no-billing", _judgement(usage=None))

    assert run.tokens is None
    assert run.billed_cases == 0


def test_tokens_sum_only_billed_cases_and_report_coverage():
    cases = [_case("a"), _case("b")]
    answers = iter([_judgement(usage={"prompt_tokens": 100, "completion_tokens": 0}), _judgement(usage=None)])

    def judge(case, result, records):  # noqa: ANN001
        payload = next(answers)
        return payload, json.dumps({"risk_level": payload["risk_level"]})

    run = RunResult(label="mixed", report=evaluate(cases, judge))

    assert run.tokens == 100
    # 覆盖率要跟着一起给出，否则「总 tokens」在两个运行间不可比
    assert run.billed_cases == 1
    assert run.total == 2


def test_citation_coverage_averages_only_evaluable_cases():
    """不可评估的用例（无行为）不参与平均，也不当 0。"""

    cases = [_case("with-behavior"), _case("without-behavior")]
    answers = iter([_judgement(behaviors=1), _judgement(behaviors=0)])

    def judge(case, result, records):  # noqa: ANN001
        payload = next(answers)
        return payload, json.dumps({"risk_level": payload["risk_level"]})

    run = RunResult(label="mixed", report=evaluate(cases, judge))

    # 只有第一条可评估，其覆盖率为 100%；若把第二条当 0 就会变成 50%
    assert run.citation_coverage == 1.0


def test_citation_coverage_is_none_when_nothing_is_evaluable():
    run = _run("all-empty", _judgement(behaviors=0))

    assert run.citation_coverage is None


# --------------------------------------------------------------------------
# 对比表
# --------------------------------------------------------------------------


def test_comparison_lists_every_run():
    runs = [_run("模型A", _judgement()), _run("模型B", _judgement())]

    table = render_comparison(runs, {"判据": "测试"})

    assert "模型A" in table
    assert "模型B" in table
    assert "| 运行 | 通过 |" in table


def test_comparison_marks_risk_level_disagreement():
    """反向验证：两个运行给出不同风险等级时必须标「分歧」。

    这张表存在的意义就是暴露分歧；如果它对差异视而不见，就只是个装饰。
    """

    runs = [
        _run("模型A", _judgement(risk_level="high")),
        _run("模型B", _judgement(risk_level="info")),
    ]

    table = render_comparison(runs)

    assert "**分歧**" in table
    assert "风险等级不一致" in table


def test_comparison_reports_agreement_when_levels_match():
    runs = [_run("模型A", _judgement(risk_level="medium")), _run("模型B", _judgement(risk_level="medium"))]

    table = render_comparison(runs)

    assert "**分歧**" not in table
    assert "一致" in table


def test_comparison_shows_na_for_missing_billing():
    runs = [_run("无账单", _judgement(usage=None))]

    table = render_comparison(runs)

    assert "| n/a |" in table
    assert "| 0/1 |" in table


def test_comparison_marks_gate_failure():
    failing = _case("failing", expect={"risk_levels": ["info"]})
    runs = [_run("模型A", _judgement(risk_level="high"), cases=[failing])]

    table = render_comparison(runs)

    assert "**失败**" in table
    assert "0/1" in table


def test_comparison_handles_empty_run_list():
    assert "没有任何运行结果" in render_comparison([])


def test_comparison_handles_single_run():
    assert "模型A" in render_comparison([_run("模型A", _judgement())])


# --------------------------------------------------------------------------
# 产物
# --------------------------------------------------------------------------


def test_artifact_contains_evidence_refs_duration_and_usage():
    run = _run(
        "模型A",
        _judgement(usage={"prompt_tokens": 100, "completion_tokens": 20}),
        sleep=0.02,
    )

    artifact = build_artifact([run], generated_at="2026-09-30T00:00:00")
    case = artifact["runs"][0]["cases"][0]

    assert artifact["generated_at"] == "2026-09-30T00:00:00"
    assert case["evidence_refs"] == ["evidence-1"]
    # 用有明确耗时的判据：替身太快的话，四舍五入会把真实测量塌成 0.0，
    # 看起来像「没测」，测出来的东西却成了没测到。
    assert case["duration_ms"] >= 20
    assert case["usage"] == {"prompt_tokens": 100, "completion_tokens": 20}


def test_artifact_writes_null_for_missing_usage_not_zero():
    """缺账单在产物里写 `null`。写 0 会让后续聚合把「没测到」算成「零成本」。"""

    run = _run("无账单", _judgement(usage=None))

    artifact = build_artifact([run], generated_at="2026-09-30T00:00:00")

    assert artifact["runs"][0]["cases"][0]["usage"] is None
    assert artifact["runs"][0]["summary"]["tokens"] is None


def test_artifact_summary_has_no_float_noise():
    run = _run("模型A", _judgement(confidence=0.44))

    summary = build_artifact([run], generated_at="x")["runs"][0]["summary"]

    assert summary["mean_confidence"] == 0.44


def test_artifact_is_json_serialisable_and_round_trips(tmp_path):
    runs = [_run("模型A", _judgement(usage={"prompt_tokens": 1}))]

    path = write_artifact(tmp_path / "nested" / "art.json", runs)
    reloaded = json.loads(path.read_text(encoding="utf-8"))

    assert reloaded["runs"][0]["label"] == "模型A"
    assert reloaded["runs"][0]["cases"][0]["name"] == "c1"


def test_artifact_keeps_gating_failures_for_triage():
    failing = _case("failing", expect={"risk_levels": ["info"]})
    run = _run("模型A", _judgement(risk_level="high"), cases=[failing])

    case = build_artifact([run], generated_at="x")["runs"][0]["cases"][0]

    assert "risk_level_acceptable" in case["gating_failures"]


# --------------------------------------------------------------------------
# Prompt 变体
# --------------------------------------------------------------------------


def test_prompt_variant_actually_replaces_the_system_prompt():
    """Prompt 变体必须真的换掉系统提示，而不是只换个标签。

    `SYSTEM_PROMPT` 是调用时读取的模块全局，所以 patch 模块属性是有效的——
    这条测试证明「多 Prompt 对比」不是在对比同一个 Prompt 的两个名字。
    """

    seen: list[str] = []
    original = ai_service.SYSTEM_PROMPT
    try:
        from unittest.mock import patch

        with patch.object(ai_service, "SYSTEM_PROMPT", "变体提示词"):
            evaluate([_case()], _judge(_judgement(), seen_prompts=seen))
    finally:
        ai_service.SYSTEM_PROMPT = original

    assert seen == ["变体提示词"]


# --------------------------------------------------------------------------
# 直接构造 CaseOutcome 的向后兼容
# --------------------------------------------------------------------------


def test_case_outcome_telemetry_fields_have_defaults():
    """新增字段必须有默认值，否则既有构造点会全炸。"""

    outcome = CaseOutcome(
        name="n",
        family="f",
        note="",
        suspicious_expected=False,
        suspicious_actual=False,
        risk_level="info",
        confidence=0.0,
        behavior_count=0,
        citation_coverage=None,
        unsupported_claims=[],
        findings=[Finding("x", True, "d")],
    )

    assert outcome.duration_ms == 0.0
    assert outcome.usage == {}
    assert outcome.evidence_refs == []
    assert outcome.dropped_evidence_ids == []
