"""成本 × 质量联合指标与 Token 回归门禁（路线图 P3 ④⑤⑥）。

三条口径用测试钉死，它们都是「看起来对、实际会得出反向结论」的坑：

1. **可疑与否看 `risk_level`，不看行为条数**。本项目有 P1-16「行为偏离」——
   正常日志上会合法地产生低置信度提示（`risk_level=info`）。按条数判定会把
   它算成误报，于是「准确率」这个新指标一开始就带着已知偏差。
2. **缺样本侧时比率是 `None` 不是 0**。样本集里没有正常用例时，误报率若返回 0，
   报告会显示「误报率 0%，完美」——而真相是根本没测。
3. **Token 下降不等于优化成功**。只降 token 却牺牲准确率必须判失败，
   否则门禁会奖励「把上下文砍到模型看不见证据」这种退化。
"""

from __future__ import annotations

import json

from app.services.ai_eval import (
    SUSPICIOUS_LEVELS,
    CaseOutcome,
    EvalReport,
    RunResult,
    build_artifact,
    compare_gate_metrics,
    load_artifact,
    metric_row,
    render_comparison,
    write_artifact,
)

# --------------------------------------------------------------------------
# 构造工具
# --------------------------------------------------------------------------


def _outcome(
    name: str = "c1",
    *,
    suspicious_expected: bool = True,
    risk_level: str = "medium",
    metrics: dict | None = None,
) -> CaseOutcome:
    """构造一条结局。`suspicious_actual` 按 `risk_level` 推导，与真实管线一致。"""

    return CaseOutcome(
        name=name,
        family="测试家族",
        note="",
        suspicious_expected=suspicious_expected,
        suspicious_actual=risk_level in SUSPICIOUS_LEVELS,
        risk_level=risk_level,
        confidence=0.5,
        behavior_count=1,
        citation_coverage=1.0,
        unsupported_claims=[],
        findings=[],
        metrics=metrics or {},
    )


def _metrics(
    *,
    tokens: int | None = 1000,
    first_round: int | None = 400,
    context_bytes: int | None = 20000,
    evidence_sent: int | None = 10,
    cost: float | None = None,
) -> dict:
    """构造一份 P3 指标。任一项传 `None` 表示**该指标没记录**（不是零）。"""

    payload: dict = {"tokens": {}, "context": {}, "cost": {"estimated": cost, "note": "测试"}}
    for key, value in (("total", tokens), ("first_round", first_round)):
        if value is not None:
            payload["tokens"][key] = value
    for key, value in (("bytes", context_bytes), ("evidence_sent", evidence_sent)):
        if value is not None:
            payload["context"][key] = value
    return payload


def _run(label: str, outcomes: list[CaseOutcome]) -> RunResult:
    report = EvalReport()
    report.outcomes.extend(outcomes)
    return RunResult(label=label, report=report, conditions={})


# --------------------------------------------------------------------------
# ④ 可疑判定的口径：只看 risk_level
# --------------------------------------------------------------------------


def test_behavior_without_risk_escalation_is_not_suspicious():
    """P1-16 行为偏离：正常日志上有行为，但 risk_level=info → 不算可疑。"""

    outcome = _outcome(suspicious_expected=False, risk_level="info")
    assert outcome.behavior_count == 1
    assert outcome.judges_suspicious is False
    assert outcome.correct is True


def test_suspicious_levels_lower_bound_is_medium():
    assert SUSPICIOUS_LEVELS == {"medium", "high", "critical"}
    assert _outcome(risk_level="low").judges_suspicious is False
    assert _outcome(risk_level="medium").judges_suspicious is True


def test_judge_failure_is_never_counted_as_correct():
    """判据崩溃时 `risk_level` 为空。若算成「负样本判对了」，
    一次崩溃会在准确率上伪装成一次成功的保守判断。"""

    failed = _outcome(suspicious_expected=False, risk_level="")
    assert failed.correct is False


def test_confusion_matrix_counts_all_four_quadrants():
    run = _run(
        "r",
        [
            _outcome("tp", suspicious_expected=True, risk_level="high"),
            _outcome("fn", suspicious_expected=True, risk_level="info"),
            _outcome("fp", suspicious_expected=False, risk_level="medium"),
            _outcome("tn", suspicious_expected=False, risk_level="info"),
        ],
    )
    assert run.confusion == (1, 1, 1, 1)
    assert run.accuracy == 0.5
    assert run.false_positive_rate == 0.5
    assert run.false_negative_rate == 0.5


def test_accuracy_is_none_without_cases():
    assert _run("empty", []).accuracy is None


def test_false_positive_rate_is_none_without_negatives():
    """没有正常用例时必须返回 None。返回 0 会显示成「误报率完美」。"""

    run = _run("only-positive", [_outcome("p", suspicious_expected=True, risk_level="high")])
    assert run.false_positive_rate is None
    assert run.false_negative_rate == 0.0


def test_false_negative_rate_is_none_without_positives():
    run = _run("only-negative", [_outcome("n", suspicious_expected=False, risk_level="info")])
    assert run.false_negative_rate is None
    assert run.false_positive_rate == 0.0


# --------------------------------------------------------------------------
# 成本：没配置单价 ≠ 成本为零
# --------------------------------------------------------------------------


def test_estimated_cost_is_none_when_no_metrics():
    run = _run("no-metrics", [_outcome(metrics={})])
    assert run.estimated_cost is None


def test_estimated_cost_sums_only_priced_cases():
    run = _run(
        "priced",
        [
            _outcome("a", metrics=_metrics(cost=0.0012)),
            _outcome("b", metrics=_metrics(cost=0.0008)),
            # 未配置单价的用例不参与求和，也不当 0
            _outcome("c", metrics=_metrics(cost=None)),
        ],
    )
    assert run.estimated_cost == 0.002


# --------------------------------------------------------------------------
# ⑤ 门禁指标行：0 与「没记录」必须分得开
# --------------------------------------------------------------------------


def test_metric_row_reports_none_when_metric_absent():
    row = metric_row(_run("absent", [_outcome(metrics=_metrics(tokens=1000, first_round=None))]))
    assert row["tokens_total"] == 1000
    assert row["tokens_first_round"] is None
    assert row["context_bytes"] == 20000


def test_metric_row_keeps_real_zero_distinct_from_missing():
    """指标里真实是 0 时要保留 0，不能被 `sum(...) or None` 压成「没记录」。"""

    row = metric_row(_run("zero", [_outcome(metrics=_metrics(evidence_sent=0))]))
    assert row["evidence_sent"] == 0
    assert row["evidence_sent"] is not None


def test_metric_row_sums_across_cases():
    row = metric_row(
        _run(
            "sum",
            [
                _outcome("a", metrics=_metrics(tokens=100, first_round=40, context_bytes=10, evidence_sent=1)),
                _outcome("b", metrics=_metrics(tokens=200, first_round=60, context_bytes=20, evidence_sent=2)),
            ],
        )
    )
    assert row["tokens_total"] == 300
    assert row["tokens_first_round"] == 100
    assert row["context_bytes"] == 30
    assert row["evidence_sent"] == 3


def test_metric_row_tolerates_malformed_metrics():
    """指标缺失或被写坏时不能炸——门禁本身崩掉比门禁判错更糟。"""

    row = metric_row(_run("malformed", [_outcome(metrics={"tokens": "oops", "context": 3})]))
    assert row["tokens_first_round"] is None
    assert row["context_bytes"] is None


# --------------------------------------------------------------------------
# ⑤ 四条联合判定规则
# --------------------------------------------------------------------------


def _row(tokens: int, accuracy: float, fp: float | None = 0.0) -> dict:
    return {
        "tokens_total": tokens,
        "tokens_first_round": tokens // 2,
        "context_bytes": 1000,
        "evidence_sent": 5,
        "accuracy": accuracy,
        "false_positive_rate": fp,
    }


def test_tokens_up_without_quality_gain_fails():
    findings = compare_gate_metrics(_row(1000, 0.8), _row(1300, 0.8))
    gating = [f for f in findings if f.gating]
    assert gating and not gating[0].passed
    assert "质量未提升" in gating[0].detail


def test_tokens_down_with_quality_loss_fails():
    """只降 token 但准确率掉了 —— 这是退化，不是优化。"""

    findings = compare_gate_metrics(_row(1000, 0.8), _row(600, 0.6))
    gating = [f for f in findings if f.gating]
    assert gating and not gating[0].passed
    assert "拿准确率换的" in gating[0].detail


def test_tokens_down_with_quality_held_passes():
    findings = compare_gate_metrics(_row(1000, 0.8), _row(700, 0.8))
    gating = [f for f in findings if f.gating]
    assert gating and gating[0].passed


def test_tokens_up_with_quality_gain_passes_but_asks_for_review():
    """涨价换到质量提升时通过，但**不自动判定为成功**——值不值由人决定。"""

    findings = compare_gate_metrics(_row(1000, 0.6), _row(1500, 1.0))
    gating = [f for f in findings if f.gating]
    assert gating and gating[0].passed
    assert "人工确认" in gating[0].detail


def test_accuracy_gain_with_worse_false_positives_is_not_an_improvement():
    """准确率涨但误报率变差，对安全产品是净损失，不能算质量提升。"""

    findings = compare_gate_metrics(
        _row(1000, 0.8, fp=0.0), _row(1300, 0.9, fp=0.5)
    )
    gating = [f for f in findings if f.gating]
    assert gating and not gating[0].passed


def test_tokens_within_tolerance_passes():
    findings = compare_gate_metrics(_row(1000, 0.8), _row(1050, 0.8))
    gating = [f for f in findings if f.gating]
    assert gating and gating[0].passed


def test_gate_is_unevaluable_not_passing_when_no_billing():
    """两边都没账单时记为**不可评估**：不计为通过，也不计为失败。"""

    row = _row(1000, 0.8)
    row["tokens_total"] = None
    findings = compare_gate_metrics(row, dict(row))
    gating = [f for f in findings if f.gating]
    assert not gating
    assert any("无法比较成本" in f.detail for f in findings)


def test_composition_finding_surfaces_context_change_at_constant_tokens():
    """token 没变但上下文体量变了也要能被看见——这正是字段白名单/采样/去重
    这类手段生效时的形态。"""

    before = _row(1000, 0.8)
    after = _row(1000, 0.8)
    after["context_bytes"] = 400
    findings = compare_gate_metrics(before, after)
    composition = next(f for f in findings if f.check == "token_composition")
    assert "context_bytes 1000→400" in composition.detail


# --------------------------------------------------------------------------
# ⑥ 报告：成本与质量必须同时出现
# --------------------------------------------------------------------------


def test_comparison_shows_quality_and_cost_together():
    runs = [
        _run("A", [_outcome("c", risk_level="high", metrics=_metrics(cost=0.002))]),
        _run("B", [_outcome("c", risk_level="info", metrics=_metrics(cost=0.001))]),
    ]
    markdown = render_comparison(runs)
    for column in ("准确率", "误报率", "漏报率", "估算成本", "总 tokens"):
        assert column in markdown
    assert "## 结论" in markdown


def test_single_run_verdict_refuses_to_declare_optimization():
    """单次运行没有对照，不能谈「优化」。"""

    markdown = render_comparison([_run("A", [_outcome("c")])])
    assert "无对照基线，不做优化判定" in markdown


def test_single_run_verdict_warns_tokens_are_only_a_proxy():
    """未配置单价时，报告必须明说 tokens 不能当成本结论。"""

    markdown = render_comparison([_run("A", [_outcome("c", metrics=_metrics(cost=None))])])
    assert "只能作为成本代理" in markdown


def test_multi_run_verdict_marks_quality_sacrifice_as_gate_failure():
    """省了 40% 的 token 但正样本被判成 info（漏报）——必须判失败。"""

    runs = [
        _run(
            "base",
            [_outcome("c", suspicious_expected=True, risk_level="high", metrics=_metrics(tokens=1000))],
        ),
        _run(
            "cheap",
            [_outcome("c", suspicious_expected=True, risk_level="info", metrics=_metrics(tokens=600))],
        ),
    ]
    markdown = render_comparison(runs)
    assert "门禁失败" in markdown
    assert "拿准确率换的" in markdown


# --------------------------------------------------------------------------
# ⑤ 基线产物：门禁要能跨轮次比对
# --------------------------------------------------------------------------


def test_artifact_stores_gate_metrics_and_confusion(tmp_path):
    run = _run(
        "A",
        [
            _outcome("tp", suspicious_expected=True, risk_level="high"),
            _outcome("tn", suspicious_expected=False, risk_level="info"),
        ],
    )
    payload = build_artifact([run], generated_at="2026-09-30T00:00:00")
    summary = payload["runs"][0]["summary"]

    assert summary["confusion"] == {"tp": 1, "fp": 0, "tn": 1, "fn": 0}
    assert summary["accuracy"] == 1.0
    assert summary["gate_metrics"]["tokens_total"] == run.tokens


def test_artifact_round_trip_feeds_the_gate(tmp_path):
    """写出的产物能被读回，并直接作为基线驱动门禁。"""

    baseline = _run("A", [_outcome("c", risk_level="high", metrics=_metrics(tokens=1000))])
    path = write_artifact(tmp_path / "base.json", [baseline])
    payload = load_artifact(path)
    stored_row = payload["runs"][0]["summary"]["gate_metrics"]

    worse = _run("A", [_outcome("c", risk_level="info", metrics=_metrics(tokens=1500))])
    findings = compare_gate_metrics(stored_row, metric_row(worse))
    gating = [f for f in findings if f.gating]
    assert gating and not gating[0].passed


def test_artifact_writes_null_for_absent_billing(tmp_path):
    """缺账单写 null，不写 0——0 会让「没测到」看起来像「零成本」。"""

    run = _run("A", [_outcome("c", metrics={})])
    path = write_artifact(tmp_path / "a.json", [run])
    payload = json.loads(path.read_text(encoding="utf-8"))

    assert payload["runs"][0]["summary"]["tokens"] is None
    assert payload["runs"][0]["cases"][0]["usage"] is None
    assert payload["runs"][0]["summary"]["estimated_cost"] is None


def test_gated_metric_names_match_the_metrics_payload():
    """门禁字段名必须与 `ai_metrics.to_payload()` 对得上。

    这是门禁最容易**静默失效**的地方：指标模块把 `context.bytes` 改名成
    `context.size`，`metric_row` 不会报错，只会读到 None，门禁于是从
    「比较上下文体量」退化成「无法比较 → 不计为失败」。改名的人不会看到任何
    失败，除非有这条用例。
    """

    from app.services import ai_metrics
    from app.services.ai_eval import GATED_METRICS

    payload = ai_metrics.build_metrics(
        context={"events": [{"name": "e", "evidence_items": [{"id": "evidence-1"}]}]},
        result=type("R", (), {"events": []})(),
        tool_trace=[
            {
                "tool": "usage",
                "usage": {
                    "prompt_tokens": 300,
                    "completion_tokens": 100,
                    # `by_round` 是**逐轮用量列表**，首轮用于拆出首轮成本。
                    "by_round": [{"prompt_tokens": 200, "completion_tokens": 50}],
                },
            }
        ],
        evidence_referenced=["evidence-1"],
        duration_ms=12.5,
        prices=ai_metrics.PriceTable(),
    ).to_payload()

    row = metric_row(_run("real", [_outcome(metrics=payload)]))
    missing = [name for name, _ in GATED_METRICS if row.get(name) is None]
    # 误报率需要样本集里有正常用例；这里只有一条正样本，不可评估是**正确的**。
    assert missing in ([], ["false_positive_rate"])
    assert row["tokens_total"] == 400
    assert row["context_bytes"] > 0
    assert row["evidence_sent"] == 1
