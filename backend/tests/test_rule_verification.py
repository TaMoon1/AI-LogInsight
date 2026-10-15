"""规则批量验证器（`scripts/verify_sigma_rules.py`）的针对性测试。

只测验证器自己，不跑全量 1778 条导入规则（那要几分钟，且结果随规则库变化）。
覆盖的是开发过程中真实踩过的坑：

① 同一字段上多个 `contains` 必须**同时**成立 —— 早期实现只取其中一段拼候选值，
   于是「CommandLine 必须同时含 A、B、C」这类规则被误判成「条件自相矛盾」。
② `Predicate.matcher` 已经把取反算进去了，验证器不能再套一层 `not negate`，
   否则取反条件会被赋上「必须不等于」的那个值，规则必然不命中 → 误报成缺陷。
③ 复核 `covers()` 时计划里必须有合法的 `log_type`，否则带 logsource 的规则
   全部会栽在 `logsource_ok` 上。
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from verify_sigma_rules import (  # noqa: E402
    _expand,
    _synthesize,
    verify_synthesizable,
)
from app.services.rules_engine import build_rule, evaluate_rule  # noqa: E402


def _rule(**detection) -> object:
    raw = {
        "id": "test.rule",
        "title": "测试规则",
        "level": "high",
        "logsource": {"log_types": ["sysmon"]},
        "detection": detection,
    }
    # 用 builtin 源构造：测试环境（conftest）默认关闭社区规则，
    # 用 "sigma" 会让 rule.enabled 为假，evaluate_rule 直接返回空。
    return build_rule(raw, "builtin")


def _events(rule, plan) -> list:
    return evaluate_rule(rule, _expand(rule, plan.record, plan.records_needed))


def test_single_equals_is_triggerable():
    rule = _rule(where=[{"field": "status", "op": "equals", "value": "1"}])
    plan = _synthesize(rule)
    assert plan.ok, plan.reason
    assert plan.record["status"] == "1"
    assert _events(rule, plan), "合成了记录却产不出事件"


def test_multiple_contains_on_same_field_are_combined():
    """同一字段上多个 contains 是 AND：候选值必须同时含各段，不能只取一段。"""

    rule = _rule(
        where=[
            {"field": "command_line", "op": "contains", "value": "-enc"},
            {"field": "command_line", "op": "contains", "value": "FromBase64String"},
        ]
    )
    plan = _synthesize(rule)
    assert plan.ok, plan.reason
    # ignore_case 默认开启，匹配前两侧都会归一，因此合成值是小写的
    value = plan.record["command_line"].lower()
    assert "-enc" in value and "frombase64string" in value
    assert _events(rule, plan)


def test_startswith_and_endswith_on_same_field():
    rule = _rule(
        where=[
            {"field": "process_image", "op": "startswith", "value": "c:\\windows\\"},
            {"field": "process_image", "op": "endswith", "value": "\\powershell.exe"},
        ]
    )
    plan = _synthesize(rule)
    assert plan.ok, plan.reason
    value = plan.record["process_image"]
    assert value.startswith("c:\\windows\\") and value.endswith("\\powershell.exe")


def test_negated_predicate_is_not_assigned_its_value():
    """取反条件要求「不命中」：绝不能把「必须不等于」的那个值填进去。"""

    rule = _rule(
        where=[
            {"field": "status", "op": "equals", "value": "1"},
            {"field": "status", "op": "equals", "value": "2", "negate": True},
        ]
    )
    plan = _synthesize(rule)
    assert plan.ok, plan.reason
    assert plan.record["status"] != "2"


def test_logsource_gate_is_satisfied_by_synthesis():
    rule = _rule(where=[{"field": "status", "op": "equals", "value": "11"}])
    plan = _synthesize(rule)
    assert plan.ok, plan.reason
    assert plan.record["log_type"] == "sysmon"
    assert rule.covers(plan.record)


def test_contradictory_equals_is_reported_as_unfinished_not_defect():
    """同一字段被要求两个不同取值 → 构造不出样本，归入「无法合成」而不是「疑似缺陷」。"""

    rule = _rule(
        where=[
            {"field": "status", "op": "equals", "value": "1"},
            {"field": "status", "op": "equals", "value": "2"},
        ]
    )
    plan = _synthesize(rule)
    assert not plan.ok
    assert not plan.record

    layer = verify_synthesizable([rule])
    assert layer.triggerable == []
    assert layer.not_triggered == []
    assert len(layer.unfinished) == 1


def test_regex_rule_is_reported_as_unfinished():
    rule = _rule(where=[{"field": "command_line", "op": "regex", "value": "foo.*bar"}])
    plan = _synthesize(rule)
    assert not plan.ok
    assert "regex" in plan.reason


def test_verified_flag_requires_covers_to_pass():
    """「可触发」的判据是端到端产出事件；合成记录本身也必须先过 covers()。"""

    rule = _rule(
        where=[{"field": "target_filename", "op": "endswith", "value": ".scr"}],
    )
    plan = _synthesize(rule)
    assert plan.ok, plan.reason
    assert rule.covers(plan.record)
    assert _events(rule, plan)


@pytest.mark.parametrize("op", ["equals", "in_set", "contains", "startswith", "endswith"])
def test_all_plain_ops_are_synthesizable(op):
    rule = _rule(where=[{"field": "process_image", "op": op, "value": "cmd.exe"}])
    plan = _synthesize(rule)
    assert plan.ok, f"{op}: {plan.reason}"
    assert _events(rule, plan), f"{op} 合成后未产出事件"
