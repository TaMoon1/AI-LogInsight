"""规则库体检门禁：重复规则、冲突规则、压制/升级链断裂与聚合失效。

对应路线图 P5-④。本文件既验证「出厂规则零阻断项」，也逐类构造反例证明**检查真的会响**
——不然门禁只是一句口号。特别是 `test_suppressed_pair_is_not_a_duplicate`：
本轮开发时先踩过这个坑，粗糙的签名把 5 组刻意设计的 `.success` 压制对误报成重复。
"""

from __future__ import annotations

from app.services.rule_health import check_rule_health, detection_signature, render_markdown
from app.services.rules import rule_objects
from app.services.rules_engine import build_rule


def _rule(rule_id: str, **overrides):
    raw = {
        "id": rule_id,
        "title": rule_id,
        "level": "low",
        "logsource": {"log_types": ["ssh"]},
        "detection": {
            "where": [{"field": "source_ip", "op": "exists"}],
            "aggregate": {"group_by": ["source_ip"], "count_gte": 5, "window_seconds": 300},
        },
        **overrides,
    }
    return build_rule(raw, source="builtin")


def test_shipped_rules_have_no_blocking_issues():
    """出厂规则（1852 条）必须零阻断项——这是本轮的直接验收标准。"""

    report = check_rule_health(rule_objects())
    assert report.rule_count >= 1600
    assert report.issues == [], render_markdown(report)


def test_intentional_suppressed_pairs_are_not_flagged_as_duplicates():
    """5 组 `.success` / 基础 规则共享 `where`，但聚合不同且互相压制——不是重复。"""

    report = check_rule_health(rule_objects())
    duplicated = {
        rule_id
        for item in report.issues
        if item.kind == "duplicate_detection"
        for rule_id in item.rules
    }
    for pair in (
        ("ssh.bruteforce", "ssh.bruteforce.success"),
        ("auth.bruteforce", "auth.bruteforce.success"),
        ("rdp.bruteforce", "rdp.bruteforce.success"),
        ("web.auth_bruteforce", "web.auth_bruteforce.success"),
        ("db.bruteforce", "db.bruteforce.success"),
    ):
        assert not (set(pair) & duplicated), f"{pair} 是刻意设计的压制对，不该判为重复"


def test_dangling_suppresses_is_flagged():
    report = check_rule_health([_rule("a", suppresses=["typo.rule"])])
    assert [item.kind for item in report.issues] == ["dangling_reference"]
    assert "typo.rule" in report.issues[0].detail


def test_dangling_upgrade_rule_is_flagged():
    report = check_rule_health([_rule("a", upgrade_rule="missing.rule")])
    assert [item.kind for item in report.issues] == ["dangling_reference"]


def test_self_suppress_is_flagged():
    report = check_rule_health([_rule("a", suppresses=["a"])])
    assert [item.kind for item in report.issues] == ["self_suppress"]


def test_suppress_cycle_is_flagged():
    rules = [_rule("a", suppresses=["b"]), _rule("b", suppresses=["a"])]
    kinds = {item.kind for item in check_rule_health(rules).issues}
    assert "suppress_cycle" in kinds


def test_asymmetric_upgrade_is_flagged():
    """A 声明被 B 升级，B 却没声明压制 A —— 升级链断了一半。"""

    rules = [_rule("a", upgrade_rule="b"), _rule("b")]
    report = check_rule_health(rules)
    assert [item.kind for item in report.issues] == ["asymmetric_upgrade"]


def test_symmetric_upgrade_is_accepted():
    rules = [_rule("a", upgrade_rule="b"), _rule("b", suppresses=["a"])]
    assert check_rule_health(rules).issues == []


def test_duplicate_detection_without_relation_is_flagged():
    rules = [_rule("a"), _rule("b")]
    report = check_rule_health(rules)
    assert [item.kind for item in report.issues] == ["duplicate_detection"]
    assert set(report.issues[0].rules) == {"a", "b"}


def test_duplicate_detection_is_order_insensitive():
    """同一判据换个书写顺序仍是同一条——否则「重复」检查会被顺序绕过。"""

    first = build_rule(
        {
            "id": "a",
            "title": "a",
            "level": "low",
            "logsource": {"log_types": ["ssh"]},
            "detection": {
                "where": [
                    {"field": "source_ip", "op": "exists"},
                    {"field": "result", "op": "equals", "value": "failure"},
                ]
            },
        },
        source="builtin",
    )
    second = build_rule(
        {
            "id": "b",
            "title": "b",
            "level": "low",
            "logsource": {"log_types": ["ssh"]},
            "detection": {
                "where": [
                    {"field": "result", "op": "equals", "value": "failure"},
                    {"field": "source_ip", "op": "exists"},
                ]
            },
        },
        source="builtin",
    )
    assert detection_signature(first) == detection_signature(second)
    assert [item.kind for item in check_rule_health([first, second]).issues] == [
        "duplicate_detection"
    ]


def test_different_aggregate_is_not_a_duplicate():
    """只有聚合不同（`follow_up`）就不是重复——这正是 `.success` 对的判据。"""

    base = _rule("a")
    upgraded = _rule(
        "b",
        detection={
            "where": [{"field": "source_ip", "op": "exists"}],
            "aggregate": {
                "group_by": ["source_ip"],
                "count_gte": 5,
                "window_seconds": 300,
                "follow_up": {
                    "where": [{"field": "result", "op": "equals", "value": "success"}],
                    "within_seconds": 1800,
                },
            },
        },
    )
    assert detection_signature(base) != detection_signature(upgraded)


def test_ungrouped_aggregate_is_flagged():
    rule = _rule(
        "a",
        detection={
            "where": [{"field": "source_ip", "op": "exists"}],
            "aggregate": {"group_by": [], "count_gte": 5, "window_seconds": 300},
        },
    )
    assert [item.kind for item in check_rule_health([rule]).issues] == [
        "ungrouped_aggregate"
    ]


def test_event_type_collision_is_observation_not_issue():
    """事件类型冲突只记观察项：`analytics._tactic` 优先按 rule_id 映射，不影响判定。"""

    first = _rule(
        "a",
        logsource={"log_types": ["ssh"]},
        event={"type": "shared", "name": "a", "level": "low"},
    )
    second = _rule(
        "b",
        logsource={"log_types": ["nginx_apache"]},
        event={"type": "shared", "name": "b", "level": "low"},
    )
    report = check_rule_health([first, second])
    assert report.healthy
    assert [item.kind for item in report.observations] == ["event_type_collision"]
    assert set(report.observations[0].rules) == {"a", "b"}


def test_render_markdown_reports_true_total():
    rules = [_rule(f"r{index}") for index in range(60)]
    text = render_markdown(check_rule_health(rules), limit=40)
    # 60 条同判据规则 → C(60,2) = 1770 个两两配对
    assert "阻断项：**1770**" in text
    assert "另有 1730 项未列出（共 1770 项）" in text


def test_render_markdown_marks_healthy():
    text = render_markdown(check_rule_health([_rule("a")]))
    assert "阻断项：**0**" in text
    assert "## 阻断项\n\n- 无" in text
