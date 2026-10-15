"""规则库体检：重复规则、冲突规则与聚合失效。

为什么需要它：导入时做过一次去重，但那只管「这一次导入的候选之间」；
规则库是长期演进的——后来手工加的规则、改过的 `suppresses`、新一批导入，
都没有统一关口。本模块对**当前装载的全部规则**做一次体检，
并由 `scripts/rule_health.py` 当门禁跑（有阻断项时非零退出）。

两类结论，口径分开（沿用本项目「不把观察项当缺陷」的纪律）：

- **阻断项（issues）**：一定是配置错误，必须为 0。
- **观察项（observations）**：当前已知且可接受，但不该悄悄变多。

六类阻断项，每类都对应一种「安静地出错」：

| 检查 | 为什么是错的 |
|---|---|
| `dangling_reference` | `suppresses` / `upgrade_rule` 指向不存在的 id——多半是改 id 或打错字，压制/升级**静默失效** |
| `self_suppress` | 规则压制自己——该规则永远不产出事件 |
| `suppress_cycle` | A 压制 B 且 B 压制 A——谁产出取决于遍历顺序，结果不稳定 |
| `asymmetric_upgrade` | A 声明 `upgrade_rule: B`，但 B 没声明 `suppresses: A`——升级链断了一半，基础规则该被升级时不会被升级 |
| `duplicate_detection` | 判据与聚合完全相同、且互相之间没有压制/升级关系——同一条记录会产出两个事件（重复告警） |
| `ungrouped_aggregate` | 声明了聚合但 `group_by` 为空——整个时间窗的记录并成一条，丢掉来源 IP / 主机等实体区分 |

**「判据相同」不等于「重复」**：本项目刻意用 `X.success` 压制 `X` 来区分
「失败聚集」与「失败后成功」两种情况（5 组），它们共享 `where` 但聚合不同、
且互相声明了压制与升级。因此本模块的判据签名**包含聚合（含 `follow_up`）**，
并把「互相压制或升级」视为已解决——否则这 5 组会被误报成缺陷。

签名与 `scripts/import_sigma_community.py` 的 `_signature()` **刻意不同**：
后者只取 logsource + where + any，作用域是「本次导入的候选之间」；
本模块作用域是**全库**，且必须区分聚合语义。两者不互相替代。
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Iterable

from .rules_engine import Aggregate, Predicate, Rule


def _predicate_key(predicate: Predicate) -> str:
    """把谓词压成可比较、可排序的字符串（排序是为了让「条件顺序不同」也判为相同）。"""

    return json.dumps(
        [
            predicate.op,
            [spec.field for spec in predicate.fields],
            list(predicate.values),
            predicate.ignore_case,
            predicate.negate,
        ],
        ensure_ascii=False,
    )


def _aggregate_key(aggregate: Aggregate | None) -> list:
    if aggregate is None:
        return []
    follow_up = aggregate.follow_up
    return [
        [spec.field for spec in aggregate.group_by],
        aggregate.window_seconds,
        aggregate.count_gte,
        aggregate.distinct_field.field if aggregate.distinct_field else None,
        aggregate.distinct_gte,
        aggregate.bucket,
        None
        if follow_up is None
        else [
            sorted(_predicate_key(item) for item in follow_up.where),
            follow_up.within_seconds,
        ],
    ]


def detection_signature(rule: Rule) -> str:
    """判据 + 聚合的规范化签名。

    `where` 是 AND、`any` 的组内是 AND、组间是 OR，都不受书写顺序影响，
    因此排序后再比较——否则「同一判据换个顺序写」会被当成两条不同规则。
    """

    return json.dumps(
        [
            sorted(rule.log_types),
            sorted(rule.exclude_log_types),
            sorted(_predicate_key(item) for item in rule.where),
            sorted(
                sorted(_predicate_key(item) for item in group) for group in rule.any_of
            ),
            _aggregate_key(rule.aggregate),
        ],
        ensure_ascii=False,
        sort_keys=True,
    )


@dataclass(frozen=True)
class HealthFinding:
    kind: str
    detail: str
    rules: tuple[str, ...] = ()

    def __str__(self) -> str:
        joined = "、".join(self.rules)
        return f"[{self.kind}] {self.detail}" + (f"（{joined}）" if joined else "")


@dataclass
class RuleHealthReport:
    rule_count: int
    issues: list[HealthFinding] = field(default_factory=list)
    observations: list[HealthFinding] = field(default_factory=list)

    @property
    def healthy(self) -> bool:
        return not self.issues


def _related(rule: Rule, other: Rule) -> bool:
    """两条规则之间是否已声明压制或升级关系（声明过就不算重复告警）。"""

    return (
        other.id in rule.suppresses
        or rule.id in other.suppresses
        or rule.upgrade_rule == other.id
        or other.upgrade_rule == rule.id
    )


def check_rule_health(rules: Iterable[Rule]) -> RuleHealthReport:
    """对规则集合做一次完整体检，返回阻断项与观察项。"""

    items = list(rules)
    by_id = {rule.id: rule for rule in items}
    issues: list[HealthFinding] = []

    for rule in items:
        for target in rule.suppresses:
            if target not in by_id:
                issues.append(
                    HealthFinding(
                        "dangling_reference",
                        f"suppresses 指向不存在的规则 {target}",
                        (rule.id,),
                    )
                )
            elif target == rule.id:
                issues.append(HealthFinding("self_suppress", "规则压制自己", (rule.id,)))
        if rule.upgrade_rule and rule.upgrade_rule not in by_id:
            issues.append(
                HealthFinding(
                    "dangling_reference",
                    f"upgrade_rule 指向不存在的规则 {rule.upgrade_rule}",
                    (rule.id,),
                )
            )

    # 升级链必须成对：A 声明被 B 升级，B 就得声明压制 A，否则升级不会发生。
    for rule in items:
        target = by_id.get(rule.upgrade_rule or "")
        if target is not None and rule.id not in target.suppresses:
            issues.append(
                HealthFinding(
                    "asymmetric_upgrade",
                    f"upgrade_rule={target.id}，但对方未声明 suppresses 本规则，升级链静默失效",
                    (rule.id,),
                )
            )

    # 压制成环：只看有向边，双向即成环。自压制已单列，不在这里重复计数。
    for rule in items:
        for target in rule.suppresses:
            other = by_id.get(target)
            if other is not None and other.id != rule.id and rule.id in other.suppresses:
                pair = tuple(sorted((rule.id, other.id)))
                issues.append(
                    HealthFinding("suppress_cycle", "两条规则互相压制，谁产出取决于顺序", pair)
                )

    groups: dict[str, list[Rule]] = defaultdict(list)
    for rule in items:
        groups[detection_signature(rule)].append(rule)
    for members in groups.values():
        if len(members) < 2:
            continue
        for index, first in enumerate(members):
            for second in members[index + 1 :]:
                if not _related(first, second):
                    issues.append(
                        HealthFinding(
                            "duplicate_detection",
                            f"判据与聚合完全相同且互不压制：{first.level} / {second.level}",
                            (first.id, second.id),
                        )
                    )

    for rule in items:
        if rule.aggregate is not None and not rule.aggregate.group_by:
            issues.append(
                HealthFinding(
                    "ungrouped_aggregate",
                    "声明了聚合但 group_by 为空，整个时间窗会并成一条并丢掉实体区分",
                    (rule.id,),
                )
            )

    # 观察项：多条规则共用同一 event.type。多由 `slug()` 截断造成（它是环境变量名的
    # 组成部分，不能随便加长），也可能是刻意共用（如 SSH 与 Windows 的 privileged_login）。
    # 不阻断：`analytics._tactic` 优先按 rule_id 映射，事件类型冲突不改变判定。
    type_owners: dict[str, list[str]] = defaultdict(list)
    for rule in items:
        type_owners[rule.event.type].append(rule.id)
    observations = [
        HealthFinding(
            "event_type_collision",
            f"event.type=`{event_type}` 被 {len(owners)} 条规则共用",
            tuple(sorted(owners)),
        )
        for event_type, owners in sorted(type_owners.items())
        if len(owners) > 1
    ]

    return RuleHealthReport(
        rule_count=len(items), issues=issues, observations=observations
    )


def render_markdown(report: RuleHealthReport, limit: int = 40) -> str:
    """把体检结果渲染成报告；截断处给出真实总数。"""

    lines = [
        "# 规则库体检报告",
        "",
        "> 由 `backend/scripts/rule_health.py --write` 生成，勿手工编辑。",
        "",
        "## 总览",
        "",
        f"- 规则总数：**{report.rule_count}**",
        f"- 阻断项：**{len(report.issues)}**（必须为 0）",
        f"- 观察项：**{len(report.observations)}**（已知且可接受，但不应变多）",
        "",
        "## 阻断项",
        "",
    ]
    if report.issues:
        counts = Counter(item.kind for item in report.issues)
        lines.append("| 检查 | 条数 |")
        lines.append("| --- | ---: |")
        lines += [f"| `{kind}` | {count} |" for kind, count in counts.most_common()]
        lines += ["", "明细：", ""]
        lines += [f"- {item}" for item in report.issues[:limit]]
        if len(report.issues) > limit:
            lines.append(
                f"- …… 另有 {len(report.issues) - limit} 项未列出（共 {len(report.issues)} 项）"
            )
    else:
        lines.append("- 无")
    lines += ["", "## 观察项", ""]
    if report.observations:
        lines.append("| 类型 | 条数 |")
        lines.append("| --- | ---: |")
        counts = Counter(item.kind for item in report.observations)
        lines += [f"| `{kind}` | {count} |" for kind, count in counts.most_common()]
        lines += ["", "明细：", ""]
        lines += [f"- {item}" for item in report.observations[:limit]]
        if len(report.observations) > limit:
            lines.append(
                f"- …… 另有 {len(report.observations) - limit} 项未列出"
                f"（共 {len(report.observations)} 项）"
            )
    else:
        lines.append("- 无")
    return "\n".join(lines) + "\n"
