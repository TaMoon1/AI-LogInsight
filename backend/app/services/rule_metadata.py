"""规则元数据门禁：格式合法性 + 「声明与证据一致」。

为什么需要它：`RuleDefinition` 早就支持 author / version / license / references /
validation_status，但此前**没有任何地方检查它们填得对不对**——填错、写成占位符、
或把「已验证」当成随手可写的标签，都不会报错。规则元数据是给人看的判断依据，
写错的代价是让人以为某条规则有依据，而其实没有。

本模块只做**格式与声明一致性**检查，不评价规则内容本身好不好。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable
from urllib.parse import urlsplit

from .rules_engine import Rule

#: 允许的许可证标识。新增规则来源时必须显式加进来——不允许「随手写个字符串」蒙混过关。
ALLOWED_LICENSES = frozenset({"proprietary", "DRL-1.1", "MIT", "Apache-2.0"})

#: 允许的验证状态。`validated` 表示有本地正样本（依据由 `scripts/eval_rules.py` 的
#: 语料评估给出），`unverified` 表示尚未有本地正样本。
ALLOWED_VALIDATION_STATUS = frozenset({"validated", "unverified"})

#: 参考链接只接受 http / https，避免出现 `参考：见内部文档` 这类不可核对的占位值。
ALLOWED_REFERENCE_SCHEMES = frozenset({"http", "https"})


@dataclass(frozen=True)
class MetadataViolation:
    rule_id: str
    field: str
    reason: str

    def __str__(self) -> str:
        return f"{self.rule_id} · {self.field}：{self.reason}"


def _is_http_url(value: str) -> bool:
    parts = urlsplit(value)
    return parts.scheme in ALLOWED_REFERENCE_SCHEMES and bool(parts.netloc)


def check_rule_metadata(rules: Iterable[Rule]) -> list[MetadataViolation]:
    """检查规则元数据的格式与取值合法性，返回全部违规项（不抛异常）。"""

    violations: list[MetadataViolation] = []
    for rule in rules:
        if not rule.author:
            violations.append(MetadataViolation(rule.id, "author", "作者未声明"))
        if not rule.license:
            violations.append(MetadataViolation(rule.id, "license", "许可证未声明"))
        elif rule.license not in ALLOWED_LICENSES:
            violations.append(
                MetadataViolation(
                    rule.id, "license", f"许可证取值不在允许集合：{rule.license}"
                )
            )
        if rule.validation_status not in ALLOWED_VALIDATION_STATUS:
            violations.append(
                MetadataViolation(
                    rule.id,
                    "validation_status",
                    f"验证状态取值不在允许集合：{rule.validation_status}",
                )
            )
        for reference in rule.references:
            if not _is_http_url(reference):
                violations.append(
                    MetadataViolation(
                        rule.id, "references", f"参考链接不是 http(s) URL：{reference}"
                    )
                )
    return violations


def check_validation_consistency(
    rules: Iterable[Rule], covered_rule_ids: Iterable[str]
) -> list[MetadataViolation]:
    """声明与证据必须一致：`validated` 的规则必须有本地正样本，反之亦然。

    「有标签」和「已验证」是两件事——本项目的 ATT&CK 覆盖报告刻意把这两个口径分开统计。
    这条检查把同一原则落到规则元数据上：不允许声明一个语料并未验证过的状态。
    """

    covered = set(covered_rule_ids)
    violations: list[MetadataViolation] = []
    for rule in rules:
        has_sample = rule.id in covered
        if rule.validation_status == "validated" and not has_sample:
            violations.append(
                MetadataViolation(rule.id, "validation_status", "声明已验证，但标注语料里没有正样本")
            )
        elif rule.validation_status == "unverified" and has_sample:
            violations.append(
                MetadataViolation(rule.id, "validation_status", "语料里有正样本，却声明为未验证")
            )
    return violations


def render_violations(violations: list[MetadataViolation], limit: int = 20) -> str:
    """把违规项渲染成一段可读文本；超限时给出真实总数（不静默截断）。"""

    if not violations:
        return "规则元数据门禁：通过（0 项违规）"
    lines = [f"规则元数据门禁：**{len(violations)} 项违规**"]
    lines.extend(f"- {item}" for item in violations[:limit])
    if len(violations) > limit:
        lines.append(f"- …… 另有 {len(violations) - limit} 项未列出（共 {len(violations)} 项）")
    return "\n".join(lines)
