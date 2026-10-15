"""规则元数据访问层：规则正文在 `backend/rules/*.yaml`，本模块只负责对外暴露与统计。

单一事实源 = YAML 规则文件；`get_rules()` 供 `/api/rules` 展示规则的开关与阈值状态。
"""

from __future__ import annotations

from ..models import RuleDefinition
from .rules_engine import Rule, load_rules


def rule_objects() -> list[Rule]:
    return load_rules()


def get_rules() -> list[RuleDefinition]:
    return [
        RuleDefinition(
            id=rule.id,
            name=rule.title,
            log_types=list(rule.display_log_types or rule.log_types),
            risk_level=rule.level,
            enabled=rule.enabled,
            threshold=rule.threshold,
            window_seconds=rule.window_seconds,
            description=rule.description,
            source=rule.source,
            tags=list(rule.tags),
            author=rule.author,
            version=rule.version,
            license=rule.license,
            references=list(rule.references),
            validation_status=rule.validation_status,
        )
        for rule in rule_objects()
    ]


def get_rule(rule_id: str) -> RuleDefinition | None:
    return next((rule for rule in get_rules() if rule.id == rule_id), None)
