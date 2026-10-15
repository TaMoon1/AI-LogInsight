"""检测入口：规则定义在 `backend/rules/*.yaml`，由声明式规则引擎执行。

历史版本把 21 条规则的判定逻辑硬编码在本模块（约 900 行），
迁移后规则成为数据，新增规则只需添加 YAML 文件，无需改动代码。
"""

from __future__ import annotations

from ..models import Event
from .rules_engine import evaluate_rules, evaluate_rules_with_coverage


def detect_events(records: list[dict[str, str | None]]) -> list[Event]:
    return evaluate_rules(records)


def detect_events_with_coverage(
    records: list[dict[str, str | None]],
) -> tuple[list[Event], set[str]]:
    """返回（事件, 被任一启用规则命中的记录 ID），供覆盖度统计复用同一次匹配。"""

    return evaluate_rules_with_coverage(records)
