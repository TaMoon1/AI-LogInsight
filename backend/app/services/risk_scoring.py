"""异常评分（借鉴 OWASP CRS 的 anomaly score 机制）。

CRS 的思路是「单条规则命中只加分，累计分数决定最终处置等级」，
本项目据此把同一来源的多条可疑事件累加，避免「一次分析里同时出现多个
medium 事件却仍然只报 medium」这种低估。

约定：

- 默认**关闭**（`RISK_SCORING_ENABLED=false`）：只计算并展示分数，
  不改变风险等级与结论，保证既有基线与规则回归不受影响。
- 权重：critical 10 / high 5 / medium 3 / low 1 / info 0。
- 升级阈值可配置：`RISK_SCORE_CRITICAL` / `RISK_SCORE_HIGH` / `RISK_SCORE_MEDIUM`。
- 只在**同一归组对象**内累加（跨对象不叠加），避免把不相关活动合并成高风险；
  归组对象优先取来源 IP，主机侧日志退回目标主机。
"""

from __future__ import annotations

import os

from ..models import Event, RiskScoreItem

DEFAULT_WEIGHTS = {
    "critical": 10,
    "high": 5,
    "medium": 3,
    "low": 1,
    "info": 0,
}
RISK_ORDER = ("info", "low", "medium", "high", "critical")


def scoring_enabled() -> bool:
    value = os.getenv("RISK_SCORING_ENABLED", "false").strip().lower()
    return value in {"1", "true", "yes", "on", "enabled"}


def _threshold(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None or not value.strip():
        return default
    try:
        return int(value.strip())
    except ValueError:
        return default


def thresholds() -> dict[str, int]:
    return {
        "critical": _threshold("RISK_SCORE_CRITICAL", 15),
        "high": _threshold("RISK_SCORE_HIGH", 10),
        "medium": _threshold("RISK_SCORE_MEDIUM", 5),
    }


def _weight(level: str) -> int:
    return DEFAULT_WEIGHTS.get(level, 0)


def _level_for(score: int, thresholds_by_level: dict[str, int]) -> str:
    for level in ("critical", "high", "medium"):
        if score >= thresholds_by_level[level]:
            return level
    return "low" if score > 0 else "info"


def score_events(events: list[Event]) -> list[RiskScoreItem]:
    """按归组对象累加事件分数，返回评分明细（按分数降序）。

    优先按来源 IP 归组；主机侧日志（Sysmon / Windows 事件）没有来源 IP，
    退回按目标主机归组，否则这部分事件完全拿不到异常评分。
    """

    limits = thresholds()
    grouped: dict[tuple[str, str], list[Event]] = {}
    for event in events:
        if event.source_ip:
            identity = ("source_ip", event.source_ip)
        elif event.target_asset:
            identity = ("target_asset", event.target_asset)
        else:
            continue
        grouped.setdefault(identity, []).append(event)

    items: list[RiskScoreItem] = []
    for (kind, key), group_events in grouped.items():
        score = sum(_weight(event.risk_level) for event in group_events)
        if score <= 0:
            continue
        baseline = max(
            (event.risk_level for event in group_events),
            key=lambda level: RISK_ORDER.index(level),
        )
        escalated = _level_for(score, limits)
        if RISK_ORDER.index(escalated) < RISK_ORDER.index(baseline):
            escalated = baseline
        items.append(
            RiskScoreItem(
                source_ip=key if kind == "source_ip" else "",
                key=key,
                kind=kind,
                score=score,
                baseline_level=baseline,
                escalated_level=escalated,
                escalated=RISK_ORDER.index(escalated) > RISK_ORDER.index(baseline),
                rule_ids=sorted({event.rule_id for event in group_events if event.rule_id}),
            )
        )
    items.sort(key=lambda item: (-item.score, item.key))
    return items


def highest_level(items: list[RiskScoreItem], fallback: str) -> str:
    """取评分升级后的最高等级（未升级时保持原等级）。"""

    level = fallback
    for item in items:
        if RISK_ORDER.index(item.escalated_level) > RISK_ORDER.index(level):
            level = item.escalated_level
    return level
