"""检测视图：把事件按**规则**归组，回答「这次到底是哪些规则在报、报了多少」。

参考 Zircolite 的 Detections 视图（按 level 分段、段内按规则归组、展开看规则元数据与命中明细）。

与「可疑事件」模块的分工：
- 可疑事件 = 一条事件一张卡，看的是**现象**（谁、从哪、干了什么）；
- 检测视图 = 一条规则一行，看的是**规则命中分布**（哪些规则在报、哪条报得最多、规则本身可不可信）。

**只做归组，不改判定**：不合并风险等级、不新增规则、不改结论。数据全部来自
既有 `AnalysisResult.events` 与规则清单（`get_rules()`）。

`validation_status` 直接取自规则元数据：内置规则的 YAML 目前**没有声明**该字段，
因此会原样显示 `unverified`——如实呈现，不替它美化成「已验证」；
补齐真实元数据属路线图 P5。`source`（builtin / sigma）是当前唯一可靠的可靠性区分依据。
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime

from ..models import (
    AnalysisResult,
    DetectionGroup,
    DetectionsReport,
    DetectionVariant,
    RISK_ORDER,
    sort_events_by_risk,
)
from .analytics import _tactic
from .rules import get_rules
from .tactics import tactic_from_tags, techniques_from_tags

#: 每条规则最多展示多少个「变体」（同一规则在不同实体上的命中）
MAX_VARIANTS = 20


def _rule_index() -> dict[str, object]:
    """规则元数据索引：给检测视图补上规则来源、描述、标签与验证状态。"""

    return {rule.id: rule for rule in get_rules()}


def build_detections(
    analysis_id: str,
    result: AnalysisResult,
    records: list[dict[str, str | None]] | None = None,
) -> DetectionsReport:
    rules = _rule_index()

    grouped: dict[str, dict] = {}
    for event in sort_events_by_risk(list(result.events)):
        key = event.rule_id or event.type
        entry = grouped.setdefault(
            key,
            {
                "rule_id": event.rule_id,
                "name": event.name,
                "risk_level": event.risk_level,
                "events": 0,
                "triggers": 0,
                "sources": Counter(),
                "entities": Counter(),
                "files": set(),
                "first_seen": None,
                "last_seen": None,
                "variants": [],
            },
        )
        entry["events"] += 1
        entry["triggers"] += event.count or 0
        if RISK_ORDER.index(event.risk_level) > RISK_ORDER.index(entry["risk_level"]):
            entry["risk_level"] = event.risk_level
        for source_file in event.source_files:
            entry["files"].add(source_file)
        entity = event.source_ip or event.target_asset
        if entity:
            entry["entities"][entity] += 1
        for observed in (event.first_seen, event.last_seen):
            if not observed:
                continue
            if entry["first_seen"] is None or observed < entry["first_seen"]:
                entry["first_seen"] = observed
            if entry["last_seen"] is None or observed > entry["last_seen"]:
                entry["last_seen"] = observed
        entry["variants"].append(
            DetectionVariant(
                event_id=event.id,
                label=entity or event.name,
                risk_level=event.risk_level,
                events=event.count or 0,
                first_seen=event.first_seen,
                summary=event.summary,
            )
        )

    groups: list[DetectionGroup] = []
    for key, entry in grouped.items():
        rule = rules.get(key)
        tags = list(getattr(rule, "tags", []) or [])
        tactic, technique = _tactic(entry["rule_id"], key)
        if tactic == "其他":
            # 内置映射认不出来时（主要是 Sigma 导入规则），回退到规则自带的 attack.* 标签
            tactic = tactic_from_tags(tags) or tactic
        if not technique or technique == "可疑行为":
            from_tags = techniques_from_tags(tags)
            if from_tags:
                technique = from_tags[0]
        variants = entry["variants"][:MAX_VARIANTS]
        groups.append(
            DetectionGroup(
                rule_id=entry["rule_id"] or key,
                name=str(getattr(rule, "name", "") or entry["name"]),
                risk_level=entry["risk_level"],
                tactic=tactic,
                technique=technique,
                event_count=entry["events"],
                trigger_count=entry["triggers"],
                source=str(getattr(rule, "source", "") or "unknown"),
                description=str(getattr(rule, "description", "") or ""),
                tags=tags,
                author=getattr(rule, "author", None),
                version=getattr(rule, "version", None),
                license=getattr(rule, "license", None),
                references=list(getattr(rule, "references", []) or []),
                validation_status=str(getattr(rule, "validation_status", "") or "unverified"),
                enabled=bool(getattr(rule, "enabled", True)),
                first_seen=entry["first_seen"],
                last_seen=entry["last_seen"],
                source_files=sorted(entry["files"]),
                entities=[value for value, _ in entry["entities"].most_common(5)],
                variants=variants,
                variants_total=len(entry["variants"]),
            )
        )

    groups.sort(
        key=lambda item: (
            -RISK_ORDER.index(item.risk_level),
            -item.event_count,
            item.rule_id,
        )
    )
    sigma_groups = sum(1 for item in groups if item.source == "sigma")
    note = (
        f"共 {len(groups)} 条规则命中；其中 Sigma 导入规则 {sigma_groups} 条"
        f"（未在本项目语料上验证过，可靠性低于内置规则）"
        if sigma_groups
        else f"共 {len(groups)} 条规则命中，全部为内置规则（有标注语料验证）"
    )
    return DetectionsReport(
        analysis_id=analysis_id,
        groups_total=len(groups),
        groups=groups,
        generated_at=datetime.now().astimezone().isoformat(timespec="seconds"),
        note=note,
    )
