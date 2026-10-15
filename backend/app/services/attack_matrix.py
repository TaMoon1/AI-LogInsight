"""ATT&CK 矩阵：战术 × 技术两级视图（仿 Zircolite 的 ATT&CK 页）。

与「概览看板的战术网格」的分工：
- 看板网格 = 一行 14 个战术格，回答「大致打到了哪些阶段」；
- 本矩阵 = 战术列下展开到**技术**，回答「这个阶段具体是哪些手法、由哪些规则报出来」。

**只做映射与计数，不改判定**。技术清单来自 `evaluation/attack-benchmark.json`
（本项目既有的覆盖标尺），命名与口径与 ATT&CK 覆盖报告一致：清单里没有、但本次真的
命中的技术也会出现，并标 `in_benchmark=False`——**不因为是自选清单外的手法就不显示**。
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime

from ..models import (
    AnalysisResult,
    AttackMatrix,
    AttackTacticColumn,
    AttackTechniqueCell,
    RISK_ORDER,
    sort_events_by_risk,
)
from .analytics import _PHASE_ORDER, _tactic
from .attack_coverage import DEFAULT_BENCHMARK, RULE_TECHNIQUES, _load_benchmark
from .rules import get_rules
from .tactics import normalize_tactic, tactic_from_tags, techniques_from_tags


def _catalog(benchmark_path=DEFAULT_BENCHMARK) -> dict[str, dict[str, str]]:
    """技术清单索引：id → {name, tactic}。读不到清单时返回空字典（视图退化为「只看命中项」）。"""

    try:
        benchmark = _load_benchmark(benchmark_path)
    except (OSError, ValueError):
        return {}
    catalog: dict[str, dict[str, str]] = {}
    for item in benchmark.get("techniques", []):
        technique_id = str(item.get("id", "")).upper()
        if not technique_id:
            continue
        catalog[technique_id] = {
            "name": str(item.get("name", "")),
            "tactic": normalize_tactic(str(item.get("tactic", ""))),
        }
    return catalog


def build_attack_matrix(
    analysis_id: str,
    result: AnalysisResult,
    records: list[dict[str, str | None]] | None = None,
) -> AttackMatrix:
    catalog = _catalog()
    rule_tags = {rule.id: list(rule.tags or []) for rule in get_rules()}

    technique_events: Counter[str] = Counter()
    technique_rules: dict[str, set[str]] = {}
    technique_tactic: dict[str, str] = {}
    technique_risk: dict[str, str] = {}

    for event in sort_events_by_risk(list(result.events)):
        rule_id = event.rule_id or event.type
        mapped = RULE_TECHNIQUES.get(rule_id, ())
        if not mapped:
            mapped = tuple(techniques_from_tags(rule_tags.get(rule_id)))
        tactic, _ = _tactic(event.rule_id, event.type)
        if tactic == "其他":
            tactic = tactic_from_tags(rule_tags.get(rule_id)) or tactic
        for technique in mapped:
            technique = technique.upper()
            technique_events[technique] += 1
            technique_rules.setdefault(technique, set()).add(rule_id)
            technique_tactic.setdefault(technique, tactic)
            current = technique_risk.get(technique, "info")
            if RISK_ORDER.index(event.risk_level) > RISK_ORDER.index(current):
                technique_risk[technique] = event.risk_level

    # 清单里出现过但本次没命中的技术也保留（0 值），前端可切换「仅命中 / 全部清单」
    cells: dict[str, AttackTechniqueCell] = {}
    for technique_id, meta in catalog.items():
        cells[technique_id] = AttackTechniqueCell(
            technique=technique_id,
            name=meta["name"],
            tactic=meta["tactic"],
            events=technique_events.get(technique_id, 0),
            rules=sorted(technique_rules.get(technique_id, ())),
            risk_level=technique_risk.get(technique_id, "info"),  # type: ignore[arg-type]
            in_benchmark=True,
        )
    for technique_id, count in technique_events.items():
        if technique_id in cells:
            continue
        cells[technique_id] = AttackTechniqueCell(
            technique=technique_id,
            name="",
            tactic=technique_tactic.get(technique_id, "其他"),
            events=count,
            rules=sorted(technique_rules.get(technique_id, ())),
            risk_level=technique_risk.get(technique_id, "info"),  # type: ignore[arg-type]
            in_benchmark=False,
        )

    grouped: dict[str, list[AttackTechniqueCell]] = {}
    for cell in cells.values():
        grouped.setdefault(cell.tactic, []).append(cell)

    columns = [
        AttackTacticColumn(
            tactic=tactic,
            phase_index=index,
            events=sum(item.events for item in grouped.get(tactic, [])),
            techniques=sorted(
                grouped[tactic], key=lambda item: (-item.events, item.technique)
            ),
        )
        for tactic, index in sorted(_PHASE_ORDER.items(), key=lambda item: item[1])
        if tactic in grouped
    ]
    # 阶段表里没有的战术**单独补一列**，不能丢：命中的技术被静默隐藏，
    # 等于报告里少了一种手法（2026-10-13 的真实事故就是「凭证访问」不入列）。
    extra = sorted(tactic for tactic in grouped if tactic not in _PHASE_ORDER)
    columns.extend(
        AttackTacticColumn(
            tactic=tactic,
            phase_index=99,
            events=sum(item.events for item in grouped[tactic]),
            techniques=sorted(
                grouped[tactic], key=lambda item: (-item.events, item.technique)
            ),
        )
        for tactic in extra
    )

    hit = [cell for cell in cells.values() if cell.events]
    return AttackMatrix(
        analysis_id=analysis_id,
        columns=columns,
        techniques_total=len(cells),
        techniques_hit=len(hit),
        events_total=sum(cell.events for cell in hit),
        generated_at=datetime.now().astimezone().isoformat(timespec="seconds"),
        note=(
            f"技术清单来自项目内置的 ATT&CK 标尺（{len(catalog)} 项，"
            "不等于 ATT&CK 全量），本次命中 "
            f"{len(hit)} 项；标 `in_benchmark=false` 的是清单外但本次确实命中的技术"
        ),
    )


# ---------- ATT&CK Navigator 导出 ----------

#: 图层着色（与界面语义色一致：严重→红、高→橙、中→黄、低→绿）
RISK_COLORS: dict[str, str] = {
    "critical": "#a3134e",
    "high": "#c2531a",
    "medium": "#9c7409",
    "low": "#24835a",
    "info": "#687b8a",
}


def build_navigator_layer(matrix: AttackMatrix) -> dict:
    """把矩阵转成 ATT&CK Navigator 图层（layer v4.5）。

    只导出**本次真正命中**的技术：图层回答「这次看到了什么」，不是「我们能检测什么」——
    把 0 命中的技术也上色，会让图层读起来像「全都被打过」。
    清单外但确实命中的技术同样导出，并在 comment 里标注。
    """

    cells = [
        cell
        for column in matrix.columns
        for cell in column.techniques
        if cell.events
    ]
    techniques = [
        {
            "techniqueID": cell.technique,
            "tactic": cell.tactic,
            "score": cell.events,
            "color": RISK_COLORS.get(cell.risk_level, RISK_COLORS["info"]),
            "enabled": True,
            "comment": (
                f"风险 {cell.risk_level} · 事件 {cell.events} · "
                f"规则：{'、'.join(cell.rules) or '（无）'}"
                + ("" if cell.in_benchmark else " · 不在项目内置标尺清单内")
            ),
        }
        for cell in sorted(cells, key=lambda item: (-item.events, item.technique))
    ]
    max_events = max((cell.events for cell in cells), default=1)
    return {
        "name": f"AI-LogInsight 检测结果 · {matrix.analysis_id[:8]}",
        "versions": {"attack": "15", "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": (
            f"由 AI-LogInsight 从本次日志分析导出：命中 {matrix.techniques_hit} 项技术、"
            f"共 {matrix.events_total} 个事件。技术清单来自项目内置标尺"
            f"（{matrix.techniques_total} 项，不等于 ATT&CK 全量）。"
            "颜色按命中事件的最高风险等级，score 为事件数。"
        ),
        "techniques": techniques,
        "gradient": {
            "colors": ["#ffffff", "#c2531a"],
            "minValue": 0,
            "maxValue": max_events,
        },
        "legendItems": [
            {"label": "严重", "color": RISK_COLORS["critical"]},
            {"label": "高风险", "color": RISK_COLORS["high"]},
            {"label": "中风险", "color": RISK_COLORS["medium"]},
            {"label": "低风险", "color": RISK_COLORS["low"]},
        ],
    }
