"""规则质量评估：在标注语料上跑完整分析流水线，输出每条规则的 TP / FP / FN。

语料位于 `backend/evaluation/corpus/*.yaml`：每个用例含一段标注日志与期望命中的规则
（含风险等级、次数、来源 IP），负样本用于验证阈值以下不误报。
"""

from __future__ import annotations

import os
from pathlib import Path

import yaml

from ..models import RuleQualityCase, RuleQualityReport, RuleQualityRule
from .analyzer import analyze_log, analyze_parsed_logs
from .parser import ParsedLog
from .rules import get_rules
from ..runtime_paths import backend_root

DEFAULT_CORPUS_DIR = backend_root() / "evaluation" / "corpus"


def corpus_dir() -> Path:
    override = os.getenv("RULE_CORPUS_DIR")
    return Path(override) if override else DEFAULT_CORPUS_DIR


def load_corpus() -> list[dict]:
    """加载 `evaluation/corpus/*.yaml`。

    用例可直接内联日志（`log`），也可用 `log_file` 引用 `evaluation/scenarios/` 下的
    真实样本（相对语料目录），便于把整条攻击链固化成回归基线。
    """

    cases: list[dict] = []
    directory = corpus_dir()
    for path in sorted(directory.glob("*.yaml")):
        document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        family = document.get("family", path.stem)
        for case in document.get("cases", []):
            case["family"] = family
            case["source"] = path.name
            log_file = case.get("log_file")
            if log_file and not case.get("log"):
                resolved = directory / log_file
                if not resolved.is_file():
                    raise FileNotFoundError(
                        f"语料用例 {case.get('name')} 引用的日志不存在：{resolved}"
                    )
                case["log"] = resolved.read_text(encoding="utf-8", errors="replace")
            cases.append(case)
    return cases


def evaluate() -> RuleQualityReport:
    cases = load_corpus()
    loaded_rules = get_rules()
    sources = {rule.id: rule.source for rule in loaded_rules}
    rule_ids = [rule.id for rule in loaded_rules]
    statistics: dict[str, dict[str, int]] = {
        rule_id: {"positive": 0, "tp": 0, "fp": 0, "fn": 0} for rule_id in rule_ids
    }
    case_results: list[dict] = []
    duplicate_hits: list[str] = []

    for case in cases:
        if case.get("records") is not None:
            parsed = ParsedLog(
                log_type=str(case.get("log_type") or "generic"),
                confidence=1.0,
                total_lines=len(case["records"]),
                parsed_lines=len(case["records"]),
                records=case["records"],
            )
            result = analyze_parsed_logs([case.get("file", "fixture.log")], [parsed])
        else:
            result = analyze_log(case["file"], case["log"])
        actual = {event.rule_id: event for event in result.events if event.rule_id}
        expectations = case.get("expect") or []
        details: list[str] = []
        case_ok = True

        for expectation in expectations:
            rule_id = expectation["rule"]
            statistics.setdefault(rule_id, {"positive": 0, "tp": 0, "fp": 0, "fn": 0})
            statistics[rule_id]["positive"] += 1
            event = actual.get(rule_id)
            if event is None:
                statistics[rule_id]["fn"] += 1
                details.append(f"缺少 {rule_id}")
                case_ok = False
                continue
            mismatches = []
            if "risk" in expectation and event.risk_level != expectation["risk"]:
                mismatches.append(f"风险 {event.risk_level}≠{expectation['risk']}")
            if "count" in expectation and event.count != expectation["count"]:
                mismatches.append(f"次数 {event.count}≠{expectation['count']}")
            if "source_ip" in expectation and event.source_ip != expectation["source_ip"]:
                mismatches.append(f"来源 {event.source_ip}≠{expectation['source_ip']}")
            if mismatches:
                statistics[rule_id]["fn"] += 1
                details.append(f"{rule_id} 属性不符：{'、'.join(mismatches)}")
                case_ok = False
            else:
                statistics[rule_id]["tp"] += 1

        expected_rules = {item["rule"] for item in expectations}
        is_negative = not expected_rules
        for rule_id, event in actual.items():
            if rule_id in expected_rules:
                continue
            statistics.setdefault(rule_id, {"positive": 0, "tp": 0, "fp": 0, "fn": 0})
            if is_negative or sources.get(rule_id, "builtin") == "builtin":
                statistics[rule_id]["fp"] += 1
                details.append(
                    f"未预期命中 {rule_id}（风险 {event.risk_level}，次数 {event.count}）"
                )
                case_ok = False
            else:
                # 导入的社区规则在**攻击样本**上重复命中：属「重复检出」，不是误报
                # （误报的定义是「正常流量被当成异常」）。保留会破坏门禁的话就没人敢导入规则了，
                # 但必须计数并列出，不能悄悄放过。
                duplicate_hits.append(f"{rule_id} 重复命中 {case['name']}")

        case_results.append(
            RuleQualityCase(
                name=case["name"],
                family=case["family"],
                expected=", ".join(sorted(expected_rules)) or "无事件",
                actual=", ".join(sorted(actual)) or "无事件",
                ok=case_ok,
                details=details,
            )
        )

    uncovered = sorted(
        rule_id
        for rule_id, item in statistics.items()
        if item["positive"] == 0 and sources.get(rule_id, "builtin") == "builtin"
    )
    unverified = sorted(
        rule_id
        for rule_id, item in statistics.items()
        if item["positive"] == 0 and sources.get(rule_id) == "sigma"
    )
    rules = [
        RuleQualityRule(rule_id=rule_id, **statistics[rule_id])
        for rule_id in sorted(statistics)
    ]
    true_positive = sum(item.tp for item in rules)
    false_positive = sum(item.fp for item in rules)
    false_negative = sum(item.fn for item in rules)
    builtin_rule_count = sum(1 for source in sources.values() if source == "builtin")
    imported_rule_count = sum(1 for source in sources.values() if source == "sigma")
    return RuleQualityReport(
        case_count=len(case_results),
        passed_count=sum(1 for case in case_results if case.ok),
        rule_count=len(statistics),
        builtin_rule_count=builtin_rule_count,
        imported_rule_count=imported_rule_count,
        covered_rule_count=builtin_rule_count - len(uncovered),
        unverified_rule_count=len(unverified),
        duplicate_hit_count=len(duplicate_hits),
        unverified_rules=unverified,
        duplicate_hits=duplicate_hits,
        true_positive=true_positive,
        false_positive=false_positive,
        false_negative=false_negative,
        precision=(
            true_positive / (true_positive + false_positive)
            if true_positive + false_positive
            else 1.0
        ),
        recall=(
            true_positive / (true_positive + false_negative)
            if true_positive + false_negative
            else 1.0
        ),
        uncovered_rules=uncovered,
        rules=rules,
        cases=case_results,
    )


def render_markdown(report: RuleQualityReport) -> str:
    lines = [
        "# 规则质量报告（基准语料评估）",
        "",
        "> 本文件由 `backend/scripts/eval_rules.py --write` 生成，请勿手工编辑。",
        "> 语料位于 `backend/evaluation/corpus/`：每个用例包含一段标注日志与期望命中的规则",
        "> （含风险等级、次数、来源 IP），另有负样本验证阈值以下不误报。",
        "",
        "## 总览",
        "",
        f"- 用例：**{report.passed_count} / {report.case_count}** 通过",
        f"- 内置规则正样本覆盖：**{report.covered_rule_count} / {report.builtin_rule_count}**"
        f"（共 {report.rule_count} 条规则 = 内置 {report.builtin_rule_count} + 导入 {report.imported_rule_count}）",
        f"- 命中：TP **{report.true_positive}** · FP **{report.false_positive}** · FN **{report.false_negative}**",
        f"- 准确率（precision）**{report.precision:.1%}** · 召回率（recall）**{report.recall:.1%}**",
        f"- 未被任何用例覆盖的内置规则：{'、'.join(report.uncovered_rules) if report.uncovered_rules else '无'}",
        f"- ⚠️ **未验证的导入规则：{report.unverified_rule_count} 条**"
        "（社区规则只做过「正常流量零命中」筛查，没有本地正样本；事件名带 `[Sigma]` 前缀）",
        f"- 导入规则在攻击样本上重复命中：**{report.duplicate_hit_count}** 次"
        "（属重复检出，不是误报——误报的定义是正常流量被当成异常）",
        "",
        "## 未验证的导入规则清单",
        "",
        "> 以下规则已经导入并通过正常流量零命中筛查，但尚无本地正样本；它们不计入内置规则的已验证覆盖。",
        "",
    ]
    if report.unverified_rules:
        lines.extend(f"- `{rule_id}`" for rule_id in report.unverified_rules)
    else:
        lines.append("- 无")
    lines.extend(
        [
            "",
            "## 重复检出明细",
            "",
        ]
    )
    if report.duplicate_hits:
        lines.extend(f"- {item}" for item in report.duplicate_hits)
    else:
        lines.append("- 无")
    lines.extend(
        [
            "",
            "## 逐规则结果",
            "",
            "| 规则 | 正样本 | TP | FP | FN | 结论 |",
            "| --- | ---: | ---: | ---: | ---: | --- |",
        ]
    )
    for item in report.rules:
        if item.fp or item.fn:
            verdict = "存在偏差"
        elif item.positive:
            verdict = "通过"
        else:
            verdict = "无正样本"
        lines.append(
            f"| `{item.rule_id}` | {item.positive} | {item.tp} | {item.fp} | {item.fn} | {verdict} |"
        )
    lines += [
        "",
        "## 用例明细",
        "",
        "| 用例 | 归属 | 期望 | 实际 | 结果 |",
        "| --- | --- | --- | --- | --- |",
    ]
    for case in report.cases:
        lines.append(
            f"| {case.name} | {case.family} | {case.expected} | {case.actual} | "
            f"{'通过' if case.ok else '失败'} |"
        )
    failures = [case for case in report.cases if not case.ok]
    if failures:
        lines += ["", "## 失败明细", ""]
        for case in failures:
            lines.append(f"- **{case.name}**：{'；'.join(case.details)}")
    return "\n".join(lines) + "\n"
