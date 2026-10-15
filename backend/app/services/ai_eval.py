"""AI 研判质量评测：对已产出的研判结果做自动检查，并聚合为可门禁的报告。

设计口径参照 `DiogoRibeiro7/ai-incident-analysis-agent` 的 evaluation harness：

1. **默认精确，仅在证据本身歧义时才放宽**。用例的 `risk_levels` 只列出「本用例下
   都算对」的等级，不为好过门禁而全局放宽——歧义是数据集的属性，不是门禁的宽容。
2. **不可评估 ≠ 通过**。没有行为可引用证据时，引用覆盖率记为 `None`（不可评估），
   不记成 1.0；否则「什么都没输出」会被当成满分，正是要拦的假阳性。
3. **检查与判定分离**。本模块只做检查，不重跑管线：接收已产出的 `judgement`，
   因此同一个检查器既能验确定性替身，也能验真实模型，还能用手写结论单测。
4. **可疑与否看 `risk_level`，不看行为条数**。本项目有「行为偏离」这一合法概念
   （低置信度提示，不改变风险等级），因此「输出了行为」不等于「判定为攻击」。
   用行为条数判定可疑会在正常日志上产生假失败——这是被真实模型输出纠正过的。
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

from app.models import AnalysisResult
from app.runtime_paths import backend_root
from app.services.analyzer import analyze_log, assign_record_ids, collect_records
from app.services.parser import parse_log

CASES_DIR = backend_root() / "evaluation" / "ai-cases"

RISK_LEVELS = {"critical", "high", "medium", "low", "info"}

#: 判定为「可疑」的风险等级下界。**由数据集标注反推，不是拍脑袋定的**：
#: 负样本允许 `info/low` 并禁止 `high/critical`，正样本期望 `medium/high/critical`
#: —— 于是 `medium` 就是「可疑」的下界，`low/info` 是「不可疑」。
#:
#: 为什么不用「行为条数 > 0」：本项目有 P1-16「行为偏离」（低置信度提示、不改变
#: 风险等级），它会在正常日志上产生行为。按条数判定会把合法偏离算成误报。
SUSPICIOUS_LEVELS = frozenset({"medium", "high", "critical"})

#: 门禁失败项（AGENTS.md §16 + 路线图 P2 第 5 条）。
#: 其余检查只记录与出报告，不单独阻断发布。
GATING_CHECKS = ("json_valid", "evidence_exists", "risk_level_severe")

#: 单次评测使用的判据函数：给定用例与上下文，返回 (judgement, 模型原始输出)。
Judge = Callable[["AiCase", AnalysisResult, list[dict[str, str | None]]], tuple[dict[str, Any], str]]


@dataclass
class AiCase:
    """一条评测用例及其期望标注。"""

    name: str
    family: str
    note: str
    filename: str
    log: str
    expect: dict[str, Any] = field(default_factory=dict)
    #: 该用例的输入**故意**无法解析（如纯文本垃圾）。显式声明而不是让测试硬编码名字：
    #: 否则「解析失败」到底是设计意图还是数据写坏了，读代码的人无从判断。
    unparseable: bool = False
    #: 是否属于**最小回归集**。标记的用例随 `pytest` 自动执行，因此必须体量小、秒级完成；
    #: 3000 行的规模用例不标，留给完整评测。
    smoke: bool = False

    @property
    def suspicious(self) -> bool:
        return bool(self.expect.get("suspicious", False))

    @property
    def risk_levels(self) -> list[str]:
        return list(self.expect.get("risk_levels") or [])

    @property
    def forbid_risk_levels(self) -> list[str]:
        return list(self.expect.get("forbid_risk_levels") or [])

    @property
    def min_behaviors(self) -> int:
        return int(self.expect.get("min_behaviors", 0))

    @property
    def evidence_keywords(self) -> list[str]:
        return [str(item) for item in (self.expect.get("evidence_keywords") or [])]


@dataclass
class Finding:
    """一条检查结果。`gating` 为真时，未通过即门禁失败。"""

    check: str
    passed: bool
    detail: str
    gating: bool = False


@dataclass
class CaseOutcome:
    name: str
    family: str
    note: str
    suspicious_expected: bool
    suspicious_actual: bool
    risk_level: str
    confidence: float
    behavior_count: int
    citation_coverage: float | None
    unsupported_claims: list[str]
    findings: list[Finding]
    #: 判据调用的耗时（毫秒）。**只计判据本身**，不含解析与规则分析——
    #: 后者与模型无关，混进来会让不同模型的耗时不可比。
    duration_ms: float = 0.0
    #: 该次调用的 token 账单。拿不到时留空 dict，**不填 0**：
    #: 「没测到」和「零成本」是两件事，报告里必须能区分。
    usage: dict[str, Any] = field(default_factory=dict)
    #: 本次研判实际引用到的证据编号（去重保序）。
    evidence_refs: list[str] = field(default_factory=list)
    #: 模型引用过但日志中不存在的证据编号。
    dropped_evidence_ids: list[str] = field(default_factory=list)
    #: 该次研判的 P3 指标（上下文体量 / 分轮 token / 成本估算 / 证据下发与引用）。
    #: 确定性替身不产出它，因此留空 dict——**不伪造一份零值指标**，
    #: 否则报告里「替身没成本数据」和「真实调用零成本」会混成一列。
    metrics: dict[str, Any] = field(default_factory=dict)

    @property
    def passed(self) -> bool:
        return all(finding.passed for finding in self.findings if finding.gating)

    @property
    def judges_suspicious(self) -> bool:
        """本次研判是否**判定为可疑**。只看 `risk_level`，不看行为条数。

        与 `check_judgement()` 的判定口径保持一致：用行为条数会把 P1-16 的
        「行为偏离」（正常日志上的低置信度提示）算成误报。
        """
        return str(self.risk_level) in SUSPICIOUS_LEVELS

    @property
    def correct(self) -> bool:
        """可疑与否的判定是否与标注一致。

        `risk_level` 为空（判据执行失败）时不算正确——把它算成「负样本判对了」
        会让一次崩溃在准确率上看起来像一次成功的保守判断。
        """
        if str(self.risk_level) not in RISK_LEVELS:
            return False
        return self.suspicious_expected == self.judges_suspicious

    @property
    def gating_failures(self) -> list[Finding]:
        return [f for f in self.findings if f.gating and not f.passed]


@dataclass
class EvalReport:
    outcomes: list[CaseOutcome] = field(default_factory=list)

    @property
    def failed(self) -> list[CaseOutcome]:
        return [outcome for outcome in self.outcomes if not outcome.passed]

    @property
    def gate_failed(self) -> bool:
        return bool(self.failed)

    @property
    def confusion(self) -> tuple[int, int, int, int]:
        """(TP, FP, TN, FN)。正类 = 「标注为可疑」。

        `correct` 已排除 `risk_level` 非法的用例，因此一次判据崩溃会同时计入
        漏报或误报，而不是悄悄变成「保守的正确判断」。
        """

        tp = fp = tn = fn = 0
        for outcome in self.outcomes:
            if outcome.suspicious_expected:
                if outcome.judges_suspicious:
                    tp += 1
                else:
                    fn += 1
            elif outcome.judges_suspicious:
                fp += 1
            else:
                tn += 1
        return tp, fp, tn, fn

    @property
    def accuracy(self) -> float | None:
        """可疑与否的判定正确率。无用例时返回 None（不可评估）。"""

        total = len(self.outcomes)
        if not total:
            return None
        return sum(1 for outcome in self.outcomes if outcome.correct) / total

    @property
    def false_positive_rate(self) -> float | None:
        """误报率 = FP / (FP + TN)。**没有负样本时返回 None**，不返回 0。

        返回 0 会让「样本集里根本没有正常用例」看起来像「误报率完美」。
        """

        _, fp, tn, _ = self.confusion
        return None if fp + tn == 0 else fp / (fp + tn)

    @property
    def false_negative_rate(self) -> float | None:
        """漏报率 = FN / (FN + TP)。没有正样本时返回 None。

        与误报率成对：安全产品里漏报的代价通常高于误报，只报误报率会给出
        一个偏乐观的印象。
        """

        tp, _, _, fn = self.confusion
        return None if tp + fn == 0 else fn / (tp + fn)


def _expand_log(payload: dict[str, Any]) -> str:
    """把用例的 `log` 内联文本或 `generator` 展开为完整日志文本。"""

    parts: list[str] = []
    generator = payload.get("generator")
    if isinstance(generator, dict):
        kind = str(generator.get("kind", ""))
        if kind != "repeat":
            raise ValueError(f"不支持的 generator.kind：{kind!r}")
        template = str(generator.get("template", ""))
        times = int(generator.get("times", 1))
        # 用 replace 而不是 format：日志正文常含花括号（JSON 片段、正则），format 会炸。
        for index in range(1, times + 1):
            parts.append(template.replace("{i}", str(index)).strip("\n"))
    inline = payload.get("log")
    if inline:
        parts.append(str(inline).strip("\n"))
    appended = payload.get("append")
    if appended:
        parts.append(str(appended).strip("\n"))
    return "\n".join(part for part in parts if part)


def load_cases(directory: Path | None = None, *, smoke_only: bool = False) -> list[AiCase]:
    """读取 `evaluation/ai-cases/*.yaml`，按文件名顺序展开为用例列表。

    `smoke_only=True` 只返回标记了 `smoke: true` 的最小回归集。
    """

    root = directory or CASES_DIR
    cases: list[AiCase] = []
    for path in sorted(root.glob("*.yaml")):
        payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        family = str(payload.get("family") or path.stem)
        for item in payload.get("cases") or []:
            cases.append(
                AiCase(
                    name=str(item["name"]),
                    family=family,
                    note=str(item.get("note") or ""),
                    filename=str(item.get("file") or f"{item['name']}.log"),
                    log=_expand_log(item),
                    expect=dict(item.get("expect") or {}),
                    unparseable=bool(item.get("unparseable", False)),
                    smoke=bool(item.get("smoke", False)),
                )
            )
    if smoke_only:
        cases = [case for case in cases if case.smoke]
    return cases


def build_case_context(case: AiCase) -> tuple[AnalysisResult, list[dict[str, str | None]]]:
    """复刻上传路径的记录组装口径，保证评测与真实分析看到同一份数据。

    直接用 `analyzer` 的公开函数（`collect_records` / `assign_record_ids`），
    而不是自己拼 `record-N`：编号一旦和管线不一致，证据引用会全对不上。
    """

    parsed = parse_log(case.log)
    records = assign_record_ids(collect_records([case.filename], [parsed]))
    result = analyze_log(case.filename, case.log)
    return result, records


def _citation_coverage(judgement: dict[str, Any]) -> float | None:
    """有证据引用的行为占比。**无行为时返回 None（不可评估）**，不返回 1.0。"""

    behaviors = judgement.get("behaviors") or []
    if not behaviors:
        return None
    cited = sum(1 for item in behaviors if getattr(item, "evidence_ids", None))
    return cited / len(behaviors)


def _usage_from(judgement: dict[str, Any]) -> dict[str, Any]:
    """从工具轨迹里取出本次调用的 token 账单。

    取不到就返回空 dict。**不返回零值字典**——服务端没回传用量和「用量为零」
    是两件事，填 0 会让成本对比得出反向结论。
    """

    for entry in reversed(judgement.get("tool_trace") or []):
        usage = entry.get("usage") if isinstance(entry, dict) else None
        if isinstance(usage, dict) and usage:
            return dict(usage)
    return {}


def _metrics_from(judgement: dict[str, Any]) -> dict[str, Any]:
    """取出本次研判的 P3 指标。取不到返回空 dict，**不返回零值字典**。"""

    metrics = judgement.get("metrics")
    return dict(metrics) if isinstance(metrics, dict) and metrics else {}


def _evidence_refs(judgement: dict[str, Any]) -> list[str]:
    """本次研判引用到的证据编号，去重保序。"""

    refs: list[str] = []
    for item in judgement.get("behaviors") or []:
        for value in getattr(item, "evidence_ids", None) or []:
            if value not in refs:
                refs.append(value)
    return refs


def check_judgement(
    judgement: dict[str, Any],
    case: AiCase,
    *,
    raw_output: str | None = None,
) -> list[Finding]:
    """对一份研判结果做全部检查。`raw_output` 用于校验 JSON 合法性。"""

    findings: list[Finding] = []
    behaviors = judgement.get("behaviors") or []
    risk_level = str(judgement.get("risk_level") or "")
    confidence = float(judgement.get("confidence") or 0.0)
    dropped = list(judgement.get("dropped_evidence_ids") or [])
    unsupported = [str(item) for item in (judgement.get("unsupported_claims") or [])]

    # 1. JSON 合法性。拿不到原始输出时如实标注不可评估，不默认通过。
    if raw_output is None:
        findings.append(Finding("json_valid", True, "未提供原始输出，跳过 JSON 合法性检查"))
    else:
        try:
            parsed = json.loads(raw_output.strip().removeprefix("```json").removesuffix("```").strip())
            ok = isinstance(parsed, dict)
            findings.append(
                Finding("json_valid", ok, "原始输出是 JSON 对象" if ok else "原始输出不是 JSON 对象", gating=True)
            )
        except (ValueError, TypeError) as exc:
            findings.append(Finding("json_valid", False, f"原始输出无法解析为 JSON：{exc}", gating=True))

    # 2. 风险等级取值合法
    findings.append(
        Finding(
            "risk_level_valid",
            risk_level in RISK_LEVELS,
            f"risk_level={risk_level!r}",
        )
    )

    # 3. 置信度范围
    in_range = 0.0 <= confidence <= 1.0
    findings.append(Finding("confidence_range", in_range, f"confidence={confidence}"))

    # 4. 证据真实性：模型引用过但日志中不存在的证据编号（门禁项）
    findings.append(
        Finding(
            "evidence_exists",
            not dropped,
            "未引用不存在的证据" if not dropped else f"引用了不存在的证据编号：{dropped}",
            gating=True,
        )
    )

    # 5. 引用覆盖率（观察指标；无行为时为不可评估）
    coverage = _citation_coverage(judgement)
    if coverage is None:
        findings.append(Finding("citation_coverage", True, "无行为可引用，覆盖率不可评估"))
    else:
        findings.append(
            Finding("citation_coverage", coverage > 0, f"引用覆盖率 {coverage:.0%}（{len(behaviors)} 条行为）")
        )

    # 6. 无依据声明
    findings.append(
        Finding(
            "grounding",
            not unsupported,
            "无无依据声明" if not unsupported else f"存在无依据声明：{unsupported[:3]}",
        )
    )

    # 7. 严重风险等级错误（门禁项）：命中禁止等级即失败
    hit = [level for level in case.forbid_risk_levels if level == risk_level]
    findings.append(
        Finding(
            "risk_level_severe",
            not hit,
            "风险等级未越界" if not hit else f"风险等级 {risk_level} 属禁止等级 {case.forbid_risk_levels}",
            gating=True,
        )
    )

    # 8. 风险等级落在可接受集合内
    if case.risk_levels:
        ok = risk_level in case.risk_levels
        findings.append(
            Finding("risk_level_acceptable", ok, f"risk_level={risk_level!r}，可接受 {case.risk_levels}", gating=True)
        )

    # 9. 召回下界：异常用例必须至少给出这么多行为
    #
    # 这里**只有下界，没有上界**。曾经我按「行为条数」判定是否可疑，并在正常用例上
    # 要求 `max_behaviors: 0`——用真实模型一跑就假失败：模型对正常日志正确地输出了
    # `risk_level=info` / `confidence=0.35`，同时附了一条 `behavior_deviation`
    # （「低频来源地址访问健康检查路径」，明说「属统计性偏离而非攻击特征」）。
    # 这正是本项目 P1-16 设计的行为偏离：低置信度提示、不改变风险等级。
    # 把「有行为」等同于「判定为可疑」会把它误判成误报，所以可疑与否一律看 risk_level。
    count = len(behaviors)
    if case.min_behaviors:
        findings.append(
            Finding(
                "behavior_recall",
                count >= case.min_behaviors,
                f"行为 {count} 条，期望至少 {case.min_behaviors} 条",
                gating=True,
            )
        )

    # 11. 关键实体是否出现在结论或行为描述中（召回口径）
    if case.evidence_keywords:
        text = str(judgement.get("conclusion") or "")
        for item in behaviors:
            text += " " + str(getattr(item, "name", "")) + " " + str(getattr(item, "analysis", ""))
            text += " " + " ".join(str(v) for v in (getattr(item, "evidence", None) or []))
        missing = [word for word in case.evidence_keywords if word not in text]
        findings.append(
            Finding(
                "evidence_keywords",
                not missing,
                "关键实体均已提及" if not missing else f"结论中未提及：{missing}",
                gating=True,
            )
        )

    return findings


def evaluate(cases: list[AiCase], judge: Judge) -> EvalReport:
    """跑完一个用例集。`judge` 决定用替身还是真实模型，检查逻辑完全共用。"""

    report = EvalReport()
    for case in cases:
        result, records = build_case_context(case)
        started = time.perf_counter()
        try:
            judgement, raw_output = judge(case, result, records)
        except Exception as exc:  # 单条用例失败不能中断整轮评测
            report.outcomes.append(
                CaseOutcome(
                    name=case.name,
                    family=case.family,
                    note=case.note,
                    suspicious_expected=case.suspicious,
                    suspicious_actual=False,
                    risk_level="",
                    confidence=0.0,
                    behavior_count=0,
                    citation_coverage=None,
                    unsupported_claims=[],
                    findings=[Finding("judge", False, f"研判执行失败：{exc}", gating=True)],
                    duration_ms=(time.perf_counter() - started) * 1000,
                )
            )
            continue
        duration_ms = (time.perf_counter() - started) * 1000
        # 先取出风险等级再推导「是否判定为可疑」：`suspicious_actual` 必须与
        # `check_judgement()` 用同一个口径（risk_level），否则归档里会存下一份
        # 与门禁结论互相矛盾的记录。
        risk_level = str(judgement.get("risk_level") or "")
        report.outcomes.append(
            CaseOutcome(
                name=case.name,
                family=case.family,
                note=case.note,
                suspicious_expected=case.suspicious,
                suspicious_actual=risk_level in SUSPICIOUS_LEVELS,
                risk_level=risk_level,
                confidence=float(judgement.get("confidence") or 0.0),
                behavior_count=len(judgement.get("behaviors") or []),
                citation_coverage=_citation_coverage(judgement),
                unsupported_claims=[str(item) for item in (judgement.get("unsupported_claims") or [])],
                findings=check_judgement(judgement, case, raw_output=raw_output),
                duration_ms=duration_ms,
                usage=_usage_from(judgement),
                metrics=_metrics_from(judgement),
                evidence_refs=_evidence_refs(judgement),
                dropped_evidence_ids=[
                    str(item) for item in (judgement.get("dropped_evidence_ids") or [])
                ],
            )
        )
    return report


def render_markdown(report: EvalReport, conditions: dict[str, str] | None = None) -> str:
    """渲染人类可读报告。不可评估的覆盖率显示为 `n/a`，不显示成 100%。

    `conditions` 写明本次评测的前提（用的哪个判据、哪套规则）。**不写条件的评测报告
    会被误读成「AI 已被评估」**——确定性替身跑出来的通过，只说明检查器和管线自洽，
    不说明模型判得准。
    """

    total = len(report.outcomes)
    passed = total - len(report.failed)
    lines = [
        "# AI 研判质量报告",
        "",
        f"- 用例：**{passed}/{total}** 通过",
        f"- 门禁：**{'通过' if not report.gate_failed else '失败'}**",
    ]
    for key, value in (conditions or {}).items():
        lines.append(f"- {key}：{value}")

    # 质量侧指标。单次运行也要给出来：只看「通过/失败」看不出判得多准——
    # 5/5 通过可能是全判 info，也可能是全判 high。
    tp, fp, tn, fn = report.confusion
    lines.extend(
        [
            "",
            f"- 准确率：**{_percent(report.accuracy)}**（TP {tp} / FP {fp} / TN {tn} / FN {fn}）",
            f"- 误报率：**{_percent(report.false_positive_rate)}**"
            f"（{fp}/{fp + tn} 条正常用例被判为可疑）",
            f"- 漏报率：**{_percent(report.false_negative_rate)}**"
            f"（{fn}/{fn + tp} 条异常用例未被判为可疑）",
        ]
    )
    if report.false_positive_rate is None or report.false_negative_rate is None:
        lines.append(
            "- 样本集缺少正常用例或异常用例，对应比率**不可评估**（显示 `n/a`，不记为 0）"
        )
    lines.extend(
        [
            "",
            "| 用例 | 家族 | 判定 | 风险等级 | 行为数 | 引用覆盖率 | 未通过项 |",
            "|---|---|---|---|---|---|---|",
        ]
    )
    for outcome in report.outcomes:
        coverage = "n/a" if outcome.citation_coverage is None else f"{outcome.citation_coverage:.0%}"
        failures = "、".join(f.check for f in outcome.gating_failures) or "—"
        lines.append(
            f"| {outcome.name} | {outcome.family} | {'通过' if outcome.passed else '**失败**'} "
            f"| {outcome.risk_level} | {outcome.behavior_count} | {coverage} | {failures} |"
        )

    if report.failed:
        lines.extend(["", "## 失败明细", ""])
        for outcome in report.failed:
            lines.append(f"### {outcome.name}")
            lines.append("")
            if outcome.note:
                lines.append(f"> {outcome.note}")
                lines.append("")
            for finding in outcome.gating_failures:
                lines.append(f"- `{finding.check}`：{finding.detail}")
            lines.append("")

    unevaluable = [o for o in report.outcomes if o.citation_coverage is None]
    if unevaluable:
        lines.extend(
            [
                "",
                "## 不可评估项",
                "",
                f"以下 {len(unevaluable)} 条用例没有输出行为，引用覆盖率**不可评估**"
                "（不记为 100%，避免「什么都没输出」被当成满分）：",
                "",
                *[f"- {o.name}" for o in unevaluable],
                "",
            ]
        )
    return "\n".join(lines)


@dataclass
class RunResult:
    """一次评测运行：(模型, Prompt) 的一个组合在整份用例集上的结果。

    对比必须带标签，否则报告里两列数字无法归因到具体组合。
    """

    label: str
    report: EvalReport = field(default_factory=EvalReport)
    conditions: dict[str, str] = field(default_factory=dict)

    @property
    def total(self) -> int:
        return len(self.report.outcomes)

    @property
    def passed(self) -> int:
        return self.total - len(self.report.failed)

    @property
    def billed_cases(self) -> int:
        """回传了 token 账单的用例数。"""

        return sum(1 for outcome in self.report.outcomes if outcome.usage)

    @property
    def tokens(self) -> int | None:
        """总 token。**一条账单都没有时返回 None**，不返回 0。"""

        billed = [outcome for outcome in self.report.outcomes if outcome.usage]
        if not billed:
            return None
        return sum(
            int(outcome.usage.get("prompt_tokens") or 0)
            + int(outcome.usage.get("completion_tokens") or 0)
            for outcome in billed
        )

    @property
    def duration_ms(self) -> float:
        return sum(outcome.duration_ms for outcome in self.report.outcomes)

    @property
    def mean_confidence(self) -> float | None:
        values = [outcome.confidence for outcome in self.report.outcomes]
        return sum(values) / len(values) if values else None

    @property
    def mean_behaviors(self) -> float | None:
        values = [outcome.behavior_count for outcome in self.report.outcomes]
        return sum(values) / len(values) if values else None

    @property
    def citation_coverage(self) -> float | None:
        """只在**可评估**的用例上求平均。

        不可评估（无行为）的用例不参与，也不当 0——否则「什么都没输出」会把
        平均值拉低，看起来像引用质量差。
        """

        values = [
            outcome.citation_coverage
            for outcome in self.report.outcomes
            if outcome.citation_coverage is not None
        ]
        return sum(values) / len(values) if values else None

    @property
    def confusion(self) -> tuple[int, int, int, int]:
        """(TP, FP, TN, FN)。委托给 `EvalReport`，避免两处各算一份。"""

        return self.report.confusion

    @property
    def accuracy(self) -> float | None:
        return self.report.accuracy

    @property
    def false_positive_rate(self) -> float | None:
        return self.report.false_positive_rate

    @property
    def false_negative_rate(self) -> float | None:
        return self.report.false_negative_rate

    @property
    def estimated_cost(self) -> float | None:
        """估算成本合计。**一条带成本的指标都没有时返回 None**，不返回 0.0。

        与 `tokens` 同理：「没配置单价」和「成本为零」是两件事。未配置单价时
        指标里的 `cost.estimated` 就是 null，这里自然会落到 None。
        """

        values: list[float] = []
        for outcome in self.report.outcomes:
            cost = outcome.metrics.get("cost")
            if isinstance(cost, dict) and cost.get("estimated") is not None:
                values.append(float(cost["estimated"]))
        return sum(values) if values else None


def _percent(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.0%}"


def _round(value: float | None) -> float | None:
    return None if value is None else round(value, 4)


#: Token 回归门禁比较的指标。这些量覆盖了「字段白名单 / 分层采样 / 去重 /
#: 证据预算 / 摘要指针」五类上下文整形手段会改变的全部可观测量：
#: 任何一类手段生效，都会落在下面某一列上。门禁因此**不依赖具体机制**——
#: P4 实现这些机制时不必再改门禁。
#:
#: 方向 `lower` 表示越小越好。`evidence_sent` 特意**不**设成越小越好：
#: 少发证据既可能是去重成功，也可能是漏发，必须结合质量指标一起看。
GATED_METRICS: tuple[tuple[str, str], ...] = (
    ("tokens_total", "lower"),
    ("tokens_first_round", "lower"),
    ("context_bytes", "lower"),
    ("evidence_sent", "lower"),
    ("accuracy", "higher"),
    ("false_positive_rate", "lower"),
)


def metric_row(run: RunResult) -> dict[str, float | None]:
    """把一次运行压成一行可比较的门禁指标。取不到的量为 `None`（不可评估）。

    逐项**记录字段是否出现过**再决定取值，而不是用 `sum(...) or None`：
    后者会把「指标里真实是 0」和「根本没记这个指标」压成同一个结果。

    `tokens_total` 优先取服务端账单（`RunResult.tokens`），拿不到时回退到 P3
    指标里记录的总量。两者是同一个量（指标模块也是按 `prompt + completion`
    逐轮累加的），但可能只有一边存在；此时回退比拒绝比较更有用——门禁悄悄
    跳过比门禁判错更危险。
    """

    totals: dict[str, int] = {}
    seen: dict[str, bool] = {}
    for outcome in run.report.outcomes:
        metrics = outcome.metrics
        rounds = metrics.get("tokens") if isinstance(metrics.get("tokens"), dict) else {}
        context = metrics.get("context") if isinstance(metrics.get("context"), dict) else {}
        for name, source, key in (
            ("tokens_total", rounds, "total"),
            ("tokens_first_round", rounds, "first_round"),
            ("context_bytes", context, "bytes"),
            ("evidence_sent", context, "evidence_sent"),
        ):
            value = source.get(key)
            if value is None:
                continue
            totals[name] = totals.get(name, 0) + int(value)
            seen[name] = True

    row: dict[str, float | None] = {
        "accuracy": run.accuracy,
        "false_positive_rate": run.false_positive_rate,
    }
    for name in ("tokens_total", "tokens_first_round", "context_bytes", "evidence_sent"):
        if name == "tokens_total" and run.tokens is not None:
            row[name] = float(run.tokens)
        else:
            row[name] = float(totals[name]) if seen.get(name) else None
    return row


def _quality_delta(
    baseline_row: dict[str, float | None],
    current_row: dict[str, float | None],
    tolerance: float,
) -> tuple[float, str]:
    """质量变化的标量摘要与文字说明。

    以**准确率**为主轴，误报率作为否决项参与：准确率提高但误报率同时变差，
    对安全产品是净损失，不能算质量提升。
    """

    base_acc = baseline_row.get("accuracy")
    cur_acc = current_row.get("accuracy")
    if base_acc is None or cur_acc is None:
        return 0.0, "准确率不可评估（无用例）"

    delta = cur_acc - base_acc
    base_fp = baseline_row.get("false_positive_rate")
    cur_fp = current_row.get("false_positive_rate")
    note = f"准确率 {base_acc:.0%}→{cur_acc:.0%}"
    if base_fp is not None and cur_fp is not None and cur_fp > base_fp + tolerance:
        note += f"，误报率 {base_fp:.0%}→{cur_fp:.0%} 变差"
        return min(delta, 0.0), note
    return delta, note


def compare_gate_metrics(
    baseline_row: dict[str, float | None],
    current_row: dict[str, float | None],
    *,
    tolerance: float = 0.10,
    quality_tolerance: float = 0.0,
) -> list[Finding]:
    """成本 × 质量联合门禁，作用在**指标行**上。

    核心逻辑放在行上而不是 `RunResult` 上，是因为基线往往来自**已归档的 JSON
    产物**（上一轮评测的 `summary.gate_metrics`），而不是一个还在内存里的运行。
    行级函数让「和上次发布比」和「和另一个模型比」共用同一套判定。

    四条规则（前两条是门禁失败，后两条通过）：

    1. Token 涨超容差且质量未提升 → 失败。多花钱没换来质量，纯浪费。
    2. Token 降但质量下降 → 失败。省下的 token 是用准确率换的，不是优化。
    3. Token 降且质量持平或提升 → 通过。
    4. Token 涨且质量提升 → 通过，但记为观察项。**不自动判定为成功**——
       是否值得这个价钱是人的决定，不是门禁能代替的。

    `quality_tolerance` 默认为 0：评测样本集本来就小，任何一条用例的判定
    翻转都是真实变化，不该被容差抹平。成本容差则可以放宽，因为 token 数
    随日志长度自然波动。

    四条规则都标 `gating=True`——**通过的那些也是门禁项，只是通过了**。
    漏标会让「门禁通过」这件事在汇总里看不见，读者无从判断到底有没有比过。
    """

    findings: list[Finding] = []

    base_tokens = baseline_row.get("tokens_total")
    cur_tokens = current_row.get("tokens_total")

    if base_tokens is None or cur_tokens is None:
        findings.append(
            Finding(
                "token_regression",
                True,
                "基线与本次运行都缺 token 账单，无法比较成本（不可评估，不计为通过也不计为失败）",
            )
        )
    else:
        ratio = (cur_tokens - base_tokens) / base_tokens if base_tokens else 0.0
        delta, quality_note = _quality_delta(baseline_row, current_row, quality_tolerance)
        improved = delta > quality_tolerance
        degraded = delta < -quality_tolerance

        if ratio > tolerance and not improved:
            findings.append(
                Finding(
                    "token_regression",
                    False,
                    f"tokens {base_tokens:g}→{cur_tokens:g}（+{ratio:.0%}）超过容差 {tolerance:.0%}，"
                    f"但质量未提升：{quality_note}",
                    gating=True,
                )
            )
        elif ratio < -tolerance and degraded:
            findings.append(
                Finding(
                    "token_regression",
                    False,
                    f"tokens {base_tokens:g}→{cur_tokens:g}（{ratio:.0%}）虽然下降，"
                    f"但质量同时下降：{quality_note}。省下的 token 是拿准确率换的",
                    gating=True,
                )
            )
        elif ratio > tolerance:
            findings.append(
                Finding(
                    "token_regression",
                    True,
                    f"tokens {base_tokens:g}→{cur_tokens:g}（+{ratio:.0%}），质量提升：{quality_note}。"
                    "**是否值得这个价钱需人工确认**，门禁不代为判定为成功",
                    gating=True,
                )
            )
        else:
            findings.append(
                Finding(
                    "token_regression",
                    True,
                    f"tokens {base_tokens:g}→{cur_tokens:g}（{ratio:+.0%}）在容差内，{quality_note}",
                    gating=True,
                )
            )

    # 逐项明细：让「token 没变但上下文体量变了」也能被看见
    changed: list[str] = []
    for name, _direction in GATED_METRICS:
        before = baseline_row.get(name)
        after = current_row.get(name)
        if before is None or after is None or before == after:
            continue
        changed.append(f"{name} {before:g}→{after:g}")
    findings.append(
        Finding(
            "token_composition",
            True,
            "、".join(changed) if changed else "上下文构成与基线一致",
        )
    )
    return findings


def check_token_regression(
    current: RunResult,
    baseline: RunResult,
    *,
    tolerance: float = 0.10,
    quality_tolerance: float = 0.0,
) -> list[Finding]:
    """`compare_gate_metrics` 的 `RunResult` 包装：比较两次内存中的运行。"""

    return compare_gate_metrics(
        metric_row(baseline),
        metric_row(current),
        tolerance=tolerance,
        quality_tolerance=quality_tolerance,
    )


def load_artifact(path: Path) -> dict[str, Any]:
    """读回归档产物。门禁需要一份基线，基线只能来自上次归档。"""

    return json.loads(Path(path).read_text(encoding="utf-8"))


def _risk_matrix(runs: list[RunResult]) -> list[tuple[str, list[str], bool]]:
    """逐用例汇总各运行的风险等级，并标出是否一致。

    这是对比里信息量最大的一张表：**同一份日志上两个模型给出不同风险等级**，
    比「通过率都是 5/5」更能说明分歧在哪里。
    """

    names: list[str] = []
    for run in runs:
        for outcome in run.report.outcomes:
            if outcome.name not in names:
                names.append(outcome.name)

    rows: list[tuple[str, list[str], bool]] = []
    for name in names:
        levels = []
        for run in runs:
            match = next((o for o in run.report.outcomes if o.name == name), None)
            levels.append(match.risk_level if match else "—")
        rows.append((name, levels, len(set(levels)) <= 1))
    return rows


def _money(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.4f}"


def render_comparison(runs: list[RunResult], conditions: dict[str, str] | None = None) -> str:
    """多模型 / 多 Prompt 对比报告。

    三条口径：
    1. **缺账单显示 `n/a` 而不是 0**——「没测到」和「零成本」是两件事；
    2. **引用覆盖率只在可评估用例上求平均**——不可评估的用例不参与，也不当 0；
    3. **成本与质量必须同时呈现**，并在结尾给出联合结论。只列 token 的报告
       会诱导出「token 少了就是优化成功」的错误结论（路线图 P3 ⑥）。
    """

    lines = ["# AI 研判多运行对比", "", f"- 运行数：**{len(runs)}**"]
    for key, value in (conditions or {}).items():
        lines.append(f"- {key}：{value}")

    if not runs:
        lines.extend(["", "没有任何运行结果。", ""])
        return "\n".join(lines)

    lines.extend(
        [
            "",
            "## 质量与成本",
            "",
            "| 运行 | 通过 | 门禁 | 准确率 | 误报率 | 漏报率 | 引用覆盖率 | 总 tokens "
            "| 估算成本 | 计费用例 | 总耗时 |",
            "|---|---|---|---|---|---|---|---|---|---|---|",
        ]
    )
    for run in runs:
        tokens = "n/a" if run.tokens is None else str(run.tokens)
        lines.append(
            f"| {run.label} | {run.passed}/{run.total} "
            f"| {'通过' if not run.report.gate_failed else '**失败**'} "
            f"| {_percent(run.accuracy)} | {_percent(run.false_positive_rate)} "
            f"| {_percent(run.false_negative_rate)} | {_percent(run.citation_coverage)} "
            f"| {tokens} | {_money(run.estimated_cost)} "
            f"| {run.billed_cases}/{run.total} | {run.duration_ms / 1000:.1f}s |"
        )

    header = " | ".join(run.label for run in runs)
    lines.extend(
        [
            "",
            "## 逐用例风险等级",
            "",
            "同一份日志上不同运行给出不同风险等级，比「通过率都是满分」更能说明分歧在哪。",
            "",
            f"| 用例 | {header} | 一致性 |",
            f"|---|---{'---|' * len(runs)}---|",
        ]
    )
    for name, levels, consistent in _risk_matrix(runs):
        cells = " | ".join(levels)
        lines.append(f"| {name} | {cells} | {'一致' if consistent else '**分歧**'} |")

    disagreements = [row for row in _risk_matrix(runs) if not row[2]]
    if disagreements:
        lines.extend(
            [
                "",
                f"存在 **{len(disagreements)}** 条用例风险等级不一致："
                + "、".join(f"`{name}`" for name, _, _ in disagreements),
            ]
        )

    lines.extend(["", *render_verdict(runs)])
    return "\n".join(lines)


def render_verdict(runs: list[RunResult]) -> list[str]:
    """联合结论段。**禁止只以 Token 下降作为优化成功标准。**

    单运行时只陈述成本与质量的实测值，不做优化判定——没有对照就没有
    「优化」可言。多运行时以第一个运行为基线逐个比对。
    """

    lines = ["## 结论", ""]
    if len(runs) == 1:
        run = runs[0]
        lines.append(
            f"- 单次运行，**无对照基线，不做优化判定**。"
            f"准确率 {_percent(run.accuracy)}，"
            f"误报率 {_percent(run.false_positive_rate)}，"
            f"tokens {run.tokens if run.tokens is not None else 'n/a'}，"
            f"估算成本 {_money(run.estimated_cost)}。"
        )
        if run.estimated_cost is None:
            lines.append(
                "- 未配置单价，成本不可评估。**tokens 只能作为成本代理，不能当作成本结论**："
                "不同模型的单价差可达一个数量级，token 少的那个未必更便宜。"
            )
        lines.append("")
        return lines

    baseline = runs[0]
    lines.append(f"- 基线：**{baseline.label}**")
    lines.append("")
    for run in runs[1:]:
        findings = check_token_regression(run, baseline)
        gating = [f for f in findings if f.gating and not f.passed]
        base_tokens = baseline.tokens
        cur_tokens = run.tokens
        if base_tokens and cur_tokens is not None:
            ratio = f"{(cur_tokens - base_tokens) / base_tokens:+.0%}"
        else:
            ratio = "n/a"
        lines.append(
            f"### {run.label}（tokens {ratio}，"
            f"准确率 {_percent(baseline.accuracy)}→{_percent(run.accuracy)}，"
            f"误报率 {_percent(baseline.false_positive_rate)}→{_percent(run.false_positive_rate)}）"
        )
        lines.append("")
        lines.append(f"- 判定：**{'门禁失败' if gating else '可接受'}**")
        for finding in findings:
            lines.append(f"- `{finding.check}`：{finding.detail}")
        lines.append("")
    return lines


def build_artifact(runs: list[RunResult], *, generated_at: str | None = None) -> dict[str, Any]:
    """把多轮评测结果整理成可归档的 JSON 产物。

    保存的证据引用 / 耗时 / token 是**原始观测值**，不是汇总值——
    汇总一旦算错就无从复核，原始值可以重新聚合。
    """

    return {
        "generated_at": generated_at or datetime.now().isoformat(timespec="seconds"),
        "runs": [
            {
                "label": run.label,
                "conditions": dict(run.conditions),
                "summary": {
                    "total": run.total,
                    "passed": run.passed,
                    "gate_failed": run.report.gate_failed,
                    # 四舍五入到 4 位：浮点求平均会留下 0.44000000000000006 这种毛刺，
                    # 产物是要归档比对的，读起来不该像有精度信息。
                    "mean_confidence": _round(run.mean_confidence),
                    "mean_behaviors": _round(run.mean_behaviors),
                    "citation_coverage": _round(run.citation_coverage),
                    "tokens": run.tokens,
                    "billed_cases": run.billed_cases,
                    "duration_ms": round(run.duration_ms, 2),
                    # 质量侧：混淆矩阵与三个比率。缺样本侧时比率为 null，
                    # 不写 0——否则「没有正常用例」会显示成「误报率完美」。
                    "confusion": dict(
                        zip(("tp", "fp", "tn", "fn"), run.confusion, strict=True)
                    ),
                    "accuracy": _round(run.accuracy),
                    "false_positive_rate": _round(run.false_positive_rate),
                    "false_negative_rate": _round(run.false_negative_rate),
                    "estimated_cost": _round(run.estimated_cost),
                    # 门禁比较用的行。存进产物，基线才能被下一轮直接读出来比对。
                    "gate_metrics": metric_row(run),
                },
                "cases": [
                    {
                        "name": outcome.name,
                        "family": outcome.family,
                        "passed": outcome.passed,
                        "risk_level": outcome.risk_level,
                        "confidence": outcome.confidence,
                        "behavior_count": outcome.behavior_count,
                        "citation_coverage": outcome.citation_coverage,
                        "duration_ms": round(outcome.duration_ms, 2),
                        # 缺账单写 null，不写 0
                        "usage": dict(outcome.usage) or None,
                        "metrics": dict(outcome.metrics) or None,
                        "evidence_refs": list(outcome.evidence_refs),
                        "dropped_evidence_ids": list(outcome.dropped_evidence_ids),
                        "gating_failures": [f.check for f in outcome.gating_failures],
                    }
                    for outcome in run.report.outcomes
                ],
            }
            for run in runs
        ],
    }


def write_artifact(path: Path, runs: list[RunResult]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(build_artifact(runs), ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return path
