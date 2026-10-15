"""AI 研判质量门禁 CLI：跑评测用例，输出报告，有门禁失败时非零退出。

用法：
    cd backend && .venv\\Scripts\\python.exe scripts\\eval_ai.py            # 确定性替身，打印报告
    cd backend && .venv\\Scripts\\python.exe scripts\\eval_ai.py --write    # 同时写入 docs/ai-quality-report.md
    cd backend && .venv\\Scripts\\python.exe scripts\\eval_ai.py --real     # 走真实模型（需 .env 配好 key）

多模型 / 多 Prompt 对比（`--real` 才有区分度）：
    cd backend && .venv\\Scripts\\python.exe scripts\\eval_ai.py --real ^
        --model deepseek-chat --model qwen-plus ^
        --prompt prompts/concise.txt --artifacts evaluation/artifacts

默认使用**确定性替身**（把规则结果原样表述为 AI 结论）：它不访问网络、结果可复现，
适合放进 CI。`--real` 才调用真实模型——真实模型输出有随机性，不适合作为阻断式门禁，
只在人工评估时使用。
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from contextlib import nullcontext
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

BACKEND_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_ROOT))

from app.models import AnalysisResult  # noqa: E402
from app.services import ai as ai_service  # noqa: E402
from app.services.ai_eval import (  # noqa: E402
    AiCase,
    EvalReport,
    RunResult,
    compare_gate_metrics,
    evaluate,
    load_artifact,
    load_cases,
    metric_row,
    render_comparison,
    render_markdown,
    write_artifact,
)

REPORT_PATH = BACKEND_ROOT.parent / "docs" / "ai-quality-report.md"


def _rules_echo_answer(result: AnalysisResult) -> dict[str, object]:
    """把规则结果原样表述为一份 AI 结论，作为确定性基线。

    这不是「正确答案」的模拟——它只是把**已经确定的规则结论**换成 AI 的措辞，
    因此每个用例的期望值都能从规则实测结果推导。真实模型若连这个基线都达不到，
    说明它在退化而不是在推理。
    """

    behaviors = []
    for event in result.events:
        evidence_ids = [item.id for item in event.evidence_items if item.id][:3]
        behaviors.append(
            {
                "type": event.type,
                "name": event.name,
                "confidence": 0.8,
                "evidence": [item.raw for item in event.evidence_items if item.raw][:2]
                or [event.summary or event.name],
                "evidence_ids": evidence_ids,
                "analysis": event.summary or event.name,
            }
        )
    return {
        "risk_level": result.risk_level,
        "confidence": 0.8 if behaviors else 0.2,
        "summary": result.conclusion,
        "behaviors": behaviors,
        "recommendations": list(result.recommendations[:3]),
    }


class _StaticProvider:
    """确定性替身：固定返回给定 JSON，不访问网络。"""

    supports_tools = False
    last_usage = {"rounds": 1, "prompt_tokens": 100, "completion_tokens": 50}

    def __init__(self, content: str) -> None:
        self._content = content
        self.last_content = content

    def complete(self, system_prompt, context, on_delta=None):  # noqa: ANN001
        return self._content


def _prompt_override(system_prompt: str | None):
    """Prompt 变体：临时替换系统提示。

    `SYSTEM_PROMPT` 是**调用时**读取的模块全局（`_request_content` 里
    `system_prompt = SYSTEM_PROMPT + reminder`），所以 patch 模块属性真的生效。
    不传变体时用 `nullcontext`，不做无意义的 patch。
    """

    if system_prompt is None:
        return nullcontext()
    return patch.object(ai_service, "SYSTEM_PROMPT", system_prompt)


def make_deterministic_judge(system_prompt: str | None = None):
    """返回一个判据函数：走真实校验管线，但模型调用由替身完成。"""

    def judge(case: AiCase, result: AnalysisResult, records):
        answer = _rules_echo_answer(result)
        raw = json.dumps(answer, ensure_ascii=False)
        provider = _StaticProvider(raw)
        with (
            _prompt_override(system_prompt),
            patch.object(ai_service, "_create_provider", lambda: provider),
            patch.object(ai_service, "_run_auto_tools", lambda _result, _records: ({}, [])),
        ):
            judgement = ai_service.request_ai_judgement(result, records)
        return judgement, raw

    return judge


def make_real_judge(system_prompt: str | None = None):
    """返回一个判据函数：调用 `.env` 中配置的真实模型。"""

    def judge(case: AiCase, result: AnalysisResult, records):
        with _prompt_override(system_prompt):
            judgement = ai_service.request_ai_judgement(result, records)
        return judgement, json.dumps(judgement, ensure_ascii=False, default=str)

    return judge


def _print_summary(report: EvalReport) -> None:
    total = len(report.outcomes)
    passed = total - len(report.failed)
    print(f"用例：{passed}/{total} 通过")
    for outcome in report.failed:
        print(f"  失败 {outcome.name}：")
        for finding in outcome.gating_failures:
            print(f"    - {finding.check}: {finding.detail}")


def _compose(runs: list[RunResult], conditions: dict[str, str]) -> str:
    """单次运行就是原来的报告；多次运行则先给对比表，再附每轮明细。"""

    if len(runs) == 1:
        return render_markdown(runs[0].report, runs[0].conditions)
    parts = [render_comparison(runs, conditions)]
    for run in runs:
        parts.extend(["", "---", "", f"## 运行明细：{run.label}", "", render_markdown(run.report, run.conditions)])
    return "\n".join(parts)


def _run_matrix(
    cases: list[AiCase], arguments: argparse.Namespace, base_conditions: dict[str, str]
) -> list[RunResult]:
    """按 (模型 × Prompt) 组合逐个运行。

    **模型必须逐个设进 `AI_MODEL` 再跑**：`_create_provider()` 每次调用都重新读
    环境变量，所以同一个进程里换模型是可行的；但反过来，跑完一轮不复位就意味着
    后续轮次会继承上一轮的模型，所以这里由外层循环独占赋值。
    """

    configured = ai_service.check_ai_config()
    runs: list[RunResult] = []
    for model in arguments.model or [None]:
        if model:
            os.environ["AI_MODEL"] = model
        model_label = model or f"{configured.provider}/{configured.model}"

        for prompt_path in arguments.prompt or [None]:
            system_prompt = None
            prompt_label = "内置 SYSTEM_PROMPT"
            if prompt_path:
                system_prompt = Path(prompt_path).read_text(encoding="utf-8")
                prompt_label = Path(prompt_path).name

            conditions = dict(base_conditions)
            conditions["模型"] = model_label
            conditions["Prompt"] = prompt_label
            label = f"{model_label} + {prompt_label}"
            print(f"[运行] {label}", file=sys.stderr)

            judge = (
                make_real_judge(system_prompt)
                if arguments.real
                else make_deterministic_judge(system_prompt)
            )
            runs.append(
                RunResult(
                    label=label,
                    report=evaluate(cases, judge),
                    conditions=conditions,
                )
            )
    return runs


def _run_baseline_gate(runs: list[RunResult], path: Path) -> tuple[list[str], list[str]]:
    """把本次运行与归档基线逐项比对，返回 (报告段落, 门禁失败说明)。

    基线取**同名 label** 的运行（label 由「模型 + Prompt」组成），因此换了模型
    或 Prompt 不会误比到别的组合上——那种情况只提示跳过，不静默当通过。
    """

    payload = load_artifact(path)
    stored = {str(item.get("label")): item for item in payload.get("runs") or []}
    lines = [
        "",
        "## 与基线的 Token × 质量回归门禁",
        "",
        f"- 基线产物：`{path.name}`（生成于 {payload.get('generated_at', '未知')}）",
        "- 口径：**只降 token 不算优化成功**——成本与质量必须同时呈现；"
        "质量下降时即便 token 大幅下降也判失败。",
        "",
    ]
    failures: list[str] = []
    for run in runs:
        baseline = stored.get(run.label)
        if baseline is None:
            lines.append(f"- `{run.label}`：基线中无同名运行，**跳过比对（不计为通过）**")
            continue
        row = (baseline.get("summary") or {}).get("gate_metrics")
        if not isinstance(row, dict):
            lines.append(f"- `{run.label}`：基线未存 gate_metrics，**跳过比对（不计为通过）**")
            continue
        lines.append(f"### {run.label}")
        lines.append("")
        for finding in compare_gate_metrics(row, metric_row(run)):
            if finding.gating and not finding.passed:
                lines.append(f"- **失败** `{finding.check}`：{finding.detail}")
                failures.append(f"{run.label} / {finding.check}: {finding.detail}")
            else:
                lines.append(f"- 通过 `{finding.check}`：{finding.detail}")
        lines.append("")
    return lines, failures


def main() -> int:
    parser = argparse.ArgumentParser(description="AI 研判质量门禁")
    parser.add_argument("--write", action="store_true", help="写入 docs/ai-quality-report.md")
    parser.add_argument(
        "--smoke",
        action="store_true",
        help="只跑最小回归集（标记 smoke: true 的用例），用于 Prompt / AI 代码改动后的快速回归",
    )
    parser.add_argument(
        "--real",
        action="store_true",
        help="调用真实模型（需在 .env 配好 key）；默认用确定性替身",
    )
    parser.add_argument(
        "--model",
        action="append",
        metavar="MODEL",
        help="指定模型名，可重复。多次给出即做多模型对比（配合 --real 才有区分度）",
    )
    parser.add_argument(
        "--prompt",
        action="append",
        metavar="FILE",
        help="用文件内容替换系统提示，可重复。多次给出即做多 Prompt 对比",
    )
    parser.add_argument(
        "--artifacts",
        metavar="DIR",
        help="把评测产物（含证据引用 / 耗时 / token）写成 JSON，落到该目录",
    )
    parser.add_argument(
        "--baseline",
        metavar="FILE",
        help="与一份归档产物做 Token × 质量联合回归门禁；有门禁失败时非零退出",
    )
    arguments = parser.parse_args()

    # Windows 默认控制台可能是 GBK；报告含中文时不能让打印阻断 --write。
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    cases = load_cases(smoke_only=arguments.smoke)
    if not cases:
        print("未找到任何评测用例，请检查 evaluation/ai-cases/")
        return 1

    if arguments.real:
        status = ai_service.check_ai_config()
        if not status.configured:
            print(f"未配置真实模型，已跳过真实评测：{status.message}")
            print("（这不是通过——请配置 AI key 后重跑，或去掉 --real 使用确定性替身。）")
            return 1
        base_conditions = {
            "判据": "真实模型（输出有随机性，不适合作为阻断式门禁）",
        }
    else:
        base_conditions = {
            "判据": "确定性替身（把规则结论换个措辞）——**不是真实模型评测**，"
            "通过只说明检查器与管线自洽，不代表模型判得准",
        }
    sigma = (os.getenv("RULE_SIGMA_IMPORTED_ENABLED") or "true").strip().lower()
    base_conditions["规则集"] = (
        "仅内置规则（Sigma 社区规则已关闭）"
        if sigma in {"0", "false", "no", "off", "disabled"}
        else "内置规则 + Sigma 社区规则"
    )
    base_conditions["用例范围"] = (
        f"最小回归集（{len(cases)} 条，标记 smoke: true）"
        if arguments.smoke
        else f"完整集（{len(cases)} 条）"
    )

    runs = _run_matrix(cases, arguments, base_conditions)
    markdown = _compose(runs, base_conditions)

    # 基线门禁在**写报告之前**跑：门禁结论属于报告的一部分，
    # 只打到 stdout 会让 --write 出的文件看起来「门禁通过」。
    gate_failures: list[str] = []
    if arguments.baseline:
        baseline_path = Path(arguments.baseline)
        if not baseline_path.is_absolute():
            baseline_path = BACKEND_ROOT / baseline_path
        if not baseline_path.exists():
            print(f"基线文件不存在：{baseline_path}")
            return 1
        gate_lines, gate_failures = _run_baseline_gate(runs, baseline_path)
        markdown = "\n".join([markdown, *gate_lines])

    print(markdown)
    for run in runs:
        print(f"\n[{run.label}]")
        _print_summary(run.report)

    if len(runs) > 1 and not arguments.real:
        print(
            "\n提示：多运行对比在使用确定性替身时**没有区分度**——替身对每个运行返回同一份结论。"
            "要看真实差异请加 --real。"
        )

    if arguments.write:
        REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
        REPORT_PATH.write_text(markdown, encoding="utf-8")
        print(f"已写入 {REPORT_PATH}")

    if arguments.artifacts:
        directory = Path(arguments.artifacts)
        if not directory.is_absolute():
            directory = BACKEND_ROOT / directory
        stamp = datetime.now().strftime("%Y%m%dT%H%M%S")
        print(f"已写入评测产物 {write_artifact(directory / f'ai-eval-{stamp}.json', runs)}")

    if gate_failures or any(run.report.gate_failed for run in runs):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
