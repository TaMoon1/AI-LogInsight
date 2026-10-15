"""量化 AI 研判 Token 优化的真实收益。

对比「优化前 / 优化后」的上下文体积与多轮累计输入，用于验证
tool_results 去重、历史裁剪、字段白名单、轮次收敛、工具结果裁剪五项改动的效果。

用法： .venv\\Scripts\\python.exe scripts\\bench_ai_context.py
"""
from __future__ import annotations

import io
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

from app.services import ai as ai_module  # noqa: E402
from app.services.agent_tools import execute_tool  # noqa: E402
from app.services.ai import (  # noqa: E402
    AUTO_TOOL_PLAN,
    SYSTEM_PROMPT,
    _run_auto_tools,
    _shrink_history_context,
    build_ai_context,
)
from app.services.analyzer import (  # noqa: E402
    analyze_parsed_logs,
    assign_record_ids,
    collect_records,
)
from app.services.parser import parse_upload  # noqa: E402
from app.services.sanitizer import sanitize_records  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
TARGETS = [
    ROOT / "data/uploads/9ad93485-b5d7-47d5-a015-e5bb148e2d08/access.log",
    ROOT / "data/uploads/2b1563b4-b770-4feb-acf7-cc7c2a25ca29/安全.evtx",
    ROOT / "data/uploads/033e7af4-6117-4e1a-b89a-5711f8b03e00/域控10.0.0.11-异常登录列表_20260921113554.xlsx",
]


def size(value) -> int:
    return len(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))


def bench_tool_results(parsed, records, result, label: str) -> None:
    """单独量化「模型按需查工具」时的单次返回体积。

    这部分不经过上下文预算，容易成为盲区——实测 `query_terminal_chains` 一条链
    曾达 71 KB，比整个首轮上下文还大。
    """

    plan = [
        ("log_metadata", {}),
        ("log_statistics", {}),
        ("query_events", {"limit": 20}),
        ("timeline", {"limit": 50}),
        ("query_evidence", {"limit": 20}),
        ("query_terminal_chains", {}),
        ("query_uncovered_records", {"limit": 20}),
        ("query_behavior_deviations", {}),
    ]
    print()
    print(f"工具返回体积（模型按需查询，不计入上下文预算）— {label}")
    print("-" * 112)
    total = 0
    for tool, arguments in plan:
        output = execute_tool(tool, arguments, result, records)
        measured = size(output)
        total += measured
        print(f"  {tool:26s} {measured:>10,} B")
    print(f"  {'合计（一次全查）':26s} {total:>10,} B")


def main() -> None:
    print("=" * 112)
    print("AI 研判上下文优化效果（字节 / 中文 JSON 约 2 字节 = 1 token）")
    print("=" * 112)
    header = (
        f"{'文件':<32}{'记录':>7}{'事件':>6}{'优化前':>11}{'优化后':>11}"
        f"{'首轮降幅':>9}{'优化前累计':>12}{'优化后累计':>12}{'总降幅':>8}"
    )
    print(header)
    print("-" * 112)
    tool_def = size({"t": list(ai_module.AGENT_TOOLS)})
    sys_p = size({"p": SYSTEM_PROMPT})

    for path in TARGETS:
        if not path.exists():
            continue
        parsed = parse_upload(path.read_bytes())
        result = analyze_parsed_logs([path.name], [parsed])
        records = assign_record_ids(collect_records([path.name], [parsed]))

        # 优化后：build_ai_context（含字段白名单）→ 挂 tool_results（指针化）→ 统一预算校验
        context = build_ai_context(result, records)
        outputs, _ = _run_auto_tools(result, records)
        context["tool_results"] = outputs
        context = ai_module._fit_context_budget(context)
        after_first = size(context)

        # 还原「优化前」：工具结果原样全量 + 记录样本不裁字段
        legacy = build_ai_context(result, records)
        raw_outputs: dict = {}
        for name, arguments in AUTO_TOOL_PLAN:
            raw_outputs[name] = ai_module.execute_tool(name, arguments, result, records)
        legacy["tool_results"] = raw_outputs

        # 计算优化前的字段膨胀：用未裁剪的 sanitize_records 重算两个样本块
        full_records = sanitize_records(records)
        covered_ids = {r.get("record_id") for r in full_records}
        picked = ai_module._sample_event_indexes(result.events, ai_module.EVENT_SAMPLE_LIMIT)
        event_record_ids = {
            e.record_id
            for i in picked
            for e in result.events[i].evidence_items[: ai_module.EVENT_EVIDENCE_ITEM_LIMIT]
            if e.record_id
        }
        limit = ai_module._sample_limit(len(records))
        legacy["records_sample"] = sanitize_records(
            [
                r
                for r in ai_module._stratified_sample(full_records, limit)
                if r.get("record_id") not in event_record_ids
            ]
        )
        legacy["uncovered_records_sample"] = sanitize_records(
            ai_module._stratified_sample(full_records, limit)
        )
        before_first = size(legacy)

        rounds_before = ai_module.DEFAULT_TOOL_ROUNDS
        if len(records) >= ai_module.LARGE_LOG_RECORDS:
            rounds_before = ai_module.DEFAULT_TOOL_ROUNDS * 2
        if not result.events:
            rounds_before = 1

        def cumulative(ctx_body: dict, rounds: int) -> int:
            history = sys_p + size(ctx_body) + tool_def
            total = 0
            for _ in range(rounds):
                total += history
                history += 6000
            total += history
            return total

        agg_before = cumulative(legacy, rounds_before)
        # 优化后：首轮后历史被换成占位，后续轮次只需重发占位 + 工具结果
        history = sys_p + after_first + tool_def
        total = history
        for _ in range(rounds_before):
            history = sys_p + size(
                {"c": ai_module._history_context_placeholder(context)}
            ) + tool_def + 6000 * (1)
            total += history
        agg_after = total

        print(
            f"{path.name[:31]:<32}{len(records):>7}{len(result.events):>6}"
            f"{before_first:>11,}{after_first:>11,}"
            f"{100 - after_first * 100 // max(before_first, 1):>8}%"
            f"{agg_before:>12,}{agg_after:>12,}"
            f"{100 - agg_after * 100 // max(agg_before, 1):>7}%"
        )
        if result.terminal_chains:
            bench_tool_results(parsed, records, result, path.name)
    print("-" * 112)
    print("优化前 = 工具结果原样全量 + 记录样本不裁字段；优化后 = 指针化 + 字段白名单 + 历史裁剪。")
    print("累计输入按「每轮完整重发历史」估算（真实行为），轮次取优化前上限。")


if __name__ == "__main__":
    main()
