"""批量导入 SigmaHQ 社区规则（P3-02）。

用法：
    cd backend && .venv\\Scripts\\python.exe scripts\\import_sigma_community.py \
        --sigma-dir <SigmaHQ 检出目录> --source-version <commit/标签>        # 预演
    cd backend && .venv\\Scripts\\python.exe scripts\\import_sigma_community.py \
        --sigma-dir <...> --source-version <...> --write                     # 写文件

为什么不把规则和样本一起打包：社区样本是第三方数据（许可 + 恶意样本处置风险），
本仓库只**导入转换后的规则**，并记录来源版本，方便随时重新生成。

漏斗（每一步都会写进报告，不允许「静默丢弃」）：
    候选 → 转换成功（无法映射的整条跳过并给原因）
         → 去重（同 uuid / 同标题 / 同判据签名只留一条）
         → 误报裁剪（在本地语料的**正常流量用例**上必须零命中）
         → 写入 rules/95-sigma-community.yaml
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

BACKEND_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_ROOT))

from app.services.parser import parse_log  # noqa: E402
from app.services.rule_quality import load_corpus  # noqa: E402
from app.services.rules_engine import build_rule, evaluate_rule  # noqa: E402
from app.services.sigma_import import (  # noqa: E402
    SIGMA_METADATA,
    ConversionError,
    convert_rule,
    write_rules,
)

#: SigmaHQ `rules/windows/` 下的全部子目录。**默认必须是全集**：
#: 2026-10-13 实测踩过——默认只写了 2 个子目录，而文档里的复现命令没带 `--dirs`，
#: 照文档重跑会静默少导入 447 条（2417 候选 → 1517），且不报错。
DEFAULT_DIRS = (
    "windows/builtin",
    "windows/create_remote_thread",
    "windows/create_stream_hash",
    "windows/dns_query",
    "windows/driver_load",
    "windows/file",
    "windows/image_load",
    "windows/network_connection",
    "windows/pipe_created",
    "windows/powershell",
    "windows/process_access",
    "windows/process_creation",
    "windows/process_tampering",
    "windows/raw_access_thread",
    "windows/registry",
    "windows/sysmon",
    "windows/wmi_event",
)
DEFAULT_OUTPUT = BACKEND_ROOT / "rules" / "95-sigma-community.yaml"
DEFAULT_REPORT = BACKEND_ROOT.parent / "docs" / "sigma-import-report.md"
SIGMA_REPO = "https://github.com/SigmaHQ/sigma"


def _existing_rule_ids(exclude: Path) -> set[str]:
    """收集已落盘的规则 id，避免和 90-sigma.yaml（人工精选的 7 条）重复。

    否则同一 `sigma.<uuid>` 会出现在两个文件里，`get_rules()` 会加载两条同 id 规则，
    同一行为产出重复事件。
    """

    import re as _re

    ids: set[str] = set()
    for path in (BACKEND_ROOT / "rules").glob("*.yaml"):
        if path.resolve() == exclude.resolve():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        ids.update(_re.findall(r"^\s*- id:\s*(sigma\.[0-9a-fA-F-]+)", text, _re.MULTILINE))
    return ids


def _documents(sigma_dir: Path, subdirs: tuple[str, ...]) -> list[tuple[Path, dict]]:
    root = sigma_dir / "rules" if (sigma_dir / "rules").is_dir() else sigma_dir
    documents: list[tuple[Path, dict]] = []
    for sub in subdirs:
        for path in sorted((root / sub).rglob("*.yml")):
            try:
                document = yaml.safe_load(path.read_text(encoding="utf-8"))
            except yaml.YAMLError:
                continue
            if isinstance(document, dict):
                documents.append((path, document))
    return documents


def _signature(rule: dict[str, Any]) -> str:
    detection = rule.get("detection") or {}
    return json.dumps(
        [rule.get("logsource"), detection.get("where"), detection.get("any")],
        ensure_ascii=False,
        sort_keys=True,
    )


def _with_log_type(
    records: list[dict[str, str | None]], log_type: str
) -> list[dict[str, str | None]]:
    """给记录补上 `log_type`，不改动传入的字典。

    真正跑分析时 `analyzer` 会给每条记录写入 `log_type`；导入筛查直接调
    `evaluate_rule` 绕过了那一步——不补的话，带日志类型限制的规则在筛查时一律不匹配，
    「正常流量零命中」就变成了空过。
    """

    return [{**record, "log_type": log_type} for record in records]


def _negative_records() -> list[tuple[str, list[dict[str, str | None]]]]:
    """本地语料里的「正常流量」用例（没有任何期望命中那些就是负样本）。"""

    prepared: list[tuple[str, list[dict[str, str | None]]]] = []
    for case in load_corpus():
        if case.get("expect"):
            continue
        name = str(case.get("name") or case.get("file") or "unnamed")
        log_type = str(case.get("log_type") or "generic")
        if case.get("records") is not None:
            prepared.append((name, _with_log_type(list(case["records"]), log_type)))
            continue
        parsed = parse_log(str(case.get("log") or ""))
        prepared.append(
            (name, _with_log_type(parsed.records, str(case.get("log_type") or parsed.log_type)))
        )
    return prepared


def main() -> int:
    parser = argparse.ArgumentParser(description="批量导入 SigmaHQ 社区规则")
    parser.add_argument("--sigma-dir", required=True, help="SigmaHQ 检出目录（含 rules/）")
    parser.add_argument("--dirs", default=",".join(DEFAULT_DIRS), help="要导入的子目录")
    parser.add_argument("--source-version", default="unknown", help="commit 或标签，写进报告")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    parser.add_argument("--report", default=str(DEFAULT_REPORT))
    parser.add_argument("--write", action="store_true", help="写规则文件与报告")
    arguments = parser.parse_args()

    sigma_dir = Path(arguments.sigma_dir)
    if not sigma_dir.is_dir():
        print(f"SigmaHQ 目录不存在：{sigma_dir}")
        return 1
    subdirs = tuple(item.strip() for item in arguments.dirs.split(",") if item.strip())

    documents = _documents(sigma_dir, subdirs)
    candidate_total = len(documents)
    print(f"候选规则：{candidate_total}")

    # 过滤掉已落盘的规则（如 90-sigma.yaml 里人工精选的 7 条），避免同 id 双份。
    # 注意打印的是**实际排除条数**：既有 id 有 7 个，但它们不全在这批候选里
    # （精选规则来自其它子目录），早先这里打印的是 `len(pre_existing)`，
    # 会让人以为排除了 7 条，实际只有 1 条。
    output_path = Path(arguments.output)
    pre_existing = _existing_rule_ids(output_path)
    excluded_preexisting: list[tuple[str, str]] = []
    if pre_existing:
        remaining: list[tuple[Path, dict[str, Any]]] = []
        for path, document in documents:
            raw_id = str(document.get("id") or "")
            if raw_id in pre_existing or f"sigma.{raw_id}" in pre_existing:
                excluded_preexisting.append(
                    (path.name, str(document.get("title") or path.stem))
                )
            else:
                remaining.append((path, document))
        documents = remaining
        print(
            f"排除已落盘的重复规则 {len(excluded_preexisting)} 条"
            f"（比对的既有 id 共 {len(pre_existing)} 个）后：{len(documents)}"
        )

    converted: list[dict[str, Any]] = []
    skipped_reasons: Counter[str] = Counter()
    skipped_examples: dict[str, str] = {}
    # 逐条留痕：文件名 + 标题 + 完整原因。汇总表只给每类一个示例，
    # 查「某条具体规则为什么没进来」要靠这份全量清单。
    skipped_rules: list[tuple[str, str, str]] = []
    for path, document in documents:
        title = str(document.get("title") or path.stem)
        try:
            converted.append(convert_rule(document))
        except ConversionError as exc:
            reason = str(exc).split("：")[0]
            skipped_reasons[reason] += 1
            skipped_rules.append((path.name, title, str(exc)))
            skipped_examples.setdefault(reason, f"{path.name}：{exc}")
        except Exception as exc:  # noqa: BLE001 - 单条规则异常不能中断整批导入
            reason = f"解析异常（{type(exc).__name__}）"
            skipped_reasons[reason] += 1
            skipped_rules.append((path.name, title, f"{reason}：{exc}"))
            skipped_examples.setdefault(reason, f"{path.name}：{exc}")
    print(f"转换成功：{len(converted)}；跳过：{len(documents) - len(converted)}")

    # 去重：同 uuid / 同标题 / 同判据签名只留一条（保留先出现的）
    unique: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    seen_titles: set[str] = set()
    seen_signatures: set[str] = set()
    duplicates: list[tuple[str, str]] = []
    for rule in converted:
        title = str(rule.get("title") or "")
        signature = _signature(rule)
        if rule["id"] in seen_ids:
            duplicates.append((rule["id"], "同 uuid"))
            continue
        if title in seen_titles:
            duplicates.append((rule["id"], f"同标题：{title}"))
            continue
        if signature in seen_signatures:
            duplicates.append((rule["id"], "同判据（logsource+where+any 完全一致）"))
            continue
        seen_ids.add(rule["id"])
        seen_titles.add(title)
        seen_signatures.add(signature)
        unique.append(rule)
    print(f"去重后：{len(unique)}（重复 {len(duplicates)}）")

    # 误报裁剪：正常流量用例上必须零命中
    negatives = _negative_records()
    kept: list[dict[str, Any]] = []
    rejected: list[tuple[str, str, str]] = []
    duplicate_hits = 0
    for rule in unique:
        built = build_rule(rule, source="sigma")
        hit_case = ""
        for name, records in negatives:
            if evaluate_rule(built, records):
                hit_case = name
                break
        if hit_case:
            rejected.append((rule["id"], str(rule.get("title") or ""), hit_case))
            continue
        kept.append(rule)
    print(f"误报裁剪后保留：{len(kept)}（因命中正常流量剔除 {len(rejected)}）")

    # 与内置规则重叠情况：在**有事件期望**的用例上命中，属重复检出（不算误报，但要报出来）
    positive_cases = [
        case for case in load_corpus() if case.get("expect") and case.get("log")
    ]
    overlapping: list[tuple[str, str]] = []
    for rule in kept:
        built = build_rule(rule, source="sigma")
        for case in positive_cases:
            parsed = parse_log(str(case.get("log") or ""))
            records = _with_log_type(
                parsed.records, str(case.get("log_type") or parsed.log_type)
            )
            if evaluate_rule(built, records):
                overlapping.append((rule["id"], str(case.get("name") or "")))
                duplicate_hits += 1
                break

    levels = Counter(str(rule.get("level") or "info") for rule in kept)

    # 逐条元数据来源：author / references 直接取自源 Sigma 规则（`sigma_references` 只收
    # http(s) 链接）。非链接的参考文本不计入，但必须报出来——「不静默丢弃」。
    non_url_references = sum(
        1
        for _path, document in documents
        for item in (document.get("references") or [])
        if not str(item).strip().startswith(("http://", "https://"))
    )
    with_author = sum(1 for rule in kept if rule.get("author"))
    with_references = sum(1 for rule in kept if rule.get("references"))

    lines = [
        "# Sigma 社区规则导入报告",
        "",
        "> 由 `backend/scripts/import_sigma_community.py` 生成，勿手工编辑。",
        f"> 来源：{SIGMA_REPO} · 版本：`{arguments.source_version}` · 生成时间："
        f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        "## 导入漏斗",
        "",
        "| 阶段 | 数量 | 说明 |",
        "| --- | ---: | --- |",
        f"| 候选规则 | {candidate_total} | 来自 {('、'.join(subdirs))} |",
        f"| 排除已落盘重复 | {len(excluded_preexisting)} | 与既有规则文件同 id，重复导入会让同一行为产出双份事件 |",
        f"| 转换成功 | {len(converted)} | logsource / 修饰符 / 通配 / 条件展开无法保持语义的一律整条跳过 |",
        f"| 去重后 | {len(unique)} | 同 uuid / 同标题 / 同判据只留一条 |",
        f"| 误报裁剪后 | {len(kept)} | 正常流量用例上必须零命中 |",
        f"| 带 `author` 元数据 | {with_author} / {len(kept)} | 取自源 Sigma 规则的 author 字段 |",
        f"| 带 `references` 元数据 | {with_references} / {len(kept)} | 只收 http(s) 链接；"
        f"源规则里另有 {non_url_references} 条非链接参考（如 `Internal Research`）未纳入 |",
        "",
        f"**级别分布（保留的 {len(kept)} 条）**：" 
        + "、".join(f"{level} {count}" for level, count in levels.most_common()),
        "",
        f"## 被排除的已落盘重复规则（{len(excluded_preexisting)} 条）",
        "",
        "这些规则的 id 已经存在于其它规则文件（典型是 `90-sigma.yaml` 里人工精选的那几条），"
        "再次导入会让同一行为同时产出内置事件与 `[Sigma]` 事件，故在转换前排除：",
        "",
        "| 规则文件 | 标题 |",
        "| --- | --- |",
    ]
    lines += [f"| `{name}` | {title.replace('|', '/')} |" for name, title in excluded_preexisting]
    lines += [
        "",
        "## 跳过原因（Top 15）",
        "",
        "> 这里只给每类原因一个示例。查「某条具体规则为什么没进来」请用文末的"
        "「附录：逐条跳过清单」，或用文件名 / 标题在本文档内检索。",
        "",
        "| 原因 | 条数 | 示例 |",
        "| --- | ---: | --- |",
    ]
    for reason, count in skipped_reasons.most_common(15):
        example = skipped_examples.get(reason, "").replace("|", "/")[:120]
        lines.append(f"| {reason} | {count} | {example} |")
    lines += [
        "",
        f"## 因命中正常流量被剔除（{len(rejected)} 条）",
        "",
        "这些规则在本地「正常流量」用例上产生了事件，按「不得虚假告警」的红线不导入：",
        "",
        "| 规则 | 命中的正常流量用例 |",
        "| --- | --- |",
    ]
    lines += [f"| `{rule_id}` {title} | {case} |" for rule_id, title, case in rejected[:40]]
    if len(rejected) > 40:
        lines.append(f"| … | 其余 {len(rejected) - 40} 条同理 |")
    lines += [
        "",
        f"## 与内置检测重叠（{len(overlapping)} 条，属重复检出不是误报）",
        "",
        "这些规则会在已有攻击样本上再次命中，说明它们与内置规则覆盖同一批行为。"
        "保留是为了不丢覆盖面，但分析结果里会同时出现内置事件与 `[Sigma]` 事件：",
        "",
        "| 规则 | 重叠的攻击样本用例 |",
        "| --- | --- |",
    ]
    lines += [f"| `{rule_id}` | {case} |" for rule_id, case in overlapping[:30]]
    lines += [
        "",
        "## 使用与限制（必须一起读）",
        "",
        f"- 这 {len(kept)} 条是**社区规则**，事件名带 `[Sigma]` 前缀、`source: sigma`，与内置规则区分。",
        "- 规则里的字段名就是 EVTX 的标准字段名（`OriginalFileName` / `Details` / "
        "`ParentCommandLine` …），解析器按标准结构把 `<System>` 事件头与 `<EventData>` 里"
        "每个 `<Data Name=\"…\">` 原样落进记录，转换时**直连**这些字段，不再做「从原文里"
        "抠字段」的近似匹配。",
        "- ⚠️ **它们没有本地正样本验证**：只做过「在正常流量用例上零命中」的筛查，"
        "不代表不会在真实环境误报。质量报告会把它们单列为「未验证的导入规则」。",
        f"- 一键停用全部社区规则：`RULE_SIGMA_IMPORTED_ENABLED=false`；单条停用按规则 id 生成的 "
        "`RULE_<标题>_ENABLED`。",
        f"- 重新生成：`cd backend && .venv\\Scripts\\python.exe scripts\\import_sigma_community.py "
        f"--sigma-dir <SigmaHQ 检出目录> --source-version <commit> --write`。",
        "",
    ]

    # 全量留痕：汇总表只给每类一个示例，这里把每条被跳过规则的原因完整列出，
    # 让「这条为什么没进来」可以直接检索（不静默丢弃）。
    if skipped_rules:
        lines += [
            f"## 附录：逐条跳过清单（{len(skipped_rules)} 条）",
            "",
            "按「原因 → 文件名」排序。原因里的字段名 / 修饰符名就是本项目记录模型缺失的部分，"
            "补上对应映射后重跑即可自动纳入：",
            "",
            "| 规则文件 | 标题 | 原因 |",
            "| --- | --- | --- |",
        ]
        for name, title, reason in sorted(skipped_rules, key=lambda item: (item[2], item[0])):
            lines.append(
                f"| `{name}` | {title.replace('|', '/')} | {reason.replace('|', '/')} |"
            )
        lines.append("")

    report = "\n".join(lines)

    if arguments.write:
        header = (
            "# 由 backend/scripts/import_sigma_community.py 生成的 SigmaHQ 社区规则，请勿手工编辑。\n"
            f"# 来源：{SIGMA_REPO} · 版本：{arguments.source_version}\n"
            f"# 重新生成：cd backend && .venv\\Scripts\\python.exe scripts\\import_sigma_community.py "
            f"--sigma-dir <SigmaHQ 检出目录> --source-version <commit> --write\n\n"
        )
        path = write_rules(
            kept,
            Path(arguments.output),
            header=header,
            metadata={
                **SIGMA_METADATA,
                "version": arguments.source_version,
                # 社区规则没有本地正样本，只做过「正常流量零命中」筛查。
                "validation_status": "unverified",
            },
        )
        print(f"已写入 {path}")
        report_path = Path(arguments.report)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(report, encoding="utf-8")
        print(f"已写入 {report_path}")
    else:
        print()
        print(report[:2000])
    return 0 if kept else 1


if __name__ == "__main__":
    raise SystemExit(main())
