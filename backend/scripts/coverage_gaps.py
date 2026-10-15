"""覆盖缺口自检：列出「没有任何规则命中」的记录，用于发现漏检并驱动补规则。

用法：
    cd backend && .venv\\Scripts\\python.exe scripts\\coverage_gaps.py <日志文件> [...]
    cd backend && .venv\\Scripts\\python.exe scripts\\coverage_gaps.py evaluation\\scenarios\\*.log

输出：总体覆盖度 + 未命中记录按「日志类型 / 状态码 / 行为主体」分组的清单。
未被任何规则覆盖 ≠ 可疑，但它是「我们还没建立判据」的明确信号。
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_ROOT))

from app.services.parser import parse_upload  # noqa: E402
from app.services.rules_engine import load_rules  # noqa: E402

SUBJECT_FIELDS = (
    "process_image",
    "target_filename",
    "registry_key",
    "query_name",
    "url",
    "raw",
)


def _subject(record: dict[str, str | None]) -> str:
    for field in SUBJECT_FIELDS:
        value = record.get(field)
        if value:
            return str(value)[:96]
    return "-"


def report(path: Path, rules) -> None:
    parsed = parse_upload(path.read_bytes())
    records = [
        {**record, "log_type": parsed.log_type, "record_id": f"record-{index}"}
        for index, record in enumerate(parsed.records, start=1)
    ]
    covered: set[str] = set()
    rules_by_record: dict[str, list[str]] = {}
    for rule in rules:
        if not rule.enabled:
            continue
        for record in records:
            if rule.covers(record):
                record_id = record["record_id"]
                covered.add(record_id)
                rules_by_record.setdefault(record_id, []).append(rule.id)

    missed = [record for record in records if record["record_id"] not in covered]
    print("=" * 78)
    print(f"{path.name}  日志类型={parsed.log_type}  解析={parsed.parsed_lines} 条"
          f"  未解析={parsed.parse_failures} 条")
    print(f"  覆盖 {len(covered)}/{len(records)} 条，未覆盖 {len(missed)} 条")
    if not missed:
        print("  未发现覆盖缺口。")
        return
    print("  未命中记录（按 状态码 / 行为主体 归并）：")
    groups: Counter[tuple[str | None, str]] = Counter(
        (record.get("status"), _subject(record)) for record in missed
    )
    for (status, subject), count in groups.most_common():
        print(f"    x{count:<3} status={status or '-':<6} {subject}")


def main() -> int:
    parser = argparse.ArgumentParser(description="日志检测覆盖缺口自检")
    parser.add_argument("paths", nargs="+", help="待检查的日志文件")
    arguments = parser.parse_args()

    rules = load_rules()
    for raw_path in arguments.paths:
        path = Path(raw_path)
        if not path.is_file():
            print(f"跳过（不存在）：{path}")
            continue
        report(path, rules)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
