"""规则质量评估 CLI：调用 app.services.rule_quality，输出报告并可写入 docs/。

用法：
    cd backend && .venv\\Scripts\\python.exe scripts\\eval_rules.py            # 打印报告，存在偏差时非零退出
    cd backend && .venv\\Scripts\\python.exe scripts\\eval_rules.py --write    # 同时写入 docs/rule-quality-report.md
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_ROOT))

from app.services.rule_metadata import (  # noqa: E402
    check_rule_metadata,
    check_validation_consistency,
    render_violations,
)
from app.services.rule_quality import evaluate, render_markdown  # noqa: E402
from app.services.rules import get_rules  # noqa: E402

REPORT_PATH = BACKEND_ROOT.parent / "docs" / "rule-quality-report.md"


def main() -> int:
    parser = argparse.ArgumentParser(description="规则质量评估")
    parser.add_argument("--write", action="store_true", help="写入 docs/rule-quality-report.md")
    arguments = parser.parse_args()

    # Windows 默认控制台可能仍是 GBK；报告含中文和警告符号时不能让打印阻断 --write。
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    report = evaluate()
    markdown = render_markdown(report)
    print(markdown)

    # 元数据门禁：格式合法性 + 「声明 validated 必须有本地正样本」的一致性。
    rules = get_rules()
    covered = {item.rule_id for item in report.rules if item.positive > 0}
    violations = check_rule_metadata(rules) + check_validation_consistency(rules, covered)
    print()
    print(render_violations(violations))

    if arguments.write:
        REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
        REPORT_PATH.write_text(markdown, encoding="utf-8")
        print(f"已写入 {REPORT_PATH}")
    has_gap = (
        report.false_positive
        or report.false_negative
        or report.uncovered_rules
        or violations
    )
    return 1 if has_gap else 0


if __name__ == "__main__":
    raise SystemExit(main())
