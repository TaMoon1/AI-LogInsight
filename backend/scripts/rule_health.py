"""规则库体检 CLI：查重复规则、冲突规则、压制/升级链断裂与聚合失效。

用法：
    cd backend && .venv\\Scripts\\python.exe scripts\\rule_health.py           # 打印报告，有阻断项时非零退出
    cd backend && .venv\\Scripts\\python.exe scripts\\rule_health.py --write   # 同时写入 docs/rule-health-report.md

退出码：0 = 无阻断项；1 = 存在阻断项（观察项不阻断）。
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_ROOT))

from app.services.rule_health import check_rule_health, render_markdown  # noqa: E402
from app.services.rules import rule_objects  # noqa: E402

REPORT_PATH = BACKEND_ROOT.parent / "docs" / "rule-health-report.md"


def main() -> int:
    parser = argparse.ArgumentParser(description="规则库体检")
    parser.add_argument("--write", action="store_true", help="写入 docs/rule-health-report.md")
    arguments = parser.parse_args()

    # Windows 默认控制台可能仍是 GBK；报告含中文时不能让打印阻断 --write。
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    report = check_rule_health(rule_objects())
    markdown = render_markdown(report)
    print(markdown)
    if arguments.write:
        REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
        REPORT_PATH.write_text(markdown, encoding="utf-8")
        print(f"已写入 {REPORT_PATH}")
    return 0 if report.healthy else 1


if __name__ == "__main__":
    raise SystemExit(main())
