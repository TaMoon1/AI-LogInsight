"""生成 ATT&CK 技术覆盖报告。

用法：
    cd backend
    .venv\\Scripts\\python.exe scripts\\attack_coverage.py
    .venv\\Scripts\\python.exe scripts\\attack_coverage.py --write
    .venv\\Scripts\\python.exe scripts\\attack_coverage.py --benchmark path.json
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_ROOT))

from app.services.attack_coverage import (  # noqa: E402
    DEFAULT_BENCHMARK,
    evaluate_attack_coverage,
    render_markdown,
)

REPORT_PATH = BACKEND_ROOT.parent / "docs" / "attack-coverage-report.md"


def main() -> int:
    parser = argparse.ArgumentParser(description="ATT&CK 技术覆盖度评估")
    parser.add_argument("--write", action="store_true", help="写入 docs/attack-coverage-report.md")
    parser.add_argument("--benchmark", type=Path, default=DEFAULT_BENCHMARK)
    args = parser.parse_args()
    report = evaluate_attack_coverage(args.benchmark)
    print(render_markdown(report))
    if args.write:
        REPORT_PATH.write_text(render_markdown(report), encoding="utf-8")
        print(f"已写入 {REPORT_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
