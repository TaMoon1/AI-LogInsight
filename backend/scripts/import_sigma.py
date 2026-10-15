"""Sigma 规则导入 CLI：把社区 Sigma 规则转换成本项目规则。

用法：
    cd backend && .venv\\Scripts\\python.exe scripts\\import_sigma.py                 # 预演（只报告，不写文件）
    cd backend && .venv\\Scripts\\python.exe scripts\\import_sigma.py --write        # 写入 rules/90-sigma.yaml
    cd backend && .venv\\Scripts\\python.exe scripts\\import_sigma.py --input <目录或文件>

退出码：0 表示成功导入；1 表示输入无效或全部规则都无法转换。
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_ROOT))

from app.services.sigma_import import (  # noqa: E402
    SIGMA_METADATA,
    convert_path,
    report_rules,
    write_rules,
)

DEFAULT_INPUT = BACKEND_ROOT / "evaluation" / "sigma-samples"


def main() -> int:
    parser = argparse.ArgumentParser(description="Sigma 规则导入")
    parser.add_argument("--input", default=str(DEFAULT_INPUT), help="Sigma 规则文件或目录")
    parser.add_argument("--write", action="store_true", help="写入 backend/rules/90-sigma.yaml")
    arguments = parser.parse_args()

    target = Path(arguments.input)
    if not target.exists():
        print(f"输入不存在：{target}")
        return 1

    report = convert_path(target)
    print(f"输入规则：{report.total}")
    print(f"转换成功：{report.converted_count}")
    print(f"跳过：{report.skipped_count}")
    print()
    for item in report.converted:
        tags = "、".join(item.tags[:3]) or "-"
        print(f"  ✓ [{item.level:8s}] {item.id}")
        print(f"      {item.title}   标签：{tags}")
    if report.skipped:
        print()
        print("以下规则未导入（原因明确，不做近似转换）：")
        for item in report.skipped:
            print(f"  ✗ {item.path}")
            print(f"      {item.title}：{item.reason}")
    if arguments.write:
        if not report.converted:
            print()
            print("没有可写入的规则。")
            return 1
        payload = report_rules(report)
        # 「声明 validated 必须有本地正样本」——依据由语料评测给出，不是自我声明。
        # 先如实写 unverified，再跑与 eval_rules.py 同源的评测，命中正样本的规则才回填
        # validated（精选集可能混入没有本地正样本的规则，一刀切会骗过元数据门禁）。
        write_rules(payload, metadata={**SIGMA_METADATA})
        covered = _positive_rule_ids()
        for rule in payload:
            rule["validation_status"] = (
                "validated" if rule["id"] in covered else "unverified"
            )
        validated = sum(1 for rule in payload if rule["validation_status"] == "validated")
        path = write_rules(payload, metadata={**SIGMA_METADATA})
        print()
        print(
            f"已写入 {path}（重启后端后生效）：validated {validated} 条、"
            f"unverified {len(payload) - validated} 条"
        )
    return 0 if report.converted else 1


def _positive_rule_ids() -> set[str]:
    """跑语料评测，返回「有正样本命中」的规则 id 集合（与 eval_rules.py 同一判定源）。"""

    from app.services.rule_quality import evaluate

    quality = evaluate()
    return {item.rule_id for item in quality.rules if item.positive > 0}


if __name__ == "__main__":
    raise SystemExit(main())
