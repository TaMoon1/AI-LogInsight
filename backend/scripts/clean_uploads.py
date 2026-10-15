"""上传目录孤儿自检与清理：找出 `data/uploads/` 下没有对应分析记录的目录。

用法：
    cd backend && .venv\\Scripts\\python.exe scripts\\clean_uploads.py            # 只列清单（默认）
    cd backend && .venv\\Scripts\\python.exe scripts\\clean_uploads.py --apply    # 执行删除

判定依据：分析记录**先写数据库、原始文件后落盘**（`_analyze_parsed` 在
`_persist_upload_files` 之前），所以数据库是权威来源——不在库里的目录即为孤儿，
不需要额外的时间保护。正常使用下孤儿只可能来自异常中断的上传请求。

删除前请确认当前确实没有正在进行的分析请求。
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_ROOT))

from app.database import repository  # noqa: E402
from app.main import UPLOAD_ROOT  # noqa: E402

PREVIEW_LIMIT = 10


def _directory_bytes(paths: list[Path]) -> int:
    total = 0
    for path in paths:
        for item in path.rglob("*"):
            if item.is_file():
                try:
                    total += item.stat().st_size
                except OSError:
                    continue
    return total


def main() -> int:
    parser = argparse.ArgumentParser(description="上传目录孤儿自检与清理")
    parser.add_argument(
        "--apply", action="store_true", help="确认删除孤儿目录（默认只列清单）"
    )
    arguments = parser.parse_args()

    if not UPLOAD_ROOT.is_dir():
        print(f"上传目录不存在：{UPLOAD_ROOT}")
        return 0

    known = {item.id for item in repository.list()}
    directories = [path for path in UPLOAD_ROOT.iterdir() if path.is_dir()]
    orphans = sorted(path for path in directories if path.name not in known)

    print(f"上传目录     ：{UPLOAD_ROOT}")
    print(f"分析记录     ：{len(known)} 条")
    print(f"目录总数     ：{len(directories)}")
    print(f"孤儿目录     ：{len(orphans)} 个，占用 {_directory_bytes(orphans) / 1048576:.1f} MB")
    print(f"有效目录     ：{len(directories) - len(orphans)} 个")

    if not orphans:
        print("未发现孤儿目录。")
        return 0

    print("\n孤儿目录清单（最多展示 %d 个）：" % PREVIEW_LIMIT)
    for path in orphans[:PREVIEW_LIMIT]:
        print(f"  {path.name}")
    if len(orphans) > PREVIEW_LIMIT:
        print(f"  … 其余 {len(orphans) - PREVIEW_LIMIT} 个")

    if not arguments.apply:
        print("\n[只读模式] 未删除任何内容，确认无误后加 --apply 执行。")
        return 0

    removed = 0
    for path in orphans:
        shutil.rmtree(path, ignore_errors=True)
        if not path.exists():
            removed += 1
    remaining = [path for path in UPLOAD_ROOT.iterdir() if path.is_dir()]
    print(f"\n已删除      ：{removed} 个")
    print(f"剩余目录    ：{len(remaining)} 个，占用 {_directory_bytes(remaining) / 1048576:.1f} MB")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
