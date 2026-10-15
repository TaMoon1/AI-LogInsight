"""运行时路径：源码模式与打包（PyInstaller）模式的统一入口。

打包后 `__file__` 指向解压出的临时目录，`Path(__file__).parents[N]` 会落到错误位置，
因此把路径按用途分开定位（**源码模式下的返回值与改造前完全一致**，只是打包模式下
统一改指 PyInstaller 资源目录 / exe 同级目录）：

- `backend_root()`：只读资源 `rules/`、`evaluation/`。源码模式 = `<仓库根>/backend`；
  打包模式 = PyInstaller 资源目录（one-dir 下是 exe 旁的 `_internal/`）。
- `project_root()`：只读资源 `sample_logs/`。源码模式 = 仓库根；打包模式同上。
  （与 `backend_root()` 只在源码模式不同——这是仓库既有布局决定的。）
- `data_root()`：**可写数据**（数据库 / 上传）。源码模式 = `<仓库根>/data`；
  打包模式 = **exe 同级 `data/`**——临时目录会被清理，便携版数据必须落在 exe 旁边。
- `env_files()`：`.env` 候选路径，打包模式优先 exe 旁的 `.env`（用户可直接改配置）。
"""

from __future__ import annotations

import sys
from pathlib import Path

#: 源码模式下本文件位于 `<仓库根>/backend/app/runtime_paths.py`
_REPO_ROOT = Path(__file__).resolve().parents[2]
_BACKEND_ROOT = Path(__file__).resolve().parents[1]


def is_frozen() -> bool:
    """是否运行在 PyInstaller 打包产物里。"""

    return bool(getattr(sys, "frozen", False))


def _bundle_root() -> Path:
    return Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent))


def backend_root() -> Path:
    """只读资源根：`rules/`、`evaluation/`。"""

    return _bundle_root() if is_frozen() else _BACKEND_ROOT


def project_root() -> Path:
    """只读资源根：`sample_logs/`。"""

    return _bundle_root() if is_frozen() else _REPO_ROOT


def data_root() -> Path:
    """可写数据根：数据库、上传。"""

    if is_frozen():
        return Path(sys.executable).resolve().parent / "data"
    return _REPO_ROOT / "data"


def env_files() -> tuple[Path, ...]:
    """`.env` 候选路径（按优先级）。"""

    root = Path(sys.executable).resolve().parent if is_frozen() else _REPO_ROOT
    return (root / ".env", root / "backend" / ".env")
