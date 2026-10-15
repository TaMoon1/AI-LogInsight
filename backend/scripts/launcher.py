"""便携版启动器：加载配置 → 选空闲端口 → 起服务 → 自动打开浏览器。

打包产物（PyInstaller）的入口就是本文件；源码调试同样可直接运行：

    cd backend && .venv\\Scripts\\python.exe scripts\\launcher.py

约定：

- `.env` 从 exe 同级目录（打包）或仓库根（源码）读取，**不覆盖已存在的真实环境变量**；
- 端口取 `LOGINSIGHT_PORT`，默认 8000；被占用时自动往后找（最多 20 个）；
- 设 `LOGINSIGHT_NO_BROWSER=1` 可禁止自动打开浏览器（服务照常运行，适合远程/无人值守）；
- 数据（数据库、上传）落在 exe 同级 `data/`，见 `app/runtime_paths.py`。
"""

from __future__ import annotations

import os
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
import webbrowser
from pathlib import Path

DEFAULT_PORT = 8000
PORT_SCAN = 20
STARTUP_TIMEOUT = 30.0


def _base_dir() -> Path:
    """打包模式 = exe 所在目录；源码模式 = 仓库根。"""

    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[2]


def _load_env() -> tuple[Path, int] | None:
    """把 `.env` 读进环境变量；已存在的变量优先。返回（文件, 载入项数）。"""

    for candidate in (_base_dir() / ".env", _base_dir() / "backend" / ".env"):
        if not candidate.is_file():
            continue
        loaded = 0
        for line in candidate.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            key, value = stripped.split("=", 1)
            key = key.strip()
            if key and key not in os.environ:
                os.environ[key] = value.strip().strip('"').strip("'")
                loaded += 1
        return candidate, loaded
    return None


def _free_port(preferred: int) -> int:
    """从 preferred 起找一个可绑定的端口。"""

    for port in range(preferred, preferred + PORT_SCAN):
        with socket.socket() as probe:
            try:
                probe.bind(("127.0.0.1", port))
            except OSError:
                continue
            return port
    raise SystemExit(f"端口 {preferred}-{preferred + PORT_SCAN - 1} 都被占用，请设置 LOGINSIGHT_PORT")


def _open_when_ready(url: str) -> None:
    """等服务真正可访问再开浏览器，避免打开一个空白错误页。"""

    deadline = time.monotonic() + STARTUP_TIMEOUT
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2):
                webbrowser.open(url)
                return
        except (urllib.error.URLError, OSError):
            time.sleep(0.4)
    print(f"服务启动超时，请手动访问 {url}")


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    if not getattr(sys, "frozen", False):
        backend_root = Path(__file__).resolve().parents[1]
        sys.path.insert(0, str(backend_root))

    config = _load_env()
    port = _free_port(int(os.getenv("LOGINSIGHT_PORT") or DEFAULT_PORT))
    url = f"http://127.0.0.1:{port}"

    print("=" * 56)
    print("  AI-LogInsight · AI 日志智能分析与可疑行为研判平台")
    print("=" * 56)
    print(f"  访问地址：{url}")
    print(f"  数据目录：{_base_dir() / 'data'}")
    print(f"  配置文件：{config[0] if config else '未找到 .env（可在 exe 旁创建，参照 .env.example）'}")
    print("  停止服务：按 Ctrl+C 或直接关闭本窗口")
    print("=" * 56)

    if os.getenv("LOGINSIGHT_NO_BROWSER", "").lower() not in {"1", "true", "yes"}:
        threading.Thread(target=_open_when_ready, args=(url,), daemon=True).start()
    import uvicorn

    from app.main import app

    uvicorn.run(app, host="127.0.0.1", port=port, log_level="info")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
