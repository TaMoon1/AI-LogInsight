"""便携版冒烟验证：启动 exe → 等就绪 → 查规则与首页 → 上传示例日志 → 退出。

用于发布前确认「打出来的包真的能跑」，本地与 CI 共用：

    cd backend && .venv\\Scripts\\python.exe scripts\\smoke_portable.py
    cd backend && .venv\\Scripts\\python.exe scripts\\smoke_portable.py --port 8123 --sample ../sample_logs/iis/iis-access.log

退出码：0 通过；非 0 表示某项检查失败（供 CI 直接判定）。
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PACKAGE = BACKEND_ROOT / "dist" / "AI-LogInsight"
DEFAULT_SAMPLE = BACKEND_ROOT.parent / "sample_logs" / "ssh" / "auth.log"
MIN_RULES = 2000


def get(port: int, path: str, timeout: float = 300) -> tuple[int, bytes]:
    with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=timeout) as response:
        return response.status, response.read()


def upload(port: int, sample: Path) -> dict:
    boundary = "----smokeboundary"
    body = (
        f'--{boundary}\r\nContent-Disposition: form-data; name="file"; '
        f'filename="{sample.name}"\r\nContent-Type: application/octet-stream\r\n\r\n'
    ).encode() + sample.read_bytes() + f"\r\n--{boundary}--\r\n".encode()
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/api/logs/upload",
        data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )
    with urllib.request.urlopen(request, timeout=900) as response:
        return json.loads(response.read())


def wait_ready(port: int, seconds: int) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            if get(port, "/api/health", timeout=5)[0] == 200:
                return True
        except (urllib.error.URLError, OSError):
            pass
        time.sleep(1)
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description="便携版冒烟验证")
    parser.add_argument("--package", default=str(DEFAULT_PACKAGE), help="解压后的包目录")
    parser.add_argument("--port", type=int, default=8123)
    parser.add_argument("--sample", default=str(DEFAULT_SAMPLE), help="用于上传验证的示例日志")
    parser.add_argument("--skip-upload", action="store_true", help="跳过上传验证")
    arguments = parser.parse_args()

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    package = Path(arguments.package).resolve()
    executable = package / "AI-LogInsight.exe"
    if not executable.is_file():
        print(f"[失败] 未找到 {executable}，请先运行 scripts/build_exe.py")
        return 1

    environment = dict(os.environ, LOGINSIGHT_PORT=str(arguments.port), LOGINSIGHT_NO_BROWSER="1")
    process = subprocess.Popen(
        [str(executable)],
        cwd=str(package),
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    failures: list[str] = []
    try:
        if not wait_ready(arguments.port, 90):
            failures.append("服务未在 90 秒内就绪")
        else:
            print(f"[通过] 服务就绪：http://127.0.0.1:{arguments.port}")

            rules = json.loads(get(arguments.port, "/api/rules")[1])
            count = len(rules) if isinstance(rules, list) else len(rules.get("rules", []))
            if count >= MIN_RULES:
                print(f"[通过] 规则 {count} 条")
            else:
                failures.append(f"规则数量异常：{count}（期望 ≥ {MIN_RULES}）")

            status, body = get(arguments.port, "/")
            if status == 200 and b"<html" in body.lower():
                print(f"[通过] 首页可访问（{len(body)} 字节）")
            else:
                failures.append(f"首页异常：HTTP {status}")

            if not arguments.skip_upload:
                sample = Path(arguments.sample).resolve()
                if not sample.is_file():
                    failures.append(f"示例日志不存在：{sample}")
                else:
                    result = upload(arguments.port, sample)["result"]
                    events = result.get("events", [])
                    if events:
                        print(
                            f"[通过] 上传 {sample.name}：风险={result['risk_level']} 事件={len(events)}"
                        )
                    else:
                        failures.append(f"上传 {sample.name} 未产生任何事件")
    finally:
        process.terminate()
        try:
            output = process.communicate(timeout=20)[0] or ""
        except subprocess.TimeoutExpired:
            process.kill()
            output = ""
        if failures:
            print("--- exe 控制台输出（尾部）---")
            print("\n".join(output.strip().splitlines()[-8:]))

    if failures:
        for item in failures:
            print(f"[失败] {item}")
        return 1
    print("冒烟验证全部通过")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
