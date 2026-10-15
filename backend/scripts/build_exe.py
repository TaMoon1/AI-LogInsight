"""构建 Windows 便携版：前端构建 → PyInstaller 打包 → 补包外文件 → 压 ZIP。

用法：

    cd backend && .venv\\Scripts\\python.exe scripts/build_exe.py
    cd backend && .venv\\Scripts\\python.exe scripts/build_exe.py --version 1.0.0 --skip-frontend

产物：`backend/dist/AI-LogInsight/`（解压即用的目录）与 `backend/dist/AI-LogInsight-<版本>-win64.zip`。
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[1]
ROOT = BACKEND_ROOT.parent
SPEC = BACKEND_ROOT / "AI-LogInsight.spec"
DIST = BACKEND_ROOT / "dist"
WORK = BACKEND_ROOT / "build"
PACKAGE = DIST / "AI-LogInsight"

README_TXT = """AI-LogInsight · AI 日志智能分析与可疑行为研判平台（便携版）
==================================================

一、启动
  双击 AI-LogInsight.exe，等待控制台出现访问地址后，浏览器会自动打开。
  默认地址 http://127.0.0.1:8000（端口被占用时会自动往后找）。
  停止：在控制台按 Ctrl+C，或直接关闭窗口。

二、配置 AI 研判（可选）
  把 .env.example 复制为 .env，填好 API Key 即可启用 AI 研判。
  没有配置也能用：规则检测、证据溯源、导出等功能不受影响。

三、数据与隐私
  所有数据只保存在本机 exe 同级的 data/ 目录（数据库 + 上传的原始日志），
  不会上传到任何服务器（只有启用 AI 研判时，脱敏后的关键事件会发给你配置的模型服务）。
  卸载 = 删除整个目录。

四、目录说明
  AI-LogInsight.exe   启动入口
  _internal/          运行库与规则（勿删、勿改）
  .env.example        配置模板
  data/               运行后生成：数据库与上传日志

五、常见问题
  1. 杀毒软件报毒：PyInstaller 打包的程序常被误报，可加入信任；也可按 README 自行构建。
  2. 端口被占用：设置环境变量 LOGINSIGHT_PORT=8010 后重新启动。
  3. 只有命令行没有界面：确认浏览器未被拦截，手动访问控制台显示的地址。
"""


def run(command: list[str], cwd: Path) -> None:
    print(f"$ {' '.join(command)}")
    result = subprocess.run(command, cwd=cwd)
    if result.returncode != 0:
        raise SystemExit(f"命令失败（退出码 {result.returncode}）：{' '.join(command)}")


def build_frontend(skip: bool) -> None:
    dist_index = ROOT / "frontend" / "dist" / "index.html"
    if skip:
        print("跳过前端构建（--skip-frontend）")
        return
    if dist_index.is_file():
        print(f"前端已构建：{dist_index}（需要重建请先删除 frontend/dist）")
        return
    print("前端未构建，先执行 npm run build")
    run(["npm", "run", "build"], ROOT / "frontend")


def run_pyinstaller() -> None:
    run(
        [
            sys.executable,
            "-m",
            "PyInstaller",
            "--noconfirm",
            "--clean",
            f"--distpath={DIST}",
            f"--workpath={WORK}",
            str(SPEC),
        ],
        BACKEND_ROOT,
    )


def add_package_files() -> None:
    """PyInstaller 只管 `_internal/`；包外给用户看的文件在这里补。"""

    example = ROOT / ".env.example"
    if example.is_file():
        shutil.copy2(example, PACKAGE / ".env.example")
    (PACKAGE / "data").mkdir(exist_ok=True)
    (PACKAGE / "使用说明.txt").write_text(README_TXT, encoding="utf-8")
    print(f"已补包外文件：.env.example / 使用说明.txt / data/")


def make_zip(version: str) -> Path:
    archive = DIST / f"AI-LogInsight-{version}-win64.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:
        for path in sorted(PACKAGE.rglob("*")):
            if not path.is_file():
                continue
            relative = path.relative_to(PACKAGE)
            # 运行时产物一律不进包：`.env` 里是使用者的 API Key，
            # `data/` 里是使用者上传的日志与数据库——打包时若残留会把隐私发出去
            if relative.name == ".env" or relative.parts[0] == "data":
                continue
            bundle.write(path, path.relative_to(DIST))
    return archive


def main() -> int:
    parser = argparse.ArgumentParser(description="构建 Windows 便携版")
    parser.add_argument("--version", default="1.0.0", help="写进压缩包名")
    parser.add_argument("--skip-frontend", action="store_true", help="跳过前端构建")
    arguments = parser.parse_args()

    build_frontend(arguments.skip_frontend)
    run_pyinstaller()
    add_package_files()
    archive = make_zip(arguments.version)

    exe = PACKAGE / "AI-LogInsight.exe"
    total = sum(path.stat().st_size for path in PACKAGE.rglob("*") if path.is_file())
    print()
    print(f"完成：{exe}")
    print(f"目录体积：{total / 1048576:.1f} MB")
    print(f"压缩包：{archive}（{archive.stat().st_size / 1048576:.1f} MB）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
