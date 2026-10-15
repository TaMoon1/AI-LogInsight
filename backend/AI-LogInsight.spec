# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller 打包配置：Windows 便携版（one-dir，解压即用）。

不要直接调用 PyInstaller，走构建脚本（它会先构建前端、再补包外文件、最后压 ZIP）：

    cd backend && .venv\\Scripts\\python.exe scripts/build_exe.py

资源布局（打包后 `app/runtime_paths.py` 按此定位）：

- `_internal/rules/`、`_internal/evaluation/` → 规则与语料（只读）
- `_internal/sample_logs/` → 演示日志（只读）
- `_internal/frontend/dist/` → 前端构建产物（由后端静态托管）
- exe 同级的 `data/` → 数据库与上传（可写，运行时创建）
"""

from pathlib import Path

from PyInstaller.utils.hooks import collect_submodules

BACKEND = Path(SPECPATH)  # backend/
ROOT = BACKEND.parent  # 仓库根

datas = [
    (str(BACKEND / "rules"), "rules"),
    (str(BACKEND / "evaluation"), "evaluation"),
    (str(ROOT / "sample_logs"), "sample_logs"),
    (str(ROOT / "frontend" / "dist"), "frontend/dist"),
]

# uvicorn 的协议实现是按名字符串动态导入的，静态分析看不见，必须显式收集
hiddenimports = collect_submodules("uvicorn") + [
    "Evtx.Evtx",  # python-evtx：EVTX 二进制解析（缺失则 EVTX 不可用）
    # pyyaml 的 libyaml C 加速：真实位置是 yaml._yaml（顶层 _yaml 只是兼容 stub）。
    # 缺失时退化为纯 Python 解析，实测规则加载从 11.8s 涨到 23.3s（2026-10-15）
    "yaml._yaml",
    "drain3",
    "multipart",  # python-multipart：上传表单
    "yaml",
]

a = Analysis(
    [str(BACKEND / "scripts" / "launcher.py")],
    pathex=[str(BACKEND)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    # 运行时不用的东西不打包：tkinter 体积大，pytest/mcp 只在开发/独立 CLI 用
    excludes=["tkinter", "pytest", "mcp", "IPython", "matplotlib", "numpy", "pandas"],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="AI-LogInsight",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,  # UPX 压缩会显著提高杀软误报率，不用
    console=True,  # 保留控制台：用户能看到访问地址与日志，也方便排查
    disable_windowed_traceback=False,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name="AI-LogInsight",
)
