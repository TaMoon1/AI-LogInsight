# 第三方组件与许可声明

本项目（AI-LogInsight）自身代码以 [MIT](LICENSE) 发布。
仓库内还包含或参考了下列第三方内容，使用本项目时需同时遵守各自许可。

## 1. 检测规则（`backend/rules/90-sigma.yaml`、`backend/rules/95-sigma-community.yaml`）

| 项 | 值 |
| --- | --- |
| 来源 | [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma)，版本 `b4ba1f2`（含本地格式转换） |
| 许可 | **Detection Rule License 1.1（DRL-1.1）**，全文：https://github.com/SigmaHQ/Detection-Rule-License |
| 已按许可要求保留 | 每条规则的 `author`（署名）、`references`（URI）、文件头 `metadata.license: DRL-1.1` |
| 修改说明 | 仅做字段名与语法的转换以适配本项目规则引擎，未改动检测语义 |

> DRL-1.1 允许使用、修改、再分发（含商业用途），条件是保留署名、来源 URI，
> 并声明该部分内容采用 DRL-1.1 许可、附许可文本或链接。本文件即该声明。

## 2. 界面设计参考（不含其源码）

| 项 | 值 |
| --- | --- |
| 项目 | [Zircolite](https://github.com/wagga40/Zircolite) 4.5.0 |
| 许可 | GNU LGPL-3.0-or-later |
| 使用方式 | 仅**参考**其信息架构与视觉设计系统（概览卡片、中轴双向时间轴、ATT&CK 网格、拼接式网格布局、导航结构），并以 Vue 3 重新实现 |

本项目**未复制其源代码**，交付物中**不包含**其源码归档（本地参考用的 `.zip` 已由 `.gitignore` 排除）。
Zircolite 是独立的 Sigma 检测工具，与本项目无隶属或背书关系。

## 3. 运行时依赖（Python）

版本锁定见 `backend/requirements.txt`：
`fastapi`、`uvicorn[standard]`、`pydantic`、`python-multipart`、`pytest`、`httpx`、
`python-evtx`、`drain3`、`mcp`。

各组件许可以上游发布为准。生成完整清单：

```bash
pip install pip-licenses && pip-licenses --format=markdown
```

## 4. 前端依赖

见 `frontend/package.json`：`vue`、`vite`、`typescript`、`@vitejs/plugin-vue`、`vue-tsc`。

```bash
cd frontend && npx license-checker --summary
```

## 5. 容器内运行时组件

`nginx`（BSD-2-Clause）、`python:3.11-slim`、`node:22-alpine`（见 `Dockerfile`）。

## 6. 便携版打包工具

| 项 | 值 |
| --- | --- |
| 项目 | [PyInstaller](https://pyinstaller.org) 6.22.3 |
| 许可 | GPL-2.0-or-later **附带例外条款**：允许以本工具打包的程序按自选许可分发 |
| 使用方式 | 仅在构建期使用（`backend/requirements-build.txt`）。生成的 Windows 便携版 exe 内嵌 PyInstaller bootloader，属该例外条款覆盖范围 |

## 7. 不随仓库分发的内容

- 第三方评测样本集与规则归档（`*.zip`）已由 `.gitignore` 排除，需自行获取；
- 真实客户日志、分析数据库、上传目录（`data/`）不随仓库分发；
- 便携版构建产物（`backend/dist/`、`backend/build/`）不入库，需要时按 README 自行构建，
  或从 Releases 下载；
- `sample_logs/` 与 `backend/evaluation/` 中的日志均为示例或合成数据，不含真实客户信息。
