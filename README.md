# AI-LogInsight

<p align="left">
  <a href="https://github.com/TaMoon1/AI-LogInsight/actions/workflows/ci.yml"><img src="https://github.com/TaMoon1/AI-LogInsight/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"></a>
  <img src="https://img.shields.io/badge/python-3.11-blue" alt="Python 3.11">
  <img src="https://img.shields.io/badge/vue-3-42b883" alt="Vue 3">
</p>

**离线优先的日志分析与可疑行为研判工具。**

> 上传日志 → 自动识别类型并解析 → 规则检测出可疑行为 → 输出证据、时间线与风险等级 → 可选接入大模型做结构化研判。
>
> **Offline-first log analysis & suspicious-behavior triage**: parse logs, detect with 2371 Sigma rules, get evidence-grounded verdicts. Read-only by design.

只读日志、只做分析，**不执行任何处置动作**（不封禁、不隔离、不登录、不下发命令）。

## ✨ 核心特性

- **开箱即用**：无需部署采集端，把日志文件或导出包拖进来即可；提供 Windows 便携版（解压双击运行）。
- **离线可跑**：不配置 AI 也完整可用；配置后才把**脱敏后的关键证据**发给大模型。
- **规则驱动**：共 2371 条规则（内置 74 条 + Sigma 导入 2297 条），带语料门禁（123 个标注用例，TP 111 / FP 0 / FN 0）与规则库体检。
- **结论可追溯**：每条结论附证据编号与日志原文出处；证据不足时明确输出「无法确认」。
- **分析视角齐全**：中轴时间线、ATT&CK 战术网格、攻击链关联、实体调查、威胁情报查询（按需）。
- **MCP 只读接口**：Claude Code / Cursor 等外部 AI 客户端可直查本机分析结果（13 个只读工具）。

## 📥 支持的日志类型

Windows EVTX（二进制）/ 事件查看器 XML / Windows Security·RDP 文本 / Sysmon / SSH /
Nginx·Apache / IIS（W3C）/ syslog 与容器日志 / Firewall·WAF 键值 /
MySQL·PostgreSQL·MongoDB·Redis·SQL Server·Oracle / 通用 JSON·CSV / 域控异常登录导出 XLSX /
通用 XML；**支持 zip / gzip / bzip2 压缩包自动解压**。

## 🚀 快速开始

### 方式一：Windows 便携版（推荐）

从 [Releases](https://github.com/TaMoon1/AI-LogInsight/releases) 下载 `AI-LogInsight-<版本>-win64.zip`，
解压后双击 `AI-LogInsight.exe`，浏览器会自动打开 `http://127.0.0.1:8000`。

### 方式二：从源码运行

```bash
# 1. 后端（Python 3.11）
cd backend
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt      # Linux/macOS: .venv/bin/pip
.venv\Scripts\python -m uvicorn app.main:app --host 127.0.0.1 --port 8000

# 2. 前端（Node 22；npm run build 后可省略这一步，后端会直接托管 dist）
cd frontend
npm install
npm run dev        # 开发模式，打开 http://localhost:5173
```

打开 `http://127.0.0.1:8000`，把 `sample_logs/` 里的示例日志拖进来即可体验。

### 方式三：Docker

```bash
docker compose up --build -d        # 打开 http://localhost:8080
docker compose logs -f              # 查看日志
docker compose down                 # 停止
```

## ⚙️ 配置

把 `.env.example` 复制为 `.env` 即可启用 AI 研判，支持 DeepSeek / OpenAI 兼容 / Anthropic / Ollama（自备 API Key）。

**不配置也能用**——规则检测、证据溯源、导出等功能不受影响；只有 AI 研判会把**脱敏后的关键证据**发给所配模型。

上传与存储上限（默认单文件 50 MB / 单次分析 200 MB / 存储 2 GB）同样在 `.env` 中调整。

## 🧠 检测规则

- 规则共 **2371 条**：内置 74 条 + Sigma 导入 2297 条（人工精选 8 条 + SigmaHQ 社区 2289 条）。
- 社区规则遵循 [DRL-1.1](https://github.com/SigmaHQ/Detection-Rule-License) 许可，逐条保留原作者署名与来源链接。
- 语料门禁：123 个标注用例覆盖全部内置规则，**TP 111 / FP 0 / FN 0**，并作为 CI 测试门禁。
- 导入规则 2070/2297 可端到端触发，全部通过「正常流量零命中」筛查；未验证部分单独标注，不冒充已验证。

## 🔌 API 与 MCP

- REST API：上传 / 分析 / 事件 / 记录 / 证据 / 威胁情报 / 报告导出（JSON·HTML·CSV·SARIF 及
  Splunk·Elastic·OpenSearch·Timesketch 模板）等，启动后见 `http://127.0.0.1:8000/docs`。
- MCP 只读接口：`backend/scripts/mcp_server.py`，供 Claude Code / Cursor 等客户端直查分析结果。

## 📁 项目结构

```text
backend/        FastAPI 后端（app/ 解析·检测·研判，rules/ 规则库，scripts/ 构建与导入工具）
frontend/       Vue 3 前端
sample_logs/    示例日志
docs/           质量报告与品牌素材
docker/         Docker 相关配置
```

## 📚 文档

| 文档 | 说明 |
| --- | --- |
| [CHANGELOG.md](CHANGELOG.md) | 变更记录 |
| [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md) | 第三方组件与许可声明 |
| [docs/rule-quality-report.md](docs/rule-quality-report.md) | 规则质量报告（TP / FP / FN） |
| [docs/sigma-import-report.md](docs/sigma-import-report.md) | Sigma 批量导入报告 |
| [docs/sigma-rule-verification.md](docs/sigma-rule-verification.md) | 导入规则可触发性验证 |
| [docs/attack-coverage-report.md](docs/attack-coverage-report.md) | ATT&CK 覆盖度报告 |
| [docs/ai-quality-report.md](docs/ai-quality-report.md) | AI 研判质量评测 |

## ⚠️ 已知限制

- 无登录与权限控制，默认只监听 `127.0.0.1`，**不要直接暴露到公网**；远程访问请自行加反向代理与鉴权。
- AI 研判结论**必须人工确认**，未经复核不得当作事实。
- 单机 SQLite 存储，不适合多人并发写入场景。
- 大日志分析在请求内同步完成，超大文件耗时较长。

## 🤝 贡献

欢迎 Issue 与 PR。提交前请跑通 `cd backend && python -m pytest -q`，开发约束见 [AGENTS.md](AGENTS.md)。

## 📄 许可

- 本项目代码以 [MIT](LICENSE) 许可发布。
- SigmaHQ 导入规则遵循 [DRL-1.1](https://github.com/SigmaHQ/Detection-Rule-License)，署名与来源已逐条保留。
- 界面设计参考 [Zircolite](https://github.com/wagga40/Zircolite)（未使用其源码），详见 [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md)。
