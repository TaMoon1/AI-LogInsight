# AI-LogInsight

**离线优先的日志分析与可疑行为研判工具。** 上传日志 → 自动识别类型并解析 → 规则检测出可疑行为
→ 给出证据、时间线与风险等级 → 可选接入 AI 做结构化研判（自备 API Key，不配置则纯本地规则）。

只读日志、只做分析，**不执行任何处置动作**（不封禁、不隔离、不登录、不下发命令）。

- **不用部署采集端**：把日志文件或导出包拖进来即可。
- **离线可跑**：不配 AI 也完整可用；只有配置了 AI 才把脱敏后的关键证据外发。
- **结论可追溯**：每条结论都给证据编号与原文出处；证据不足时明确输出「无法确认」，不假装正常。
- **支持的输入**：Windows EVTX / 事件查看器 XML / Windows Security·RDP 文本 / Sysmon、
  SSH、Nginx·Apache、IIS(W3C)、syslog 与容器日志、Firewall·WAF 键值、
  MySQL·PostgreSQL·MongoDB·Redis·SQL Server·Oracle、通用 JSON·CSV、域控异常登录导出 XLSX。
- **规则**：74 条内置 + 2198 条 Sigma 导入，按日志类型与必要条件索引匹配。

## 快速开始

### 方式一：本机运行（Windows / macOS / Linux）

前置：Python 3.11+、Node 20+。

```bash
# 后端（终端 1）
cd backend
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt   # macOS/Linux: .venv/bin/python
.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000

# 前端（终端 2）
cd frontend
npm install
npm run dev -- --host 127.0.0.1 --strictPort
```

打开 http://127.0.0.1:5173 ，先用页面自带的示例日志看效果。

### 方式二：Docker

```bash
docker compose up --build -d
# 打开 http://127.0.0.1:8080
```

### 接入 AI（可选）

页面「AI 配置」里选择服务商并填入自己的 API Key（DeepSeek / OpenAI / 通义 / 智谱 / Moonshot /
Ollama 本地模型等 18 个预设 + 通用 OpenAI-compatible）。**不配置也能用**，只是不做 AI 研判。
AI 请求前会对敏感字段脱敏，且只发送采样后的关键证据，不是整份日志。

## 已知限制（请先读完再用）

- **无登录与权限控制**，默认只监听 `127.0.0.1`。**不要直接暴露到公网**；确需远程访问请自行加反向代理与鉴权。
- AI 研判结论**必须人工确认**，未经复核不得当作事实；页面与导出报告会标注哪些内容来自 AI 推断。
- 单次上传默认上限 50 MB、单次分析 200 MB；文本日志峰值内存约为文件大小的 4.4 倍。
- 大日志的分析在请求内同步完成，超大文件会占用较长时间。
- 规则中的社区导入部分没有本地正样本，仅做过「正常流量零命中」筛查与可触发性验证。
- 仅支持单机 SQLite 存储，不适合多人并发写入场景。

## 许可与致谢

本项目以 **MIT** 发布。仓库内 Sigma 规则来自 [SigmaHQ](https://github.com/SigmaHQ/sigma)（DRL-1.1），
界面信息架构参考 [Zircolite](https://github.com/wagga40/Zircolite)（LGPL-3.0，仅参考设计，未复制源码）。
详见 [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md)。

---

<!-- 以下为详细规格与开发文档；小节编号（§N）未变动，供开发、审计与追溯使用 -->

## 项目结构

```text
backend/
  app/                 FastAPI 接口、解析器、检测器、AI 研判与报告服务
  rules/               内置规则和 Sigma 导入规则
  evaluation/          脱敏评测样本、场景日志和评测结果
  scripts/              规则导入、评测、基准测试和维护命令
  tests/               后端自动化测试
frontend/
  src/                 Vue 前端源码
sample_logs/           可直接上传的示例日志
docs/
  IMPROVEMENT_ROADMAP.md  当前改进路线，开发前必读
  archive/             历史记录，仅供追溯
```

本机生成的 `backend/.venv`、`frontend/node_modules`、`frontend/dist`、
`__pycache__`、`data/` 和 `.pytest_cache` 都是运行或构建产物，不属于源码结构，
已通过 `.gitignore` 排除。

> AI-Powered Security Log Analysis Platform

**AI 日志智能分析平台**

一个面向安全服务、安全运营和应急响应场景的轻量化 Web 日志分析平台。

## 当前实现状态

仓库当前已具备可运行 MVP：

- FastAPI 后端：日志上传、类型识别、SSH / Nginx / Apache / IIS / Windows-RDP / Firewall-WAF 解析、统计和可疑行为候选事件检测。
- Vue 3 + Vite 前端：上传日志、展示统计、可疑事件、原始证据和进一步排查建议。
- 支持多文件上传，并对不同来源日志进行统一统计和事件关联。
- 支持 OpenAI、DeepSeek、通义千问、百度千帆、智谱、Moonshot、MiniMax、硅基流动、OpenRouter、Groq、Together、Fireworks、Mistral、xAI、Gemini、Anthropic、Ollama 以及通用 OpenAI-compatible Provider。
- 测试：覆盖 SSH/Web 检测、AI 结构化结果、失败降级、多文件分析和报告导出。

当前仍未实现用户权限、异步大文件任务和自动化处置；这些不属于当前 MVP 的必要闭环。

当前版本已增加 SQLite 持久化、历史分析管理和研判交付能力：

- 分析结果保存到 `data/loginsight.db`。
- 支持通过历史列表重新打开已完成的分析。
- 支持删除分析记录。
- 分析记录包含 `processing`、`completed`、`failed` 状态字段。
- SSH 检测支持 5 分钟失败窗口、多账户尝试、失败后近时成功登录和高权限账户登录。
- Nginx/Apache 检测支持敏感路径、路径遍历候选、敏感文件（私钥 / 云凭证 / 运维配置）访问与「返回 2xx 的敏感文件成功读取」升级，以及高频 404 Web 扫描候选。
- Web 访问日志解析兼容标准 combined、无引号、脱敏（剥离 `/` `:`）与**无 `[时间]` 字段（时间由外层提供）**四种写法，来源支持 IPv4 与 IPv6；攻击特征规则覆盖 SQL 注入、XSS、命令注入、敏感管理接口探测、WebShell 与攻击工具 User-Agent（`web.sql_injection`、`web.xss`、`web.command_injection`、`web.sensitive_interface`、`web.webshell`、`web.scanner_user_agent`），按「来源 IP + 规则」聚合。
- **syslog / 容器日志**：识别 `时间 级别 主机 程序[PID]:` 前缀并剥壳，再按内层内容分派——内层是访问日志就复用 Web 解析（时间戳取自前缀，主机记为 `target_asset`），内层是 `key=value` 应用日志就映射出 `src_ip` / `user_id` / `result` / `endpoint` 等字段；应用自身记录的安全信号（`suspicious_path_sequence`、`temporary_block`、`restricted_resource_access`）按应用侧结论直接采信（`app.sensitive_path_probe`、`app.auth_threshold_block`、`app.restricted_resource_access`）。
- Windows EVTX（本机事件日志）：支持二进制 `.evtx`（依赖 `python-evtx`）与事件查看器 XML 导出，映射 4624 / 4625 的账户、来源 IP、登录类型，复用 Windows/RDP 规则；非认证事件（Sysmon 等）额外映射进程镜像、命令行、父进程、落地文件、注册表键、DNS 查询、外联目标与哈希，供 Sysmon 行为规则研判，同时保留为明细记录用于取证；命令行中未转义的 `&` 会先转义再解析，避免整条事件被丢弃。
- 测试使用临时 SQLite（`LOGINSIGHT_DB_PATH`）与临时上传目录（`LOGINSIGHT_UPLOAD_ROOT`），不会写入 `data/loginsight.db` 或 `data/uploads/`。
- IIS（W3C 扩展日志）复用同一套 Web 规则，并额外解析出目的 IP（`s-ip`）供筛选和取证。
- Windows Security / RDP 检测支持 4625 认证失败聚集、失败后 4624 成功登录（`rdp.bruteforce`、`rdp.bruteforce.success`）和高权限账户远程登录（`windows.privileged_logon`），并区分登录类型（3 网络 / 10 RDP）。
- **Windows 事件日志键值化导出**：识别 `时间 级别 主机 提供程序 EventID=N 键=值` 形态（程序名后无冒号），映射 `EventID` / `Account` / `LogonType` / `SourceAddress` / `Process` / `PID` / `ServiceFile` / `Service` 等键，与事件查看器文本导出**共用同一套字段口径**——4624 记成功、4625 记失败，其余事件的 `Result` 一律不计入认证统计。检测支持账户锁定（`windows.account_lockout`，4740）、新服务安装（`windows.service_install`，7045，持久化候选）与关键防护服务被停止（`windows.protection_service_stopped`，7036 且 `State=Stopped`，防御规避 T1562.001）。
- 通用 JSON / CSV 事件：**原样收下记录自带的全部字段名**，同时把已知别名映射到规范字段并归一化取值（`failure` / `失败` / `denied` 等统一为 failure），VPN、堡垒机、应用和网络设备的结构化导出可直接接入，并复用认证与 Web 规则。
- Firewall / WAF 键值日志：支持 `SRC`、`DST`、`PROTO`、`DPT` 与 `ACTION/VERDICT` 常见字段，并检测同一来源短时间访问多个目的端口的端口扫描候选。
- 检测规则以 YAML **声明式表达**（`backend/rules/*.yaml`），支持记录条件、时间窗聚合与「失败聚集后成功」这类跨记录关联；新增规则无需改代码。
- 支持导入 **Sigma 社区规则**：人工精选 7 条 + 批量导入的 SigmaHQ 社区规则（Windows 进程创建 / 文件 / 注册表 / DNS / 网络连接 / 安全通道，2191 条，见 `backend/rules/95-sigma-community.yaml` 与 `docs/sigma-import-report.md`）。字段映射与布尔条件严格转换，无法映射的规则整条跳过并报告原因；社区规则事件名带 `[Sigma]` 前缀，`RULE_SIGMA_IMPORTED_ENABLED=false` 可一键停用。
- 提供**基准语料与误报率评估**：123 个标注用例覆盖全部 **74 条内置规则**（含 4 个整份真实日志用例，其中 2 个属攻击链场景 family），`GET /api/rules/quality` 输出每条规则的 TP / FP / FN，并作为测试门禁。导入的社区规则没有本地正样本，单独统计为「未验证的导入规则」，只做「正常流量零命中」筛查。
- 提供 **ATT&CK 技术覆盖报告**：以外部参考集（EVTX-to-MITRE-Attack，>270 个第三方 EVTX 样本，**不打包进仓库**）的技术清单当尺子，`GET /api/rules/attack-coverage` 与 `backend/scripts/attack_coverage.py` 输出「外部参考规模 / **有规则** / **有本地正样本验证**」三个口径。刻意把「有标签」与「已被语料验证」分开，未覆盖与「有规则但缺样本」都单独列出；报告同时声明清单不等于 ATT&CK 全量。当前 **120/120 有规则、46/120 有本地正样本**，其中**外部参考集原有 27 项、本项目补充 93 项分开统计**（补充项标 `origin: project`，不构成外部基准）。
- 提供**检测覆盖度与结论三态**：分析结果包含 `coverage`（总记录 / 含可判定字段 / 命中规则 / 未覆盖 / 未纳入检测）。未纳入检测再拆成 `parse_errors`（解析失败）与 `retention_drops`（超出单次保留上限），`parse_failures` 保留为两类之和，接口向后兼容。无事件时结论分三态——**已覆盖且未发现异常**、**覆盖不完整无法确认**（记录缺行为字段、解析失败或超出保留上限）、并给出 `limitation` 说明；避免把「没解析出来」表述成「没有异常」。
- 提供**覆盖缺口自检**：`backend/scripts/coverage_gaps.py <日志>` 列出未被任何规则命中的记录并按状态码归并，用于发现漏检并驱动补规则。
- 提供 **IOA 行为偏离**（`behavior_deviations`）：在攻击特征之外补充「行为偏离」视角——本批次首次出现的公网目的地址 / 域名、非常用端口外联、低频公网来源、罕见访问路径。基线为**同批次 + 内置白名单**（私有网段 / 常用端口 / 常用域名 / 非公网主机名），口径显式标注为「与本批次相比首次出现」。偏离独立于 `events`、**不改变风险等级**；无事件但有偏离时结论为「未发现明确攻击特征，但存在 N 项行为偏离（低置信度）」。设计见 `docs/ioa-behavior-baseline.md`。
- 提供**异常评分**（借鉴 OWASP CRS）：同源多条异常按权重累计并在达到阈值时升级风险等级，默认关闭、不改变既有定级。
- `GET /api/rules` 返回规则清单（规则 ID、适用日志类型、风险等级、启用状态、阈值、时间窗口、来源与 ATT&CK 标签），共 2272 条规则（74 条内置 + 2198 条 Sigma 导入，其中 7 条精选 + 2191 条批量社区导入）。
- 事件结果包含原始证据和时间线；已提供 AI 请求前的敏感字段脱敏工具。
- 事件证据包含稳定的证据编号、来源文件、时间、IP、账户、URL 和原始日志字段；规则事件包含可追踪的 `rule_id`。
- AI 行为结果支持 `evidence_ids`，后端只接受当前分析中真实存在的证据编号，前端可点击引用定位原始日志。
- AI 研判前会确定性执行一轮只读轻量工具（`log_metadata`、`log_statistics`、`query_events`、`timeline`），**返回结果以指针形式并入上下文**（只保留摘要与计数锚点，避免与已有上下文块重复），模型可再按需追加调用 `query_evidence` / `query_behavior_deviations` / `query_uncovered_records` / `query_terminal_chains` / `query_records`；调用轨迹与未支撑声明一并返回并在前端展示。
- 当前研判会根据规则动态显示风险等级、置信度、结论和分析来源，并生成下一步排查方向与具体方法。
- 支持通过 `POST /api/analysis/{id}/ai` 手动触发结构化 AI 研判；调用前会脱敏，AI 不可用时保留本地规则结果。前端使用 `POST /api/analysis/{id}/ai/start` + `GET /api/ai/tasks/{task_id}` 轮询真实研判阶段（准备上下文 → 执行工具 → 调用模型 → 解析 → 溯源校验），进度浮层显示真实百分比。上传的原始日志保存在 `data/uploads/{analysis_id}/`，可通过 `GET /api/analysis/{id}/download` 下载（单文件直下、多文件 zip；演示日志不落盘、不支持下载）。
- 支持 `GET /api/ai/config` 检查当前 Provider、模型和配置状态。
- 分析详情页按**模块**组织，顶部模块导航常驻并随滚动高亮：`01 分析概览`（结论 / 关键统计 / 处置建议）、`02 可疑事件`、`03 AI 研判`、`04 日志模板`、`05 实体关联`、`06 统一时间线`、`07 日志明细`；空模块自动隐藏并重新编号，模块可单独折叠，另有「折叠关联分析」一键收起次要模块。
- AI 配置弹窗的 Provider / 模型使用**自定义选择器**（搜索、品牌头像、默认模型说明、选中对勾），不再使用浏览器原生下拉；`Esc` 可关闭弹窗。
- 支持一次上传多份日志，跨 SSH、Nginx、Apache 和通用日志统一分析。
- 支持通过分析详情导出 JSON 数据或 HTML 研判报告。
- AI 配置页面会根据 Provider 自动提供默认 Base URL 和常用模型选择，也支持自定义兼容网关。
- 内置演示日志库覆盖 SSH、IIS、Windows/RDP、JSON/CSV、Firewall/WAF 与未识别应用日志，可在上传弹窗中选择后直接体验完整分析流程。
- 未识别类型的日志（`generic`）会做在线模板挖掘（Drain3），输出模板、出现次数与占比，仅出现一次的模板标记为罕见。
- 分析结果包含**实体关联**（按来源 IP、目的 IP、账户串联，跨网络与认证日志）与**统一时间线**（事件 + 证据按时间合并）。

## 同类开源项目与产品定位

目前公开社区中没有发现与 AI-LogInsight 完全一致的项目，但以下开源项目在日志分析、异常检测、数字取证或 AI 辅助研判方面具有较高参考价值。

### 高度相似项目

#### NetForensicAI

项目地址：[https://github.com/Sh3n0bi/NetForensicAI](https://github.com/Sh3n0bi/NetForensicAI)

NetForensicAI 是一个本地优先的数字取证和调查平台，支持多来源证据、时间线、事件关联、检测规则、AI 辅助调查和证据化报告。

与 AI-LogInsight 的共同点：

- 强调证据优先；
- 支持多来源数据关联；
- 支持时间线分析；
- AI 结论需要建立在具体证据上；
- 不以自动攻击或自动处置为核心。

主要区别是 NetForensicAI 更偏 DFIR 和数字取证，而 AI-LogInsight 更偏安全日志上传、异常行为识别和快速研判。

#### Security Log Analyzer

项目地址：[https://github.com/BOURICE/log-analysis-tool](https://github.com/BOURICE/log-analysis-tool)

Security Log Analyzer 是一个轻量化日志分析工具，覆盖 Apache、Nginx、SSH 等日志，并支持暴力破解、SQL 注入、XSS、路径遍历、Web 扫描、IP 统计、时间线和报告导出。

它与 AI-LogInsight 在 SSH/Web 日志检测和分析报告方面最接近，适合参考日志解析、确定性检测规则和报告结构。AI-LogInsight 在多模型接入、证据化 AI 研判、前端筛选和多日志关联方面进一步扩展。

#### AI Incident Analysis Agent

项目地址：[https://github.com/DiogoRibeiro7/ai-incident-analysis-agent](https://github.com/DiogoRibeiro7/ai-incident-analysis-agent)

该项目面向日志和指标的 AI 事件分析，支持时间线标准化、异常检测、事件关联、根因分析、证据排序和结构化报告生成。

它适合参考 AI 分析上下文构建、事件关联和报告生成方式。AI-LogInsight 则更聚焦 SSH、Web 访问日志和安全可疑行为研判。

### 部分重合项目

#### SentinelSoC

项目地址：[https://github.com/fleames/SentinelSoC](https://github.com/fleames/SentinelSoC)

SentinelSoC 是一个偏实时监控的安全运营面板，支持 Web 访问日志、SSH 暴力破解、IP 统计、路径分析、行为评分和安全事件查询。

它适合参考实时监控、SSH/Web 分离展示和行为评分。AI-LogInsight 当前更偏“上传日志后完成一次完整分析并生成研判报告”。

#### LogGuardian

项目地址：[https://github.com/blackms/LogGuardian](https://github.com/blackms/LogGuardian)

LogGuardian 主要探索使用大语言模型进行日志语义提取、模板分析和异常分类，适合参考 LLM 日志异常检测方向。

#### LogAI

项目地址：[https://github.com/salesforce/logai](https://github.com/salesforce/logai)

LogAI 是日志解析、摘要、聚类和时间序列异常检测库，适合参考机器学习异常检测、日志聚类和通用日志分析算法。

它不是完整的安全研判平台，也不专门针对 SSH 暴力破解或 Web 攻击行为。

#### Wazuh

项目地址：[https://github.com/wazuh/wazuh](https://github.com/wazuh/wazuh)

Wazuh 是成熟的开源安全监控和 SIEM/XDR 平台，支持日志采集、入侵检测、主机监控、漏洞检测、合规检测和安全告警。

Wazuh 的规模和定位明显大于 AI-LogInsight。AI-LogInsight 不复制 Wazuh 的持续采集、资产管理和自动化处置能力，而是保持轻量的日志分析与 AI 辅助研判定位。

#### Sigma

项目地址：[https://github.com/SigmaHQ/sigma](https://github.com/SigmaHQ/sigma)

规则规范：[https://github.com/SigmaHQ/sigma-specification](https://github.com/SigmaHQ/sigma-specification)

Sigma 是通用日志检测规则标准，不是完整的日志分析平台。AI-LogInsight 后续可以参考其规则组织方式，将当前检测逻辑逐步规范为包含日志类型、检测条件、风险等级、证据和说明的可配置规则。

### AI-LogInsight 的差异化定位

AI-LogInsight 的核心定位是：

> **面向安全运维、应急响应和日志审计人员的轻量化安全日志分析与 AI 辅助研判平台。**

它与大型 SIEM 或单纯的 AI 聊天工具不同，主要特点包括：

- 上传日志后自动完成识别、解析、统计和异常检测；
- 使用规则检测发现候选事件，再由 AI 结合证据进行辅助研判；
- 展示源 IP、目标 IP、访问路径、状态码、时间线和原始日志证据；
- 支持多份日志统一分析和跨日志事件关联；
- 支持多种主流 AI Provider 和本地 Ollama；
- AI 不可用时仍保留本地规则分析结果；
- 支持分页筛选、CSV 导出以及 JSON/HTML 报告；
- 只输出风险判断和进一步排查建议，不自动攻击、执行命令、封禁 IP 或修改系统。

推荐重点参考的三个项目：

1. [NetForensicAI](https://github.com/Sh3n0bi/NetForensicAI)：参考证据链、时间线和可解释性。
2. [Security Log Analyzer](https://github.com/BOURICE/log-analysis-tool)：参考 SSH/Web 解析、检测规则和报告结构。
3. [AI Incident Analysis Agent](https://github.com/DiogoRibeiro7/ai-incident-analysis-agent)：参考 AI 上下文构建、事件关联和报告生成。

以上项目的具体功能、许可证和实际运行质量应以其官方仓库当前内容为准。引入代码、规则或依赖前，需要单独确认许可证兼容性。

## 本地运行

后端：

```powershell
cd backend
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload
```

前端（另开终端）：

```powershell
cd frontend
npm run dev
```

打开 `http://localhost:5173`，上传 `sample_logs/ssh/auth.log`、`sample_logs/iis/iis-access.log`、`sample_logs/windows/security-rdp.log`、`sample_logs/structured/vpn-events.json`、`sample_logs/structured/bastion-auth.csv` 或 `sample_logs/generic/app.log` 即可查看分析结果。

前端构建过（`cd frontend && npm run build`）之后，也可以只起后端：后端会直接托管
`frontend/dist`，访问 `http://127.0.0.1:8000` 即可，不需要 Node 常驻。

## Windows 便携版（解压即用）

不想装 Python / Node 时用打包版：从 Releases 下载 `AI-LogInsight-<版本>-win64.zip`，解压后双击
`AI-LogInsight.exe`，控制台出现访问地址后浏览器会自动打开（默认
`http://127.0.0.1:8000`，端口被占用时自动往后找）。

- **配置 AI 研判（可选）**：把 `.env.example` 复制为 `.env` 并填入 API Key。不配置也能用——
  规则检测、证据溯源、导出等功能不受影响，界面会提示 AI 研判未配置。
- **数据位置**：数据库与上传的原始日志只保存在 exe 同级的 `data/` 目录，卸载 = 删除整个目录。
- **改端口**：设置环境变量 `LOGINSIGHT_PORT=8010` 后重新启动。
- 首次运行可能被杀毒软件拦截（PyInstaller 打包程序的常见误报），可加入信任，或按下面自行构建。

### 自行构建便携版

```powershell
cd backend
.\.venv\Scripts\python.exe -m pip install -r requirements-build.txt
cd ..\frontend
npm run build
cd ..\backend
.\.venv\Scripts\python.exe scripts\build_exe.py --version 1.0.0
```

产物在 `backend/dist/`：`AI-LogInsight/`（目录）与 `AI-LogInsight-<版本>-win64.zip`。
构建后可自检（启动 exe → 查规则与首页 → 上传示例日志，失败时非零退出）：

```powershell
.\.venv\Scripts\python.exe scripts\smoke_portable.py
```

构建说明：`AI-LogInsight.spec` 定义资源布局（`rules/`、`evaluation/`、`sample_logs/` 与前端
`dist/` 进包，可写的 `data/` 留在 exe 旁）；启动入口是 `scripts/launcher.py`（加载 `.env`、
选空闲端口、就绪后开浏览器）；路径在源码/打包两种模式下的差异由 `app/runtime_paths.py` 统一处理。

推 `v*` 标签（或手动触发 `Release` 工作流）时，GitHub Actions 会先跑规则门禁与核心回归，
再在 Windows 上构建便携版、跑同一个冒烟脚本，通过后把 ZIP 附到 Release。

## Docker 部署

需要已安装并启动 Docker Desktop。在项目根目录执行：

```powershell
docker compose up --build -d
```

打开 `http://localhost:8080`。停止服务：

```powershell
docker compose down
```

上传文件、SQLite 数据库和案件证据保存在 Docker 卷 `loginsight-data` 中。
默认单文件和单次分析上限为 500MB，可通过 `.env` 中的
`LOGINSIGHT_MAX_FILE_BYTES`、`LOGINSIGHT_MAX_ANALYSIS_BYTES` 调整，但不建议超过
项目验证范围。也可以运行 `.\启动Docker.ps1` 一键启动。

接口包括：

```text
GET    /api/health
GET    /api/rules
POST   /api/logs/upload
GET    /api/logs
GET    /api/analysis/{id}
DELETE /api/analysis/{id}
POST   /api/analysis/{id}/ai
POST   /api/analysis/{id}/ai/start
GET    /api/ai/tasks/{task_id}
GET    /api/analysis/{id}/download
GET    /api/analysis/{id}/insights
GET    /api/ai/config
POST   /api/ai/test
PUT    /api/ai/config
GET    /api/ai/usage-history
GET    /api/analysis/{id}/ai/ledger
GET    /api/analysis/{id}/ai/ledger/export?format=json|html|csv
GET    /api/analysis/{id}/records?page=1&page_size=50
GET    /api/analysis/{id}/records/export
GET    /api/analysis/{id}/report?format=json
GET    /api/analysis/{id}/report?format=html
POST   /api/rules/preview
PATCH  /api/rules/{rule_id}/enabled?enabled=false
GET    /api/rules/audit
```

> 规则预览（`POST /api/rules/preview`）、启停覆盖（`PATCH /api/rules/{rule_id}/enabled`）与变更审计（`GET /api/rules/audit`）是**后端接口能力，前端未接入**，需直接调用接口使用，详见 §6.5.5。
> AI 研判台账（`GET /api/analysis/{id}/ai/ledger`）同理：记录本次研判的 `provider` / `model`、`tool_trace`（每次工具调用与返回摘要）、结论引用的 `evidence_ids`、被溯源校验拦下的 `unsupported_claims`、`usage` 与 `duration_ms`，可用 `/export?format=json|html|csv` 导出；接口可用，页面尚未提供入口。

### 配置 AI 研判

复制 `.env.example` 为 `.env`，选择 Provider。除 Anthropic 外，内置厂商均使用 OpenAI Chat Completions 兼容协议：

```env
AI_PROVIDER=deepseek
DEEPSEEK_API_KEY=
DEEPSEEK_BASE_URL=https://api.deepseek.com
DEEPSEEK_MODEL=deepseek-chat
AI_TIMEOUT_SECONDS=300
AI_MAX_TOOL_ROUNDS=4
AI_MAX_OUTPUT_TOKENS=4096
AI_PROMPT_CACHE=true
```

> **研判以结论准确为先，不追求快速返回。** 上述三个上限默认已给足余量（单次请求 300 秒、工具追加调用 4 轮、输出 4096 tokens），慢模型或长上下文日志可继续调大；不需要为了快一点而牺牲结论质量。请求超时的报错会明确给出已等待时长，便于判断是模型慢还是服务不可用。

> **`AI_MAX_TOOL_ROUNDS` 留空时按场景自适应**：无事件的干净日志收敛为 1 轮，有事件默认 4 轮，≥2 万条记录自动翻倍到 8；显式配置时始终以配置为准。Token 成本控制的内置行为（工具结果指针化、历史上下文裁剪、记录字段白名单、事件证据按风险分档、轻量档、System Prompt 精简、prompt caching）见 [`docs/ai-token-cost.md`](docs/ai-token-cost.md)，复测用 `cd backend && .venv\Scripts\python.exe scripts\bench_ai_context.py`。

> **`AI_PROMPT_CACHE`（默认 `true`）**：system prompt 与工具定义在整个会话中逐字节不变，是天然的缓存前缀。Anthropic / OpenRouter 需要显式标记，会在 system prompt 上自动打 `cache_control`；DeepSeek / OpenAI 走自动前缀缓存，只依赖「稳定字段在前」的排序。命中缓存的输入按折扣计价（约 1/10）。设为 `false` 可关闭。

可直接切换到其他内置厂商，例如：

```env
AI_PROVIDER=qwen
QWEN_API_KEY=
QWEN_MODEL=qwen-plus
```

支持的内置 Provider 名称：

```text
openai, deepseek, qwen, qianfan, zhipu, moonshot, minimax,
siliconflow, openrouter, groq, together, fireworks, mistral,
xai, gemini, anthropic, ollama, openai_compatible
```

对于未列出的主流厂商，只要其提供 OpenAI-compatible 接口即可直接接入：

```env
AI_PROVIDER=openai_compatible
AI_API_KEY=
AI_BASE_URL=https://your-provider.example/v1
AI_MODEL=your-model-name
```

Gemini 可使用内置的 OpenAI 兼容入口：

```env
AI_PROVIDER=gemini
GEMINI_API_KEY=
GEMINI_MODEL=gemini-2.0-flash
```

Anthropic 使用原生 Messages 协议：

```env
AI_PROVIDER=anthropic
ANTHROPIC_API_KEY=
ANTHROPIC_BASE_URL=https://api.anthropic.com
ANTHROPIC_MODEL=claude-3-5-haiku-latest
```

使用本机 Ollama 时：

```env
AI_PROVIDER=ollama
OLLAMA_BASE_URL=http://127.0.0.1:11434/v1
OLLAMA_MODEL=llama3.1
OLLAMA_API_KEY=ollama
```

Ollama 通常不需要真实 API Key，但对应模型和服务必须已经在本机运行。不配置远程 API Key 或本地服务不可用时，系统仍可使用本地规则完成分析；前端会显示 AI 状态和失败原因，不影响规则结果。

`GET /api/ai/config` 用于读取配置状态；页面中的“测试连接”会调用 `POST /api/ai/test`，用最小请求验证 Provider 是否可达，不会发送日志内容。

默认不发送 `response_format`，以兼容更多模型网关；如果确认所用服务支持 JSON response format，可设置 `AI_JSON_RESPONSE_FORMAT=true`。

页面中的“AI 配置”按钮可以保存当前 Provider、Base URL、模型和 API Key。配置写入本机项目根目录 `.env`，接口和页面均不会回显密钥明文。

Provider 选择后，页面会自动填充推荐 Base URL，并将常用模型显示为下拉选项。选择“自定义模型...”后可以直接填写模型名称；Base URL 也可以改为企业内部或第三方 OpenAI-compatible 网关。

### 内置演示日志

上传弹窗包含“内置演示日志”区域，当前提供：

```text
SSH：认证失败、成功登录和高权限账户
IIS：Web 访问、敏感路径和 404 扫描
Windows/RDP：4625 失败与 4624 成功登录
JSON / CSV：通用结构化认证事件
Firewall/WAF：多目的端口探测候选
应用日志：未识别类型，演示模板挖掘与罕见模板
```

可以只选择一种日志体验单类解析，也可以全选后进行多日志关联分析。演示日志由后端从 `sample_logs/` 白名单目录读取，与用户上传日志使用同一解析、检测、证据和报告流程；不会执行任何系统操作。

### 日志分页和筛选

“日志明细”默认每页请求 50 条，支持按源 IP、目的 IP、路径/URL、日志类型、动作和状态筛选：

```text
GET /api/analysis/{id}/records?page=1&page_size=50&source_ip=10.0.0.8&path=/.git
```

`page_size` 支持 10 到 200。未填写筛选项时也只返回当前页，避免大日志一次性加载和渲染。
接口返回 `available_log_types`，前端会根据当前分析实际解析出的类型动态生成日志类型选项。筛选结果还可以通过 `/records/export` 导出 CSV。

### 多文件上传和跨日志关联

页面可一次选择多个 `.log`、`.txt`、`.csv` 或 `.json` 文件。接口使用重复的 `files` 字段：

```text
POST /api/logs/upload
files[]=auth.log
files[]=access.log
```

系统会分别识别和解析文件，然后合并记录、统计、异常事件和时间线；来源文件名会保存在 `metadata.source_files`，每条事件还会记录 `source_files` 和 `correlation_basis`。当前关联依据包括同一来源 IP、时间范围内的连续记录和多个日志文件证据，不会把缺少证据的事件强行判定为同一攻击。

AI 行为结果中的 `evidence_ids` 必须引用当前分析返回的 `events[].evidence_items[].id`。后端会过滤不存在的编号，避免模型引用日志中不存在的证据；如果没有足够证据，行为可以返回空的 `evidence_ids` 并说明无法确认。

### 报告导出

分析完成后可调用：

```text
GET /api/analysis/{id}/report?format=json
GET /api/analysis/{id}/report?format=html
```

### 检测规则元数据

`GET /api/rules` 返回当前检测规则清单，包括规则 ID、名称、适用日志类型、风险等级、启用状态、阈值、时间窗口、来源（`builtin` / `sigma`）与 ATT&CK 标签。规则以 YAML 声明式表达，由 `app/services/rules_engine.py` 执行（见 §6.5）；规则接口只读，便于前端展示、测试与复用。

当前支持通过环境变量覆盖部分阈值：

```env
SSH_FAILURE_THRESHOLD=20
SSH_FAILURE_WINDOW_SECONDS=300
WEB_404_THRESHOLD=20
WEB_404_WINDOW_SECONDS=300
RULE_SSH_BRUTEFORCE_ENABLED=true
RULE_SSH_BRUTEFORCE_SUCCESS_ENABLED=true
RULE_SSH_PRIVILEGED_LOGIN_ENABLED=true
RULE_WEB_SENSITIVE_PATH_ENABLED=true
RULE_WEB_PATH_TRAVERSAL_ENABLED=true
RULE_WEB_404_SCAN_ENABLED=true
```

规则默认全部启用。将对应的 `RULE_*_ENABLED` 设置为 `false`、`0`、`no` 或 `off` 即可关闭单条规则；设置为 `true`、`1`、`yes` 或 `on` 即可启用。修改 `.env` 后需要重启后端才会对新上传的日志生效。关闭某条规则不会影响其他规则、日志解析、统计和原始证据保留。

阈值配置无效或小于等于 0 时会回退到默认值；启停配置使用无法识别的值时也会回退为默认启用。

除 `.env` 之外，也可以通过接口**覆盖**单条规则的启停状态（`PATCH /api/rules/{rule_id}/enabled`），并用 `GET /api/rules/audit` 追溯变更记录，详见 §6.5.5。接口只提供「启停覆盖」，**不能增删改规则内容** —— 规则的增删改仍然只能改 `backend/rules/*.yaml`，避免把规则管理扩大成复杂的策略平台。

JSON 适合后续系统处理，HTML 适合直接查看或归档。报告只包含当前分析结果，不执行任何自动处置。

运行后端测试：

```powershell
cd backend
.\.venv\Scripts\python.exe -m pytest -q
```

通过：

> **日志导入 → 日志识别 → 结构化解析 → 统计分析 → 异常检测 → AI 智能研判 → 可疑行为输出**

帮助安全人员快速从大量日志中发现值得关注的异常行为。

------

# 1. 项目定位

AI-LogInsight 不是完整的 SIEM、XDR、SOAR，也不是单纯的 AI Chat。

项目定位为：

> **AI 辅助型安全日志分析与可疑行为研判平台。**

核心目标只有一个：

> **让用户上传日志后，系统能够自动分析日志，并告诉用户“哪些行为值得关注、为什么可疑、可能是什么行为”。**

------

# 2. 核心工作流

```text
用户上传日志
      │
      ↓
日志类型识别
      │
      ↓
日志解析 / 标准化
      │
      ↓
基础统计
      │
      ↓
规则检测
      │
      ↓
提取可疑行为
      │
      ↓
AI Agent 深度分析
      │
      ↓
行为研判
      │
      ↓
风险等级 + 分析依据
      │
      ↓
Web 页面展示
```

------

# 3. 产品核心原则

## 3.1 AI 不是日志解析器

不要把大量原始日志直接发送给大模型。

正确流程：

```text
原始日志
 ↓
程序解析
 ↓
结构化
 ↓
统计 / 规则
 ↓
提取关键事件
 ↓
AI Agent
 ↓
研判
```

程序负责：

- 日志格式解析
- 正则匹配
- 字段提取
- 时间统计
- IP统计
- 请求统计
- 次数统计
- 规则检测
- 数据聚合

AI 负责：

- 理解异常行为
- 综合多个证据
- 判断行为是否可疑
- 分析可能的攻击行为
- 解释判断依据
- 给出进一步分析建议

------

# 4. V1.0 功能范围

V1.0 只实现以下功能。

## 4.1 日志上传

支持：

```text
.log
.txt
.csv
.json
.xml      （事件查看器等导出的事件 XML）
.evtx     （Windows 本机事件日志二进制，需 python-evtx）
```

上传空间治理默认限制：

```text
单个文件：50 MB
单次分析所有文件合计：200 MB
data/uploads/ 全局占用：2 GB
```

可在 `.env` 中通过 `LOGINSIGHT_MAX_FILE_BYTES`、`LOGINSIGHT_MAX_ANALYSIS_BYTES`、
`LOGINSIGHT_MAX_STORAGE_BYTES` 调整，三个值均使用字节数。落盘失败会自动回滚该次分析的目录与记录。

上传目录自检（列出没有对应分析记录的目录，默认只读，确认后加 `--apply` 删除）：

```bash
cd backend && .venv\Scripts\python.exe scripts\clean_uploads.py
cd backend && .venv\Scripts\python.exe scripts\clean_uploads.py --apply
```

大日志性能基准（默认 1/5/10 MB，`--mb 50` 按上传上限压测；输出解析耗时、规则匹配耗时、峰值内存、命中数与覆盖率）：

```bash
cd backend && .venv\Scripts\python.exe scripts\bench_large_log.py
```

------

## 4.2 自动日志识别

支持识别：

```text
SSH
Nginx
Apache
IIS
Windows Security
RDP
JSON / CSV 通用事件
Firewall
WAF
Generic
```

当前已实现：SSH、Nginx/Apache、IIS（W3C 扩展日志）、Windows Security / RDP（事件查看器或 wevtutil 文本导出）、Windows EVTX 二进制、**Windows 事件日志键值化导出**、**syslog / 容器日志**（`时间 级别 主机 程序[PID]:` 前缀，内层访问日志与应用键值日志自动分派）、JSON / CSV 通用事件、Firewall/WAF 键值日志、MySQL / PostgreSQL / MongoDB / Redis 数据库日志、Generic。

识别结果：

```json
{
  "log_type": "ssh",
  "confidence": 0.98
}
```

------

# 5. V1.0 日志类型

## SSH

典型：

```text
auth.log
secure
```

重点分析：

- 登录失败
- 登录成功
- 暴力破解
- 多账户尝试
- 登录失败后成功
- 异常来源 IP
- 异常登录时间
- root / administrator 等高权限账户登录

------

## Nginx / Apache

典型：

```text
access.log
```

解析兼容三种写法：

```text
标准 combined（带引号）  10.0.0.9 - - [12/Sep/2026:01:01:00 +0800] "GET /x HTTP/1.1" 200 123 "-" "ua"
无引号                   10.0.0.9 - - [12/Sep/2026:01:01:00 +0800] GET /x HTTP/1.1 200 123 - ua
脱敏（剥离 `/` `:`）      10.0.0.9 - - [12Sep2026010100 +0800] GET x HTTP1.1 200 123 - ua
```

脱敏格式说明：请求段无引号、路径与时间中的 `/` `:` 被移除时仍可识别与解析；敏感路径判定会自动为缺失前导 `/` 的路径补齐（如 `wp-admin` → `/wp-admin`、`.env` → `/.env`）。若分隔符本身被删除（如 `/.git/config` 变成 `.gitconfig`），无法还原原始路径，只能按普通请求处理。

重点分析：

- 高频请求
- 大量 404
- 目录扫描
- 敏感文件探测
- `.git` 探测
- `etc/passwd` 等敏感路径访问
- SQL 注入特征（`web.sql_injection`）
- 路径遍历特征（`web.path_traversal`，原始与解码后的 URL 都参与匹配）
- XSS 特征（`web.xss`）
- 命令注入特征（`web.command_injection`）
- 敏感管理接口探测（`web.sensitive_interface`：actuator、swagger、phpinfo、server-status、debug、`/metrics` 等；**不含 `/health`、`/ready` 这类健康检查端点**，它们被负载均衡与编排系统日常高频访问，纳入会产生大量误报）
- WebShell 上传或访问（`web.webshell`）
- 异常 User-Agent（`web.scanner_user_agent`：sqlmap、nikto、nmap 等已知工具）
- 登录接口失败聚集（`web.auth_bruteforce` / `web.auth_bruteforce.success`：同一来源对含 login/auth/token 等路径出现多次 401/403，随后出现 2xx 时升级为 high）

攻击特征按「来源 IP + 规则」聚合为一条事件，事件内保留命中次数、首末时间和最多 10 条证据。

------

## IIS

典型：

```text
iis-access.log
```

支持 W3C 扩展日志格式（含 `#Fields:` 指令行，字段顺序以该行为准；缺少指令行时按默认字段顺序解析）。**`#Fields:` 声明的每一列都会原样落进记录**（`cs(User-Agent)`、`time-taken`、`sc-substatus` 等都能当规则判据），下面只是其中映射到规范字段的部分：

字段映射：

```text
date + time          -> 时间 / timestamp_iso
c-ip                 -> 源 IP
s-ip                 -> 目的 IP
cs-method            -> 动作
cs-uri-stem(+query)  -> 路径 / URL
cs-username          -> 账户
sc-status            -> 状态码
```

重点分析：

- 大量 404 与目录扫描
- 敏感文件探测（`.git`、`.env`、`phpmyadmin`）
- 路径遍历特征
- 异常请求频率

IIS 复用 Nginx/Apache 的同一套 Web 规则，规则清单里 `web.*` 的 `log_types` 已包含 `iis`。

------

## Windows / RDP

典型：

```text
Security（事件查看器或 wevtutil 文本导出）
```

已实现的解析与检测：

- 识别事件 ID `4625`（登录失败）与 `4624`（登录成功），其余安全事件不进入认证统计；
- 解析 `Date`、`Account Name`、`Logon Type`、`Source Network Address`，并优先取「Account For Which Logon Failed」/「New Logon」段落中的账户，避免误取 Subject 中的计算机账户；
- 登录类型 7 / 10 标记为 `rdp_logon`（交互式远程），其余为 `logon`；
- 同一来源 IP 在 5 分钟内失败达到阈值（默认 10 次）产生 `rdp_bruteforce`；随后 30 分钟内出现成功登录则升级为 `rdp_bruteforce_success`（high）；
- `administrator` 等高权限账户成功登录产生 `privileged_login`（规则 `windows.privileged_logon`）。

重点分析：

- 登录成功
- 登录失败
- 高频认证失败
- RDP 暴力破解
- 异常账户
- 异常来源
- 登录失败后成功
- 异常时间登录

------

## Windows EVTX（本机事件日志）

支持两种来源：

```text
二进制 .evtx    本机 C:\Windows\System32\winevt\Logs 目录，或其它机器导出的事件日志
XML 导出        事件查看器「另存为 XML」/ wevtutil 导出的事件 XML
```

解析与判定：

- 认证事件：`4625`（登录失败）、`4624`（登录成功）映射为统一认证记录，字段取 `TargetUserName`、`IpAddress`、`LogonType`、`TimeCreated`；
- 登录类型 7 / 10 标记为 `rdp_logon`（交互式远程），其余为 `logon`，因此直接复用 `rdp.bruteforce`、`rdp.bruteforce.success`、`windows.privileged_logon`；
- 其余事件保留为明细记录（`action=event`，`status=事件 ID`），用于人工取证与事件 ID 分布统计；认证事件优先保留 5000 条，其它事件最多 500 条；
- 时间戳按时区归一化后参与时间窗口计算，可与其它日志类型混合分析。

------

## 通用 JSON / CSV 事件

适用于 VPN、堡垒机、应用系统、网络设备等已经输出结构化字段的日志导出。

支持的三种形态：

```text
JSON 对象数组        [{"timestamp": "...", "src_ip": "..."}, ...]
JSON 容器对象        {"events": [...]}   // 也支持 records / logs / items / data / results
NDJSON              每行一个 JSON 对象
CSV / 分隔符文本    首行为表头，支持逗号、分号、制表符、竖线
```

除下列别名映射到规范字段外，**记录里出现的每个键都会原样保留**（如 `event_type`、`dst_ip`、中文列名），规则可直接引用。字段别名（不区分大小写、支持下划线/空格/中文）：

```text
timestamp   timestamp, time, @timestamp, datetime, event_time, ts, 时间
source_ip   source_ip, src_ip, src, client_ip, remote_ip, ip, 源IP, 源地址
destination_ip  destination_ip, dst_ip, dst, dest_ip, server_ip, 目的IP, 目的地址
username    username, user_name, user, account, account_name, 账户, 用户名
action      action, method, event, event_type, operation, 动作
result      result, outcome, disposition, 结果
status      status, status_code, http_status, code, 状态码
url         url, uri, path, request, request_uri, 路径
raw         raw, message, msg, log, 原始日志
```

取值归一化：

```text
success / succeeded / accepted / allow / ok / 成功 / 通过   -> success
failure / failed / deny / blocked / reject / 失败 / 拒绝     -> failure
signin / sign_in / sign-in                                -> login
```

归一化后即可直接复用既有检测规则：

- `action=login` 且 `result` 为失败/成功 → `auth.bruteforce`、`auth.bruteforce.success`；
- `url` + `status`（如 404）→ `web.sensitive_path`、`web.path_traversal`、`web.404_scan`。

通用结构化日志使用独立规则 `auth.*`，不会把非 SSH 来源的认证失败误标为 SSH 暴力破解。

------

## 未识别日志的模板挖掘

日志未匹配任何已知类型时（`log_type=generic`），在原始正则解析之外再做一次**在线模板挖掘**（Drain3），把「解析不出内容」变成「有结构可看」：

```text
输入   未结构化的应用日志、中间件日志、自定义文本日志
输出   模板 + 出现次数 + 占比，仅出现一次的模板标记为罕见
```

- IP 与长十六进制串在聚类前先做掩码（模板中显示为 `<IP>`、`<HEX>`），避免同类日志被拆成大量模板；
- 只扫描前 20000 个非空行，最多输出 20 个模板，按出现次数排序；
- 罕见模板（仅出现一次）通常是异常事件、错误堆栈或一次性告警，排查时优先查看；
- 模板挖掘只做结构归纳，**不产生风险结论**；风险等级仍由检测规则给出，两者互不干扰。

------

## 实体关联与统一时间线

在所有规则检测完成后，额外做一层轻量关联，用于把分散在多份日志中的同一行为串起来：

```text
实体关联   按来源 IP、目的 IP、账户聚合
          命中可疑事件的实体，或跨 ≥2 份日志文件出现的实体会被列出
          输出：风险等级、关联事件数、命中规则、日志类型、来源文件、首次/末次出现时间

统一时间线  可疑事件与其日志证据按时间合并
          输出：时间、事件/证据、标题、规则编号、来源 IP / 账户 / 文件
```

- 实体风险等级取其关联事件的最高风险，不新增独立结论；
- 跨日志类型串联示例：同一 IP 既出现在 SSH 认证失败中、又在 Web 日志里探测敏感路径，会合并为同一实体的两条线索；
- 时间线最多输出 200 条，时间戳统一按归一化后的时间排序。

------

# 6. 异常行为检测

异常检测采用：

```text
规则
+
统计
+
AI
```

而不是完全依赖 AI。

------

## 6.1 SSH 暴力破解

例如：

```text
192.168.1.100

5分钟：
失败登录：387
尝试账户：17
成功登录：1
```

检测引擎产生：

```json
{
  "event_type": "ssh_bruteforce",
  "risk_level": "high",
  "source_ip": "192.168.1.100",
  "failed_count": 387,
  "success_count": 1
}
```

然后交给 AI Agent。

------

## 6.2 Windows / RDP 认证失败聚集

例如：

```text
203.0.113.66

5分钟：
登录类型 10（RDP）失败：12
涉及账户：1
随后成功登录：1
```

检测引擎产生：

```json
{
  "event_type": "rdp_bruteforce_success",
  "rule_id": "rdp.bruteforce.success",
  "risk_level": "high",
  "source_ip": "203.0.113.66",
  "failed_count": 12,
  "success_count": 1
}
```

阈值与时间窗口可通过环境变量调整：

```env
RDP_FAILURE_THRESHOLD=10
RDP_FAILURE_WINDOW_SECONDS=300
```

------

## 6.3 通用结构化日志的认证失败聚集

适用于 VPN、堡垒机、应用等 JSON / CSV 事件：

```json
{
  "event_type": "auth_bruteforce_success",
  "rule_id": "auth.bruteforce.success",
  "risk_level": "high",
  "source_ip": "203.0.113.66",
  "failed_count": 20,
  "success_count": 1
}
```

```env
AUTH_FAILURE_THRESHOLD=20
AUTH_FAILURE_WINDOW_SECONDS=300
```

------

------
# 6.5. 规则体系

检测规则是**数据**而不是代码：全部规则定义在 `backend/rules/*.yaml`，
由声明式规则引擎（`app/services/rules_engine.py`）执行。新增规则只需添加 YAML 文件，不需要改代码。

目前规则共 **2272 条**：74 条内置规则（含 7 条数据库规则、33 条 Sysmon 行为规则、3 条应用层安全信号规则、4 条 Windows 事件规则、2 条域控异常登录导出规则）+ 2198 条 Sigma 导入规则（其中 7 条人工精选、2191 条批量社区导入，覆盖 SigmaHQ 全部 17 个 Windows 子目录）。批量导入的规则由 `backend/scripts/import_sigma_community.py` 生成，落地在 `backend/rules/95-sigma-community.yaml`，只有「能严格转换且不在正常流量上误报」的才会保留，其余跳过/剔除的原因见 `docs/sigma-import-report.md`。Sigma 的 Windows 规则用的就是 EVTX 的**标准字段名**（`OriginalFileName` / `ParentCommandLine` / `Details` 等），EVTX 解析器按标准结构把 `<System>` 事件头与 `<EventData>` 里每个 `<Data Name="…">` 原样落进记录，转换时**直连**这些字段，不做「从原文里抠字段」的近似匹配。

## 6.5.1 声明式规则表达

一条规则的完整结构：

```yaml
source: builtin                      # 规则来源（builtin / sigma）
rules:
  - id: web.sensitive_path           # 规则编号，事件与报告中的 rule_id
    title: 敏感路径探测
    description: 请求 .git、.env、后台或系统敏感路径。
    level: medium                    # critical / high / medium / low / info
    logsource:
      log_types: []                  # 记录级筛选：空 = 不限
      exclude_log_types: [json, csv] # 反向筛选：排除结构化日志（可选）
      display_log_types: [nginx_apache, iis]   # 仅用于 /api/rules 展示
    enabled_env: RULE_WEB_SENSITIVE_PATH_ENABLED
    threshold: 20                    # 默认阈值（可选）
    threshold_env: WEB_404_THRESHOLD # 阈值环境变量（可选，优先于默认值）
    window_seconds: 300              # 时间窗（可选）
    window_env: WEB_404_WINDOW_SECONDS
    detection:
      where:                         # 记录必须全部满足（AND）
        - {field: url, op: exists}
        - {field: url, op: any_path_prefix, transform: url_path,
           values: ["/.git", "/etc/passwd", "/wp-admin"]}
      any:                           # 任一子条件成立即可（OR of AND，可选）
        - - {field: action, op: equals, value: GET}
      aggregate:                     # 时间窗聚合（可选）
        group_by: [source_ip]
        count_gte: 20
        window_seconds: 300
        distinct_field: destination_port   # 去重计数：用于端口扫描这类「多目标」规则
        distinct_gte: 10
        bucket: true                       # 只按分组汇聚，不做阈值与时间窗（特征类规则用）
        follow_up:                         # 关联窗口之后的另一类记录（可选）
          where: [{field: result, op: equals, value: success}]
          within_seconds: 1800
    suppresses: [ssh.bruteforce]   # 命中后压制其它规则，避免同一行为重复告警
    upgrade_rule: ssh.bruteforce.success   # 被该规则升级；其启用状态决定基础规则的措辞
    tags: [attack.T1595]           # ATT&CK 标签
    event:
      type: sensitive_path_access
      name: 敏感路径探测
      level: medium
      summary: "{ip} 请求了敏感路径 {sample}，需结合业务场景核实。"
      count: window                # window | distinct（计数口径）
      time: window                 # window | follow_up_end（last_seen 取窗口末条或关联末条）
      evidence: single             # single | window_head | window_follow_up
      evidence_head: 10
      follow_up_head: 2
      notes:                       # 按 follow_up 状态选择文案
        success_note:
          none: "，暂未发现随后成功登录。"
          downgraded: "，失败后成功登录规则当前已关闭。"
          found: "，随后出现 {success_count} 次成功登录。"
```

### 匹配原语

| 类别 | 取值 | 说明 |
| --- | --- | --- |
| `op` | `exists` / `equals` / `in_set` / `any_contains` / `contains` / `startswith` / `any_startswith` / `endswith` / `any_endswith` / `any_path_prefix` / `regex` | `any_path_prefix` 匹配「路径相等或以该路径 + `/` 开头」，专用于敏感路径判定 |
| `transform` | `none` / `lower` / `upper` / `url_decode` / `url_path` | `url_decode` 双重解码并转小写；`url_path` 再取路径并补前导 `/` |
| `field` | 字段名或字段名数组 | 数组表示「任一字段满足」 |
| `negate` | `true` / `false` | 取反，用于表达 `not filter` |
| `ignore_case` | 默认 `true` | 大小写不敏感 |

### 事件文案占位符

`summary` 与 `notes` 支持：`{ip}` `{count}` `{window}` `{accounts}` `{success_count}` `{sample}` `{path}` `{statuses}` `{ports}` `{destination}` `{protocol}` `{username}` `{rdp_hint}` `{rdp_attempts}` `{logon_hint}` `{success_note}`。

### 新增 / 修改规则

1. 在 `backend/rules/` 下新建或修改 YAML；
2. 在 `backend/evaluation/corpus/` 增加正样本与负样本用例（覆盖新规则）；
3. 运行质量评估：`cd backend && .venv\Scripts\python.exe scripts\eval_rules.py`，要求 precision / recall 保持 100%；
4. 运行测试：`.venv\Scripts\python.exe -m pytest tests -q`。

阈值与开关沿用环境变量，因此 `.env` 中的既有配置无需改动。

## 6.5.2 社区规则导入（Sigma）

```bash
# 预演（只报告，不写文件）
cd backend && .venv\Scripts\python.exe scripts\import_sigma.py --input <目录或文件>

# 正式导入
cd backend && .venv\Scripts\python.exe scripts\import_sigma.py --write
```

导入链路：

```text
Sigma YAML
  → logsource 映射（category / product+service → 本项目日志类型）
  → detection 条件解析（and / or / not / 括号 / 1 of / all of）
  → 字段映射 pipeline（cs-uri-stem → url、EventID → status、SourceAddress → source_ip ...；未登记的字段名原样直通）
  → 修饰符映射（contains / startswith / endswith / re / all）
  → DNF 归一化（OR of AND）→ 本项目 where / any 结构
```

转换约束（**不做近似猜测**）：

- 条件表达式按布尔代数严格转换，含 De Morgan 展开（`not 1 of filter_*` → 逐个条件取反）；
- 修饰符 `base64` / `cidr` / `fieldref` / `windash` / `lt|gt|lte|gte` 暂不支持；
- 字段名**原样直通**：Sigma 的 Windows 规则用的就是日志里的标准字段名（`OriginalFileName` / `ParentCommandLine` / `Details` …），解析器已按标准结构把它们落进记录；只有 `logsource`、修饰符、通配形态或条件展开无法保持语义时才整条跳过，并在报告中给出原因；
- 条件展开超过 64 个分支时跳过，避免语义漂移。

导入结果写入 `backend/rules/90-sigma.yaml`（由脚本生成，请勿手工编辑），并具备两级开关：

```env
RULE_SIGMA_IMPORTED_ENABLED=true              # 全局：一键停用全部导入规则
RULE_CROSS_SITE_SCRIPTING_STRINGS_ENABLED=false   # 单条规则开关（按标题生成）
```

`POST /api/rules/sigma/preview` 提供上传预演（只转换与报告，不写规则目录）。

当前导入样例（`backend/evaluation/sigma-samples/`，取自 SigmaHQ）：

```text
✓ Java Payload Strings                                  high     attack.T1190
✓ Path Traversal Exploitation Attempts                  medium   attack.T1190
✓ Source Code Enumeration Detection by Keyword           medium   attack.T1083
✓ SQL Injection Strings In URI                          high     attack.T1190
✓ Suspicious User-Agents Related To Recon Tools          medium   attack.T1190
✓ Cross Site Scripting Strings                          high     attack.T1189
✓ Denied Access To Remote Desktop                        medium   attack.T1021.001
✗ Potentially Suspicious Explicit Credential Local Logon  → 字段 TargetServerName 无法映射
✗ RDP over Reverse SSH Tunnel WFP                        → 字段 SourcePort 无法映射
```

## 6.5.3 基准集与误报率评估

标注语料位于 `backend/evaluation/corpus/*.yaml`：每个用例是一段真实风格的日志 + 期望命中的规则（含风险等级、次数、来源 IP），另有负样本验证阈值以下与正常流量不误报。

```bash
cd backend && .venv\Scripts\python.exe scripts\eval_rules.py           # 打印报告，存在偏差时退出码 1
cd backend && .venv\Scripts\python.exe scripts\eval_rules.py --write   # 同时写入 docs/rule-quality-report.md
```

- `GET /api/rules/quality` 以结构化形式返回同一份结果（供前端或流水线消费）；
- 该评估同时是**回归门禁**：`tests/test_rule_quality.py` 要求语料全绿且每条规则都有正样本，任何规则改动导致误报或漏报都会让测试失败。

当前结果：

```text
用例 123 / 123 通过 · 内置规则正样本覆盖 74 / 74 · TP 111 · FP 0 · FN 0 · precision 100% · recall 100%
```

> 另有 2191 条 Sigma 导入规则**没有本地正样本**，不计入上面的覆盖口径，只做过「正常流量零命中」筛查，详见 `docs/rule-quality-report.md`。

## 6.5.4 导入规则的批量检测效果验证

导入规则一千多条，逐条人工验证既做不到也没必要。`scripts/verify_sigma_rules.py` 把「规则能不能检出」拆成三个互不重叠的问题，各自用机器回答：

```bash
cd backend && .venv\Scripts\python.exe scripts\verify_sigma_rules.py           # 打印摘要
cd backend && .venv\Scripts\python.exe scripts\verify_sigma_rules.py --write   # 写入 docs/sigma-rule-verification.md
```

| 层 | 做法 | 回答的问题 |
|---|---|---|
| 层 1 合成正样本 | 从规则谓词树**反推一条必然满足它的记录**，再用 `evaluate_rule()` 端到端跑一次 | 这条规则的逻辑在我们的记录模型上能不能成立 |
| 层 2 真实语料回放 | 用 `sample_logs/`、`data/uploads/`、`evaluation/scenarios/` 的真实日志跑全部规则 | 它有没有在真实数据上命中过 |
| 层 3 负样本筛查 | 在「正常流量」内联语料上跑 | 它会不会在正常流量上乱报 |

当前结果：**1992 / 2198 可端到端触发（90.6%）· 疑似缺陷 0 · 判定过宽 0**；另有 206 条因正则无法反推、或跨字段约束过复杂而无法自动合成，如实单列而不是当作通过。

> 三层都只描述**规则的可验证状态**。层 1 通过只说明「能触发」，不说明「触发它的事件真的是攻击」；层 2 未命中不等于规则写错——本地语料里没有 mimikatz、没有 Cobalt Strike，缺的是**样本**而不是判据。

## 6.5.5 异常评分（借鉴 OWASP CRS）

CRS 的做法是「单条规则命中只加分，累计分数决定处置等级」。本项目的对应实现：

- 按**同一来源 IP** 累加事件分数：critical 10 / high 5 / medium 3 / low 1 / info 0；
- 达到阈值时升级风险等级：`RISK_SCORE_MEDIUM`（默认 5）/ `RISK_SCORE_HIGH`（10）/ `RISK_SCORE_CRITICAL`（15）；
- 跨来源不叠加，避免把不相关活动合并成高风险；
- **默认关闭**（`RISK_SCORING_ENABLED=false`）：分数照常计算并在详情页展示，但不改变风险等级与结论 —— 保证既有规则基线与回归结果稳定；
- 开启后，若因累计分数升级，结论会注明：`同一来源 203.0.113.60 的多项异常累计 21 分（high → critical），已按异常评分升级风险等级。`

## 6.5.6 规则治理接口（预览 / 启停 / 审计）

三个接口服务于「改规则之前先看清楚后果」，均为**后端接口，前端未接入**。

### 规则预览 `POST /api/rules/preview`

提交规则草稿做校验与试运行，**不写入规则目录**，因此失败也无需回滚。

请求体（`RulePreviewRequest`），三种草稿写法任选其一：

| 字段 | 说明 |
|---|---|
| `yaml_text` | 完整规则 YAML 文本 |
| `rule` / `rules` | 单条或多条规则的 JSON 对象 |
| `sample_log` | 可选的样本日志正文；留空则只做校验 |
| `filename` | 样本日志文件名，影响日志类型识别（默认 `preview.log`） |
| `expected_rule_ids` | 期望命中的规则 ID，用于算 FN |

返回 `RulePreviewReport`：`valid`、`errors`、`rule_ids`、`event_count`、`covered_records`、`true_positive` / `false_positive` / `false_negative`、`events`。

### 启停覆盖 `PATCH /api/rules/{rule_id}/enabled?enabled=false`

把单条规则的启停状态写入 `rule_overrides` 表，并记一条变更到 `rule_changes`。规则不存在时返回 404。

**与 `.env` 的关系**：`.env` 里的 `RULE_*_ENABLED` 仍是默认基线，接口覆盖**优先级更高**；规则对象每次请求重建，所以接口改动**立即生效，无需重启后端**（改 `.env` 才需要重启）。

### 变更审计 `GET /api/rules/audit?limit=100`

返回最近的启停变更（`limit` 取值 1–500，最新在前），每条含 `action`（`enable` / `disable`）、`rule_id`、`before`、`after`、`actor`、`created_at`。

> 当前 `actor` 由服务端写入，默认为 `console`；尚未接入登录态，因此审计记录的是「做了什么」，不是「谁登录做的」。

# 7. AI Agent

AI Agent 名称：

```text
Security Log Analysis Agent
```

简称：

```text
Log Analysis Agent
```

职责：

> 对程序发现的可疑日志行为进行进一步分析、关联和研判。

Agent 不负责：

- 执行系统命令
- 登录服务器
- 修改防火墙
- 封禁 IP
- 扫描目标
- 漏洞利用
- 自动处置安全事件

Agent 只负责：

> **分析日志并研判日志中存在的可疑行为。**

------

# 8. Agent 工作方式

例如用户：

```text
帮我分析这个 SSH 日志
```

Agent：

```text
① 获取日志类型
       ↓
② 获取统计结果
       ↓
③ 获取异常事件
       ↓
④ 查看关键证据
       ↓
⑤ 综合分析
       ↓
⑥ 判断是否存在可疑行为
       ↓
⑦ 输出分析结果
```

------

# 9. Agent Tools

V1.0 建议设计以下工具。

```text
tools/
├── log_metadata
├── log_statistics
├── query_events
├── query_evidence
└── timeline
```

------

## 工具实现状态（已落地）

研判前**确定性执行一轮**轻量只读工具，结果以指针形式并入上下文作为模型的事实输入：

```text
tool_results = log_metadata + log_statistics + query_events + timeline
```

其余工具（`query_evidence` / `query_behavior_deviations` / `query_uncovered_records` / `query_terminal_chains` / `query_records`）由模型按需追加调用，避免每次请求都重复携带大块证据。
- 工具定义（JSON Schema）随请求下发，模型可基于结果**追加调用**（无事件默认 1 轮、有事件默认 4 轮、≥2 万条记录 8 轮，可用 `AI_MAX_TOOL_ROUNDS` 固定；模型不再调工具时立即早停）；OpenAI-compatible Provider 支持工具调用，Ollama 与 Anthropic 自动降级为单次调用；
- 多轮调用下，**第二轮起首轮完整上下文会被替换为摘要占位**（保留记录总数、本地风险、覆盖度、事件总数与查询指引），原始明细由模型按需用工具查询；这样避免每轮重发全部日志原文导致成本按轮次倍增。
- 前端「AI 调用工具轨迹」展示每一步的工具名、参数、来源（自动执行 / 模型调用）与结果摘要，并单独一行给出**本次研判用量**（输入/输出 tokens、轮数、缓存命中率）；
- token 用量按服务端字段归一化（DeepSeek `prompt_cache_hit_tokens`、OpenAI `prompt_tokens_details.cached_tokens`、Anthropic `cache_read_input_tokens`），服务端未回传时明确省略而非显示为 0%，避免把「未上报」误读成「缓存没生效」；
- 所有工具只读，不接受任何写入、封禁或处置参数。

------

## 证据溯源校验

AI 结论必须能落到日志事实上，否则会被标记而不是被当成结论：

- 结论与 behaviors 中出现的 IP、记录编号必须存在于**本次日志记录集合**（含未被规则命中的记录），否则前端提示「未在日志证据中找到对应记录」；
- `evidence_ids` 只接受本次分析中真实存在的证据编号；模型直接引用 `record-N` 时自动映射回证据编号；
- 校验只提示、不修改 AI 输出，避免掩盖模型的不确定性。

------

## 工具速查

| 工具 | 用途 |
|---|---|
| `log_metadata` | 日志类型、文件、数量、时间范围、解析状态 |
| `log_statistics` | Top IP / 用户 / URL、HTTP 状态码、成功与失败次数 |
| `query_events` | 检测引擎已发现的异常事件 |
| `query_evidence` | 异常事件对应的原始日志证据 |
| `timeline` | 把多个相关事件按时间顺序组织 |
| `query_behavior_deviations` | IOA 行为偏离（首次出现的目的地址 / 域名、非常用端口外联等） |
| `query_uncovered_records` | 未被任何规则覆盖的记录 |
| `query_terminal_chains` | 终端证据链（进程、文件、注册表、DNS、外联） |
| `query_records` | 按字段条件查原始记录 |

`AGENTS.md` §6 只规定工具调用的约束（预取哪些、只读边界），工具定义以本表为准。

------

# 10. Agent 输入

Agent 尽可能接收结构化数据。

例如：

```json
{
  "log_type": "ssh",
  "time_range": {
    "start": "2026-09-12 01:00:00",
    "end": "2026-09-12 01:10:00"
  },
  "statistics": {
    "total": 12032,
    "failed_login": 387,
    "successful_login": 2
  },
  "events": [
    {
      "type": "ssh_bruteforce",
      "source_ip": "192.168.1.100",
      "count": 387
    }
  ]
}
```

------

# 11. Agent 输出

必须使用结构化 JSON。

```json
{
  "has_suspicious_behavior": true,
  "risk_level": "high",
  "confidence": 0.92,
  "behaviors": [
    {
      "type": "ssh_bruteforce",
      "name": "疑似SSH暴力破解",
      "confidence": 0.95,
      "evidence": [
        "5分钟内产生387次失败登录",
        "尝试多个用户名",
        "随后出现成功登录"
      ]
    }
  ],
  "summary": "该日志存在明显的SSH暴力破解特征。",
  "recommendations": [
    "核实来源IP是否属于可信管理地址",
    "核实成功登录行为"
  ]
}
```

------

# 12. 风险等级

统一使用：

```text
critical
high
medium
low
info
```

原则：

> 本节口径与 `AGENTS.md` §10 保持一致，**以 `AGENTS.md` 为准**。

### Critical

必须存在非常强的证据组合。

### High

存在明显的高风险攻击行为特征。

例如：

```text
大量认证失败
+
成功登录
```

### Medium

存在明显异常，但证据不足。

### Low

低风险异常行为。

### Info

普通行为或仅供参考的信息。

------

# 13. 重要原则：不要过度判断

AI **不得因单条日志就断言「确定被攻击」**，只能给出有限度的结论，并同时附上证据、分析逻辑与置信度。

可选结论口径与「风险等级 + 置信度 + 证据 + 分析依据」的强制要求见 `AGENTS.md` §9 与 §11。

------

# 14. Web 页面

## 页面结构

```text
AI-LogInsight
│
├── 分析工作台
├── 日志管理
├── 分析结果
├── 可疑行为
└── 设置
```

V1.0 不需要复杂的权限系统。

------

# 15. UI 风格

整体采用：

> **企业级安全产品 + AI**

设计关键词：

```text
白色
浅灰
蓝色
简洁
专业
数据可视化
卡片式
```

避免：

```text
× 黑色背景
× Cyberpunk
× 霓虹灯
× 代码雨
× 大面积渐变
× 过度动画
```

整体视觉参考企业级安全产品的产品设计语言，但不要复制任何厂商的 Logo、商标或具体页面。

------

# 16. 推荐技术栈

## Frontend

```text
Vue 3
TypeScript
Vite
Element Plus
ECharts
Pinia
Vue Router
Axios
```

核心：

> Vue 3 + TypeScript + Element Plus

------

## Backend

```text
Python 3.11+
FastAPI
Pydantic
SQLAlchemy
SQLite
```

------

## AI

第一版：

```text
DeepSeek API
```

同时抽象：

```text
AI Provider
```

未来支持：

```text
DeepSeek
Qwen
OpenAI-compatible API
Ollama
```

------

# 17. Agent 技术

V1.0：

```text
FastAPI
   ↓
Agent Service
   ↓
LLM
   ↓
Tool Calling
```

暂时不强制引入复杂 Agent Framework。

推荐先实现：

```text
Agent
 ├── System Prompt
 ├── Tool Calling
 ├── Structured Output
 └── Analysis Context
```

当后续出现复杂：

```text
多步骤分析
条件分支
循环调用工具
多Agent
状态管理
```

再考虑：

```text
LangGraph
```

------

# 18. 数据处理原则

日志首先在本地处理。

```text
用户日志
 ↓
Backend
 ↓
Parser
 ↓
结构化数据
 ↓
Detector
 ↓
关键事件
 ↓
脱敏
 ↓
AI
```

不要默认：

```text
用户日志
 ↓
直接上传DeepSeek
```

------

# 19. 敏感数据脱敏

AI 请求前进行脱敏：

```text
Token
Cookie
Authorization
Password
Session
API Key
```

例如：

```text
Authorization: Bearer abcdefg
```

转换：

```text
Authorization: Bearer [REDACTED]
```

------

# 20. 项目目录

推荐：

```text
AI-LogInsight/
│
├── frontend/
│   ├── src/
│   │   ├── api/
│   │   ├── components/
│   │   ├── layouts/
│   │   ├── views/
│   │   ├── router/
│   │   ├── stores/
│   │   └── types/
│   ├── package.json
│   └── vite.config.ts
│
├── backend/
│   ├── app/
│   │   ├── api/
│   │   ├── core/
│   │   ├── models/
│   │   ├── schemas/
│   │   ├── services/
│   │   │   ├── parser/
│   │   │   ├── detector/
│   │   │   ├── agent/
│   │   │   └── analyzer/
│   │   └── main.py
│   │
│   ├── tests/
│   └── requirements.txt
│
├── rules/
│   ├── ssh/
│   ├── web/
│   └── windows/
│
├── prompts/
│   └── log_analysis_agent.md
│
├── sample_logs/
│   ├── ssh/
│   ├── nginx/
│   └── apache/
│
├── data/
│
├── .env.example
├── docker-compose.yml
├── AGENTS.md
└── README.md
```

------

# 21. Backend 模块职责

```text
backend/app/services/
```

## parser

负责：

```text
日志识别
日志解析
字段提取
标准化
```

------

## detector

负责：

```text
异常检测
规则匹配
统计分析
事件生成
```

------

## analyzer

负责：

```text
数据聚合
事件关联
时间线
证据整理
```

------

## agent

负责：

```text
调用LLM
Tool Calling
AI研判
结构化输出
```

------

# 22. 标准日志数据结构

所有 Parser 尽可能输出统一格式。

```json
{
  "timestamp": "",
  "source_ip": "",
  "destination_ip": "",
  "source_port": null,
  "destination_port": null,
  "username": "",
  "hostname": "",
  "method": "",
  "url": "",
  "status": "",
  "user_agent": "",
  "action": "",
  "result": "",
  "process": "",
  "message": "",
  "raw": ""
}
```

不适用字段：

```text
null
```

不要为了统一结构伪造字段。

------

# 23. Event 数据结构

```json
{
  "id": "event-001",
  "type": "ssh_bruteforce",
  "risk_level": "high",
  "source_ip": "192.168.1.100",
  "target_ip": "192.168.1.10",
  "first_seen": "",
  "last_seen": "",
  "count": 387,
  "evidence": [],
  "summary": ""
}
```

------

# 24. API

## 上传日志

```http
POST /api/logs/upload
```

## 获取日志

```http
GET /api/logs
```

## 开始分析

```http
POST /api/analysis
```

## 获取分析状态

```http
GET /api/analysis/{id}
```

## 获取事件

```http
GET /api/events
```

## 获取事件详情

```http
GET /api/events/{id}
```

## Agent 分析事件

```http
POST /api/events/{id}/analyze
```

------

# 25. 开发原则

## 原则 1

先实现可运行 MVP。

不要一次性实现：

```text
SIEM
XDR
SOAR
多租户
分布式计算
```

------

## 原则 2

优先确定：

```text
数据结构
API
Parser
Detector
Agent
```

再优化 UI。

------

## 原则 3

AI 输出必须结构化。

禁止后端直接依赖：

```text
LLM自然语言
```

作为核心业务逻辑。

------

## 原则 4

所有 AI 结论必须能够追溯到日志证据。

------

# 26. V1.0 开发顺序

```text
Phase 1
项目初始化
        ↓
Phase 2
Vue + FastAPI
        ↓
Phase 3
日志上传
        ↓
Phase 4
SSH/Nginx/Apache Parser
        ↓
Phase 5
Detector
        ↓
Phase 6
事件中心
        ↓
Phase 7
DeepSeek
        ↓
Phase 8
Log Analysis Agent
        ↓
Phase 9
AI研判页面
        ↓
Phase 10
Docker部署
```

------

# 27. V1.0 验收标准

上传：

```text
auth.log
```

系统必须：

```text
✓ 自动识别SSH日志
✓ 显示日志数量
✓ 显示时间范围
✓ 统计来源IP
✓ 统计登录成功/失败
✓ 检测暴力破解
✓ 检测异常登录
✓ 生成可疑行为
✓ 展示证据
✓ 调用AI进行研判
✓ 输出风险等级
✓ 输出AI分析结论
```

例如：

```text
高风险

疑似 SSH 暴力破解

来源：
192.168.1.100

失败次数：
387

成功登录：
1

主要依据：
- 短时间大量认证失败
- 多账户尝试
- 后续出现成功登录
```

------

# 28. V1.0 明确不实现

```text
× 自动封禁IP
× 自动执行服务器命令
× 自动登录服务器
× 漏洞扫描
× 渗透测试
× WebShell执行
× 反弹Shell
× SOAR自动处置
× 防火墙自动配置
× EDR自动隔离
× 完整SIEM
× XDR
× 威胁情报平台
```

------

# 29. 最终产品闭环

```text
                    AI-LogInsight

                         用户
                          │
                          ↓
                      上传日志
                          │
                          ↓
                     日志识别
                          │
                          ↓
                     日志解析
                          │
                          ↓
                    统计 / 检测
                          │
                          ↓
                     可疑事件
                          │
                          ↓
                   Log Analysis Agent
                          │
                   ┌──────┴──────┐
                   ↓             ↓
                 证据分析       行为研判
                   │             │
                   └──────┬──────┘
                          ↓
                    风险等级
                          │
                          ↓
                    可疑行为结果
```

核心价值：

> **不是让 AI “看日志”，而是让 AI 帮助安全人员快速从日志中发现值得关注的可疑行为。**
