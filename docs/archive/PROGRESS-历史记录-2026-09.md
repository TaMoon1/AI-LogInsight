# 项目进度

更新时间：2026-09-16

> 逐次代码变更的详细记录（改动文件、原因、验证证据、遗留问题）见 `CHANGELOG.md`。

## 已完成

- 第一阶段 MVP：FastAPI + Vue 3。
- 日志上传、SSH/Nginx/Apache 基础识别和 SSH 候选事件检测。
- SSH 时间字段标准化，支持按 5 分钟窗口识别认证失败集中行为。
- SSH 多账户尝试、失败后成功登录、高权限账户成功登录检测代码已实现。
- Nginx/Apache 敏感路径、路径遍历候选、高频 404 Web 扫描候选检测代码已实现。
- 事件增加 `timeline` 时间线字段，保留原始日志证据。
- AI 研判前敏感信息脱敏工具已加入 `backend/app/services/sanitizer.py`。
- 当前研判已动态生成风险等级、置信度、结论和分析来源。
- 前端已根据风险等级切换颜色，并展示研判结论和置信度。
- 已增加按 SSH/Web 事件生成的下一步排查方向与具体方法。

## 当前阶段

- [x] 创建 SQLite 仓储层。
- [x] 上传结果持久化。
- [x] 历史分析查询和删除 API。
- [x] 前端历史记录列表。
- [x] 补充持久化、删除和错误场景测试。
- [x] 完善 SSH 时间窗口、多账户和时间线检测。
- [x] 完善 Nginx/Apache 敏感路径和扫描检测。
- [x] 补充 SSH/Web 检测、误关联和脱敏测试。
- [x] 增加 AI 请求前脱敏工具（AI Provider 尚未接入）。
- [x] 增加 Windows 一键启动和关闭脚本。
- [x] 增加规则驱动的动态当前研判和排查建议。
- [x] 接入 OpenAI-compatible 结构化 AI 研判接口。
- [x] AI 请求前使用脱敏后的统计、事件、时间线和有限日志样本。
- [x] AI 结果持久化，并在 AI 失败时保留本地规则结果。
- [x] 前端增加手动触发 AI 研判和结果展示。
- [x] 增加 `GET /api/ai/config` AI 配置检查接口。
- [x] 前端显示 AI Provider、模型、配置状态、调用中、完成和失败状态。
- [x] 抽象 DeepSeek、OpenAI-compatible、Ollama Provider。
- [x] 支持一次上传多份日志并统一分析。
- [x] 支持跨日志时间线和事件关联基础能力。
- [x] 增加 JSON/HTML 研判报告导出。
- [x] 增加 AI 配置刷新按钮和 Provider 连接测试接口。
- [x] 扩展主流模型接入：厂商预设、通用 `AI_BASE_URL` 配置和 Anthropic 原生协议。
- [x] 为事件和结构化记录增加来源文件标记及跨日志关联依据。
- [x] HTML 报告增加事件来源、关联依据和完整事件时间线。
- [x] 增加日志明细分页和源/目 IP、路径、日志类型、动作、状态筛选。
- [x] 日志类型筛选改为根据当前分析动态生成，并支持筛选结果 CSV 导出。
- [x] 增加轻量 AI 配置页面，支持 Provider、Base URL、模型和密钥保存。
- [x] 按当前分析实际记录动态生成日志类型筛选项，并支持筛选结果 CSV 导出。
- [x] 增加 AI 配置保存后的前端生效状态反馈。
- [x] 参考 NetForensicAI 增加事件证据编号、证据元数据和规则 ID。
- [x] 参考 AI Incident Analysis Agent 将规则、证据编号和关联依据纳入 AI 上下文。
- [x] 前端和 HTML 报告展示检测规则与结构化证据来源。
- [x] 证据支持 `record_id` 联动日志明细，前端可从事件证据定位并高亮原始记录。
- [x] AI 行为增加 `evidence_ids`，并过滤当前分析中不存在的证据引用。
- [x] 前端展示 AI 证据引用并支持点击定位原始日志。
- [x] 建立轻量检测规则元数据注册表，支持只读查询和阈值环境变量覆盖。
- [x] 增加内置规则独立启停配置，`GET /api/rules` 返回实时 `enabled` 状态，并补充回归测试和配置说明。
- [x] 增加 Firewall/WAF 键值日志解析与轻量端口扫描候选检测。
- [x] AI Provider 配置增加推荐 Base URL 和模型下拉选择，保留自定义配置能力。
- [x] 增加内置演示日志库和一键分析入口，覆盖当前主要日志类型。
- [ ] 后续：模型侧再考虑流式响应和按 Provider 配置重试。

## 运行验证

- 后端测试：`40 passed`，1 warning（Starlette/AnyIO 第三方弃用提示，不影响功能）。
- 前端 TypeScript 类型检查：已通过。
- 动态研判字段测试：已覆盖空日志和 SSH 高风险场景。
- AI 结构化结果和失败降级测试：已通过。
- Provider 选择、多文件上传、跨日志合并、JSON/HTML 报告导出测试：已覆盖。
- 事件来源文件、关联依据和 HTML 时间线：已覆盖。
- 日志明细动态类型选项、分页筛选和 CSV 导出：已覆盖并通过。
- OpenAI-compatible 和 Anthropic 请求格式、响应提取及错误处理：已覆盖。
- AI 配置刷新和连接测试：已接入，已覆盖未配置和可达 Provider 场景。
- 前端完整构建：当前沙箱运行 Vite 时触发 `spawn EPERM`，未能完成；不是类型检查错误。
- 启停脚本：已优化为并行就绪轮询，尚未在本机双击进行 GUI 验证。

## 中断恢复入口

下一步优先补充跨事件实体关联和基准日志集测试；随后评估 AI 流式响应与按 Provider 重试。
仍需保持 AI 失败时的本地规则分析结果，并避免把大量原始日志直接发送给模型。

## 本次进度记录（2026-09-16 · 规则独立启停配置完成）

### 本次完成

- 为 SSH、Web、Windows/RDP、JSON/CSV 认证规则提供 `.env` 独立启停配置，默认全部开启。
- `/api/rules` 暴露每条规则当前的 `enabled` 状态，便于前端展示和诊断。
- 增加规则关闭后的回归测试，确认关闭规则不会影响解析、统计或其他未关闭能力。
- README 补充启停值、重启要求、默认行为和只读边界说明。

### 下一步

- 增加跨日志实体关联，优先围绕同一来源 IP、目的 IP、账户和时间窗口生成统一时间线。
- 为现有解析器建立小型基准日志集，补充字段缺失、乱码、边界阈值和误报场景测试。

## 本次进度记录（2026-09-16 · Firewall/WAF 解析与端口扫描候选完成）

### 本次完成

- 新增 `firewall_waf` 日志类型识别，支持常见 `SRC`、`DST`、`PROTO`、`DPT`、`ACTION/VERDICT` 键值格式。
- 统一记录增加目的端口和协议字段，事件证据与明细筛选可保留这些信息。
- 新增 `firewall.port_scan` 规则：同一来源在时间窗口内访问同一目的地址的多个端口时生成中风险候选事件。
- 新增 Firewall/WAF 示例日志、达到阈值、低于阈值和规则关闭测试。

### 验证

- 后端测试：`38 passed`，1 warning。
- 前端 TypeScript 类型检查：通过。

## 本次进度记录（2026-09-16 · AI 配置预设与内置演示日志完成）

### 本次完成

- AI 配置状态接口增加 Provider 推荐 Base URL 和常用模型列表。
- 前端选择 Provider 后自动填充地址和模型，模型使用下拉选项，兼容网关仍可自定义。
- 新增演示日志清单接口和白名单分析接口，前端上传弹窗可按文件选择或批量体验。
- 演示库覆盖 SSH、IIS、Windows/RDP、JSON/CSV 和 Firewall/WAF，复用真实上传的解析、规则、证据和持久化流程。
- 增加目录越界防护和接口测试。

### 验证

- 后端测试：`40 passed`，1 warning。
- 前端 TypeScript 类型检查：通过。

## 本次进度记录（2026-09-14）

### 本次完成

1. 修复混合日志筛选测试：
   - `mixed` 作为整体分析类型保留；
   - 明细筛选使用记录实际类型 `ssh` 或 `nginx_apache`；
   - Web 记录筛选已改为 `log_type=nginx_apache`。
2. 完成动态日志类型筛选验证：
   - 类型选项从当前分析记录动态计算；
   - 不再依赖固定的日志类型列表。
3. 完成 CSV 导出验证：
   - 导出接口复用明细筛选条件；
   - 支持源 IP、目的 IP、路径、日志类型、动作和状态等条件；
   - 导出字段包含时间、来源文件、日志类型、IP、URL、动作、状态、结果和原始日志。
4. 完成启动和关闭脚本语法核对：
   - `start_loginsight.ps1` 可正常解析；
   - `stop_loginsight.ps1` 可正常解析；
   - 启动脚本保留并行启动和端口就绪轮询。

### 本次验证

- 后端测试：`20 passed`。
- 前端 TypeScript 类型检查：通过。
- PowerShell 启停脚本语法检查：通过。
- 测试中仅存在第三方依赖弃用警告，不影响当前功能。

### 当前项目能力

当前版本已经具备：

- SSH、Nginx/Apache 日志识别和解析；
- 规则检测、风险等级、置信度和证据展示；
- 多模型 Provider 配置和 AI 研判；
- AI 失败时保留本地规则分析结果；
- 多日志上传、来源文件标记和跨日志关联；
- 日志明细分页、动态类型筛选和 CSV 导出；
- JSON/HTML 研判报告导出；
- Windows 一键启动和关闭脚本。

### 下次恢复入口

优先实现 AI 配置保存后的生效状态反馈：

- 保存后显示配置已保存；
- 明确提示后端后续请求将使用新配置；
- 提供轻量“刷新配置状态”或“测试连接”反馈；
- API Key 仍只保存在后端 `.env`，前端不回显明文。

后续再评估流式 AI 响应、按 Provider 重试和更多日志解析器。

## 本次进度记录（2026-09-15 · 前端首页重构为「分页日志列表 + 常驻筛选栏」）

### 本次完成

1. 首页改为「日志列表」视图：
   - 日志记录改为表格列表，每页 10/20/50 条可切换，带首页 / 上一页 / 页码 / 下一页 / 末页；
   - 不再像之前那样把全部历史记录无限向下堆叠；
   - 每行展示文件名、任务号、日志类型、风险等级、状态、上传时间与操作（查看 / 删除）；
   - 支持关键词、日志类型、风险等级、状态筛选与四种排序，均为客户端即时筛选。
2. 筛选功能固定到首页：
   - 新增常驻 `sticky` 筛选栏（吸附在 60px 页头下方），任何视图下都可见；
   - 列表范围展示「日志列表筛选」：关键词 / 日志类型 / 风险等级 / 状态 / 排序 / 重置；
   - 打开某条日志后自动切换为「日志明细筛选」：源 IP / 目的 IP / 路径 / 日志类型 / 动作 / 状态 / 筛选 / 重置 / 导出 CSV，并提供「返回日志列表」；
   - 之前筛选框只在点开某条日志后、且位于页面底部，现已移除该行为。
3. 交互与视觉重构（参考主流控制台风格，浅色企业级）：
   - 左侧固定侧边栏（品牌、日志列表导航 + 计数、AI 配置入口、后端 / 分析引擎状态卡）；
   - 页头吸附并放置「上传日志」「导出 JSON / HTML」等页面级操作；
   - 上传日志改为弹窗：支持拖拽、点击选择、多选去重、文件名与大小、单文件移除；
   - 指标卡、事件卡、证据折叠、来源 IP / 状态码统计、排查建议重新排版；
   - 统一设计令牌（颜色 / 圆角 / 阴影 / 间距）、徽章、分页控件、空状态、加载态、滚动条与响应式断点；
   - 新增内联 SVG favicon，消除浏览器 404。

### 后端配套修改

- `GET /api/analysis/{id}/records` 的 `status` 参数之前只匹配 Web 状态码字段，SSH 日志（结果存在 `result`，如 `success` / `failure`）筛不出任何记录；
- 现已改为同时匹配 `status` 与 `result`，前后端筛选提示「状态码 / 结果」与实际行为一致；
- 新增测试 `test_record_status_filter_matches_result_and_status_code` 覆盖该行为。

### 本次验证

- 后端测试：`21 passed`（新增 1 个筛选测试）。
- 前端 TypeScript 类型检查：`vue-tsc --noEmit` 通过。
- 生产构建：`vite build --outDir <临时目录>` 通过（CSS 18.1 kB / JS 99.1 kB，gzip 4.3 / 36.8 kB）。
- 浏览器实测（Chrome 无头 + Playwright，1440×940）：
  - 列表每页 10 行，共 110 条 → 11 页；
  - 风险筛选「高风险」→ 72 条，筛选栏 `position: sticky` / `top: 60px` 生效；
  - 翻页到第 2 页正常；返回列表后筛选栏自动切回「日志列表筛选」；
  - 明细每页切 20 条后翻到第 2 / 2 页正常；状态筛选 `failure` → 20 条；
  - 控制台零报错、零 4xx。

### 已知问题

1. `npm run build` 在本沙箱内会因 `rmSync` 的 safe-delete shim 超时失败（`prepareOutDir` 阶段），不是代码问题；改用 `vite build --outDir <未存在的目录>` 可正常产出。
2. 后端测试会写入真实的 `data/*.db`，导致首页混入大量测试数据（当前 117 条，文件名如 `report.log` / `empty.log` / `2 个日志文件`）。建议后续把测试切到临时数据库。
3. `App.vue` 已达 1090 行、`style.css` 525 行，后续可拆分为 `LogList` / `AnalysisDetail` / `UploadModal` / `AiConfigModal` 等组件。

### 下次恢复入口

1. 测试改用临时 `data/*.db`，避免污染真实数据；
2. 评估日志列表的服务端分页（当前为客户端筛选 + 分页，记录量大后需要后端支持）；
3. 拆分前端组件；再评估流式 AI 响应与按 Provider 重试。

## 本次进度记录（2026-09-15 · 启动脚本解析错误修复）

### 问题现象

- 双击 `启动 AI-LogInsight.bat` 报错：
  - `start_loginsight.ps1:139 字符: 41` 字符串缺少终止符 `"`；
  - `start_loginsight.ps1:132 字符: 6` `else {` 语句块缺少右 `}`。

### 根因

- `start_loginsight.ps1` 之前保存为 UTF-8 **无 BOM**。
- Windows PowerShell 5.1（`powershell.exe`，即 `.bat` 调用的解释器）对无 BOM 脚本按系统 ANSI 代码页（简中为 CP936/GBK）解码；
- 中文多字节序列的尾字节会把紧随其后的 ASCII `"` 一并吞掉，导致引号配对整体错位；
- 因此报错行 **139 不是真正的出错行**，真正崩点是上一处中文提示行（旧 133 行 `日志。"`）的收尾引号被吞。
- 之前"PowerShell 启停脚本语法检查：通过"的结论是在 PowerShell 7 下得出的（pwsh 默认 UTF-8），掩盖了 5.1 的编码问题。

### 修复内容

- `start_loginsight.ps1` 重新保存为 **UTF-8 with BOM**，并在文件头注释中固化该约束。
- 所有中文提示在收尾引号前保留一个 ASCII 空格，作为 BOM 丢失时的二次保险。
- 就绪轮询上限由 5 秒提升到 60 秒（Vite 首次冷启动常超过 5 秒），并区分"仅后端就绪/仅前端就绪/未就绪"三种输出。
- `stop_loginsight.ps1` 为纯 ASCII，无此问题，未改动。

### 验证

- 后端测试：`20 passed`（0.68s），1 条第三方弃用警告。
- 脚本已通过最坏情况 DBCS 解码校验：引号配对无错位。
- 本机 PowerShell 5.1 双击验证：待人工执行（当前环境无法调用 `powershell.exe`）。

### 经验固化

1. 项目内所有 `.ps1` 必须保存为 **UTF-8 with BOM**。
2. 语法校验必须用真实解释器 `powershell.exe`，不能只用 `pwsh`。
3. 中文提示若紧邻引号，优先在引号前补 ASCII 空格。

## 本次进度记录（2026-09-15 · 参考同类项目增强证据链）

### 本次完成

- 对照 NetForensicAI，补充事件级结构化证据：
  - 每条证据生成 `evidence-{event_type}-{序号}` 编号；
  - 保存时间、来源文件、源/目的 IP、用户名、URL 和原始日志；
  - 保留原有 `evidence` 字段，兼容旧数据和旧调用方。
- 对照 Security Log Analyzer，补充规则可解释性：
  - SSH 暴力破解、成功登录、高权限登录、敏感路径、路径遍历和 Web 扫描均带有 `rule_id`；
  - HTML 报告和前端事件详情展示规则编号。
- 对照 AI Incident Analysis Agent，增强 AI 上下文：
  - AI 可同时看到规则编号、证据编号、来源文件和关联依据；
  - 证据原文仍经过脱敏后才进入 AI 请求。
- 前端增加 AI 配置保存成功提示，明确显示后续研判使用的 Provider 和模型。
- 证据支持记录级联动：
  - 结构化日志记录增加稳定 `record_id`；
  - 事件证据保存对应记录 ID；
  - 前端点击“定位日志”后切换到明细并高亮对应记录；
  - 增加 `record_id` 精确查询接口参数。
- 保存成功后清除旧的连接测试结果，避免把旧状态误认为新配置状态。
- 保存失败时在 AI 配置状态区域显示错误信息。
- 保留后端 `.env` 存储和 API Key 脱敏规则，前端不回显密钥。

### 本次验证

- 后端测试：`22 passed`。
- 前端 TypeScript 类型检查：通过。
- 第三方依赖仍有 1 条弃用警告，不影响当前功能。
- 证据链、规则编号和 AI 上下文测试：已通过。
- 证据定位和明细高亮测试：已通过。
- AI 证据引用校验和无效引用过滤测试：已通过。
- 规则清单接口、默认阈值和阈值覆盖测试：已通过。

### 下次恢复入口

优先评估：

1. AI 流式响应，改善长研判任务的等待体验；
2. 按 Provider 的有限重试和超时策略；
3. 在不发送全部原始日志的前提下，继续完善证据上下文构建。

## 当前差距评估（2026-09-15）

当前产品已经完成“日志上传 → 解析 → 规则检测 → 证据 → AI 研判 → 报告”的 MVP 闭环。
下一阶段不追求复制大型 SIEM，而是优先补强以下轻量能力：

1. 增加规则启停配置，但保持只读分析边界和轻量配置方式；
2. 增加 IIS、Firewall、JSON/CSV 通用事件等高价值解析器；
3. 增加跨事件的轻量实体关联和统一时间线；
4. 增加小型基准日志集、误报场景和解析覆盖率测试。

暂不实现：实时采集、完整 SIEM、用户权限、多租户、自动封禁、自动处置和复杂威胁情报平台。

## 本次进度记录（2026-09-15 · 新增 IIS 与 Windows / RDP 日志类型）

对应「当前差距评估」第 2 项：增加 IIS 等高价值解析器。

### 本次完成

1. **IIS（W3C 扩展日志）解析**
   - 以 `#Fields:` 指令行为准动态映射字段，缺失指令行时退回默认字段顺序；
   - 解析 `date + time`、`c-ip`（源 IP）、`s-ip`（目的 IP）、`cs-method`（动作）、`cs-uri-stem(+query)`（路径）、`cs-username`（账户）、`sc-status`（状态码）；
   - 目的 IP 此前在所有日志类型中恒为空，IIS 是第一个真正填充该字段的解析器；
   - 复用 Nginx/Apache 的同一套 Web 规则，`web.sensitive_path`、`web.path_traversal`、`web.404_scan` 的 `log_types` 增加 `iis`。
2. **Windows Security / RDP 解析**
   - 支持事件查看器 / `wevtutil` 文本导出（含事件头 + 空行 + 正文的格式），按空行切块并把无事件 ID 的正文块并入上一事件，避免正文与事件头被拆开；
   - 仅将 `4625`（登录失败）与 `4624`（登录成功）计入认证统计，其余安全事件跳过；
   - 账户解析优先取「Account For Which Logon Failed」/「New Logon」段落，避免误取 Subject 中的计算机账户（`WIN-SRV01$`）；
   - 登录类型 7 / 10 标记为 `rdp_logon`（交互式远程），其余为 `logon`；兼容中文字段名（日期 / 账户名 / 源网络地址 / 登录类型）。
3. **新增检测规则（规则总数 6 → 9）**
   - `rdp.bruteforce`（medium，默认 10 次 / 300 秒，可用 `RDP_FAILURE_THRESHOLD` 覆盖）；
   - `rdp.bruteforce.success`（high，失败聚集后 30 分钟内出现成功登录）；
   - `windows.privileged_logon`（medium，administrator 等高权限账户成功登录，含 RDP 提示）。
4. **检测与建议**
   - `detect_events` 增加 Windows/RDP 分支，事件结构（证据编号、时间线、来源文件、关联依据、`rule_id`）与 SSH / Web 保持一致；
   - 新增 RDP 排查建议（来源网段、账户锁定策略、登录类型 3 / 10、后续进程创建记录）。
5. **配套**
   - 新增示例日志 `sample_logs/iis/iis-access.log`、`sample_logs/windows/security-rdp.log`；
   - `.env.example` 增加「检测规则阈值与开关」段（SSH / Web / RDP 全覆盖）。
   - 前端无需改动：日志类型筛选项为动态生成，规则编号与证据展示沿用既有组件。

### 本次验证

- 后端测试：`28 passed`（新增 3 个：IIS 识别与 Web 规则命中、Windows/RDP 检测与规则编号、阈值以下不告警）。
- 端到端（真实 HTTP 上传示例日志）：
  - IIS：`log_type=iis`、32 行解析出 28 条记录、目的 IP `10.0.0.5`、统计 404×24，事件为敏感路径 ×3、路径遍历（high）、404 扫描（×24），整体风险 high；
  - Windows：`log_type=windows_rdp`、13 条记录、失败 12 / 成功 1，事件为 `rdp_bruteforce_success`（high，摘要含「RDP 登录失败 12 次」）与 `privileged_login`（`windows.privileged_logon`），`status=4625` 过滤返回 12 条。
- `GET /api/rules` 返回 9 条规则，`web.*` 的 `log_types` 已包含 `iis`。
- 前端实测（Chrome 无头 + Playwright）：日志类型下拉自动出现 `iis` 与 `windows_rdp`；详情页指标、事件、规则编号渲染正常；明细按 `4625` 过滤得 12 条；控制台零报错。

### 下次恢复入口

「当前差距评估」剩余项目，建议按此顺序：

1. 补充 Firewall / WAF 与通用 JSON、CSV 事件解析器（可复用现有 `record_id` / 证据结构）；
2. 跨事件的轻量实体关联（同 IP / 同账户跨日志类型串联）与统一时间线；
3. 小型基准日志集与误报场景测试（含阈值边界、跨时区时间戳、编码异常）；
4. AI 流式响应与按 Provider 重试（沿用既有 `ai_status` / `ai_error` 降级口径）。

## 本次进度记录（2026-09-15 · 通用 JSON / CSV 事件解析与认证检测复用）

对应「当前差距评估」第 2 项剩余部分：JSON / CSV 通用事件解析器。

### 本次完成

1. **通用 JSON 事件解析**（`log_type=json`）
   - 支持 JSON 对象数组、容器对象（`events` / `records` / `logs` / `items` / `data` / `results`）、NDJSON 三种形态；
   - 字段别名映射到统一记录：`@timestamp` / `time` / `ts` / `时间`、`src_ip` / `client_ip` / `源IP`、`dst_ip` / `server_ip` / `目的IP`、`user` / `account` / `账户`、`event_type` / `method` / `动作`、`result` / `结果`、`status_code` / `状态码`、`path` / `uri` / `路径`、`message` / `msg` / `原始日志`；
   - 时间兼容 ISO 8601（含 `Z` 与 `+08:00` 时区）。
2. **通用 CSV / 分隔符事件解析**（`log_type=csv`）
   - 自动判定分隔符（逗号、分号、制表符、竖线），要求表头至少有 2 个可识别字段，避免把普通文本误判为 CSV；
   - 支持中文表头与 BOM；保留原始行作为证据。
3. **取值归一化**（结构化日志入口统一处理）
   - `success` / `succeeded` / `accepted` / `allow` / `ok` / `成功` / `通过` → `success`；
   - `failure` / `failed` / `deny` / `blocked` / `reject` / `失败` / `拒绝` → `failure`；
   - `signin` / `sign_in` / `sign-in` → `login`。
   - 归一化后结构化日志可直接复用既有规则，无需额外适配代码。
4. **认证检测去重复用**
   - `_detect_ssh` 与 `_detect_windows` 合并为共享实现 `_detect_auth(records, profile)`，窗口聚合、失败后成功关联、证据与时间线构造完全共用，差异集中在 `AuthProfile`（动作集合、规则 ID、事件类型、名称、失败措辞、RDP 提示）；
   - 新增 `STRUCTURED_PROFILE` 与规则 `auth.bruteforce`（medium，20 次 / 300 秒）、`auth.bruteforce.success`（high），规则总数 9 → 11；
   - `detect_events` 按记录 `log_type` 分派：SSH（`login`）、Windows（`logon` / `rdp_logon`）、结构化（`json` / `csv`）互不重叠，避免同一批记录被重复计数；
   - 由此非 SSH 来源（VPN、堡垒机、应用）的认证失败不再被标记为「SSH 暴力破解」。
5. **配套**
   - 新增示例 `sample_logs/structured/vpn-events.json`（缩进 JSON，193 行）与 `sample_logs/structured/bastion-auth.csv`（分号分隔 + 中文表头）；
   - `.env.example` 增加 `AUTH_FAILURE_THRESHOLD`、`AUTH_FAILURE_WINDOW_SECONDS` 与 `RULE_AUTH_*` 开关；
   - 前端无需改动。

### 本次修复

- 缩进格式的 JSON 常超过 `detect_log_type` 的前 100 行采样窗口，导致被识别为 `generic`（示例日志实际命中）；
- 现改为 JSON 判定使用**完整文本**，CSV 仍按表头采样；新增回归测试 `test_pretty_printed_json_larger_than_sample_window_is_detected`。

### 本次验证

- 后端测试：`33 passed`（新增 5 个：JSON 事件与 auth 规则、NDJSON + 分号 CSV、CSV Web 规则与目的 IP、缩进 JSON 采样窗口、无结构文本回落 generic）。
- 端到端（真实 HTTP 上传示例）：
  - `vpn-events.json`：`log_type=json`、193 行解析 21 条记录、失败 20 / 成功 1（中英文结果值均归一化）、`auth_bruteforce_success`（high，`auth.bruteforce.success`）、带时区时间戳保留、目的 IP `10.0.0.30`；
  - `bastion-auth.csv`：`log_type=csv`、22 行解析 21 条记录、同一规则命中，中文表头与分号分隔正常工作。
- `GET /api/rules` 返回 11 条规则，含新增 `auth.*`。
- 既有 28 个测试全部保持通过，说明重构未改变 SSH / Windows / Web 行为。

### 下次恢复入口

1. Firewall / WAF 解析器（Firewall 可用 `SRC= / DST= / PROTO= / DPT=` syslog 风格 + 端口扫描候选规则）；
2. 跨事件的轻量实体关联（同 IP / 同账户跨日志类型串联）与统一时间线；
3. AI 流式响应与按 Provider 重试。
## 2026-09-16：本地规则研判演示样例与 Detection 状态优化

- 新增 `sample_logs/structured/auth-events-demo.csv`：同一来源 IP 在 5 分钟内连续 20 次认证失败，随后成功登录，用于复现高风险规则事件。
- Detection 区域增加“本地规则初步研判”说明，明确未调用 AI 时结论来自确定性规则和日志证据。
- 事件卡按风险等级增加左侧色带，规则 ID 使用等宽标签，提升高风险事件、证据和规则的可扫描性。
- 验证：样例解析 21 条记录，命中 `auth.bruteforce.success`，high，20 次，来源 IP `203.0.113.90`；AI 状态为未分析。
- 前端 `vue-tsc` 通过。后端全套测试中有 3 个既有 AI 配置测试受项目根目录 `.env` 中现存 API 配置影响，未改写用户配置。

## 2026-09-16：脱敏访问日志解析容错、Web 攻击特征规则与测试隔离

### 问题现象

上传 `access.log`（76 行）被判为 `generic`、已解析 0 行、风险 info，页面显示「未发现可疑事件」。

### 根因

1. 该文件是**脱敏后的访问日志**：请求段无引号、路径与时间中的 `/` `:` 被剥离（`16Sep2026090112 +0800`、`wp-admin`、`HTTP1.1`、`Mozilla5.0`）；
2. Web 解析依赖严格正则（必须匹配 `"METHOD URL HTTP/1.1"` 引号结构），脱敏后完全无法匹配；
3. 即便解析成功，该日志中的 SQL 注入、XSS、命令注入、WebShell、敏感管理接口探测等特征当时**没有对应规则**（`README.md` §5 已列为重点分析项，但未实现）。

### 本次完成

1. **Web 解析容错**：以 `_parse_web_line()` 取代原严格正则，兼容标准 combined、无引号、脱敏三种写法；请求段按 HTTP 版本标记切分，URL 允许包含空格（如 `searchq=' OR '1'='1`）。
2. **时间戳兼容**：`16/Sep/2026:09:01:12 +0800` 与 `16Sep2026090112 +0800` 均可解析。
3. **敏感路径判定**：路径缺失前导 `/` 时自动补齐，`wp-admin` / `.env` 可命中 `web.sensitive_path`。
4. **路径遍历匹配**：原始 URL 与双重解码 URL 同时参与匹配，编码型遍历（`%2e%2e%2e`）不再漏报。
5. **新增 6 条 Web 攻击特征规则**（规则 12 → 18，数据驱动 + 按「来源 IP + 规则」聚合）：
   - `web.sql_injection`（high）、`web.xss`（high）、`web.command_injection`（high）；
   - `web.sensitive_interface`（medium）、`web.webshell`（medium）、`web.scanner_user_agent`（low）。
6. **排查建议**：新增攻击特征分支（是否被 WAF 拦截、是否存在绕过后继续利用）。
7. **配置**：`.env.example` 增加 6 个 `RULE_WEB_*` 开关。
8. **测试隔离**：`database.py` 支持 `LOGINSIGHT_DB_PATH`，新增 `backend/tests/conftest.py` 指向临时 SQLite，测试不再写入 `data/loginsight.db`。
9. **演示日志精简**：`sample_logs/windows/security-rdp.log` 350 → 98 行（10 次 4625 + 1 次 4624，压缩事件块）；`sample_logs/structured/vpn-events.json` 193 → 21 行（改为 NDJSON，一行一事件）。

### 本次修复

- 3 个既有 AI 配置测试此前因项目根 `.env` 中真实配置失败；测试内新增 autouse fixture，使 `_setting` 只读取环境变量，全套测试首次全绿。

### 本次验证

- 后端测试：`43 passed`（新增 2 个；原 3 个失败已修复）。
- 用户脱敏 `access.log` 实测：`log_type=nginx_apache`（0.90）、76 行解析 59 条记录、风险 **high**、15 个可疑事件——敏感路径 ×2、路径遍历 ×2、SQL 注入 ×4 + ×1、XSS ×3、命令注入 ×2、WebShell ×1、敏感管理接口 ×4 + ×2 + ×2、攻击工具 User-Agent ×3×3。
- 精简后演示日志实测：`security-rdp.log`（98 行）→ 10 次失败 + 1 次成功、`rdp_bruteforce_success`（high）与 `privileged_login`；`vpn-events.json`（21 行）→ 20 次失败 + 1 次成功、`auth_bruteforce_success`（high）。
- 前端（Chrome 无头 + Playwright）：详情页展示 15 个事件、风险等级色带、规则编号与证据折叠均正常，控制台零报错。
- 测试隔离验证：运行完整套测试前后 `data/loginsight.db` 记录数不变（473）。

### 下次恢复入口

1. Web 登录爆破候选规则（同一来源 HTTP 401 聚集 + 后续 200 成功）；
2. 跨事件的轻量实体关联（同 IP / 同账户跨日志类型串联）与统一时间线；
3. AI 流式响应与按 Provider 重试；
4. 可选：清理 `data/loginsight.db` 中 473 条历史记录（绝大部分为历史测试数据），需用户确认后执行。
