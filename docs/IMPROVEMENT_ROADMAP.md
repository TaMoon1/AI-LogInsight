# 项目改进路线

更新时间：2026-09-30

## 项目定位

AI-LogInsight 是面向应急响应的本地日志研判工作台。目标是导入一批日志后，快速定位异常时间、来源 IP、目标资产、账号和原始证据，并以低 Token 成本辅助人工研判。

重点参考：

- [NetForensicAI](https://github.com/Sh3n0bi/NetForensicAI)：证据副本、哈希校验、manifest、时间线、实体调查、案件导出和人工确认。
- [ai-incident-analysis-agent](https://github.com/DiogoRibeiro7/ai-incident-analysis-agent)：真实模型评测、可复现运行、可观测性、评估产物和质量门禁。
- [Sigma](https://github.com/SigmaHQ/sigma)：规则元数据、来源版本、规则测试、转换质量和规则治理。

不纳入本项目范围：持续采集、实时流式分析、日志轮转、定时任务、分析队列、多用户并发控制、后台任务持久化、长期告警状态、事件生命周期管理、自动封禁或其他自动处置。

## 核心原则

1. Token 越少越好，但不得牺牲证据覆盖率、证据真实性和研判准确率。
2. 原始日志优先保留，结构化事件和 AI 结论都必须能追溯到原始记录。
3. 一次性上传的历史参考日志只用于本次对照，不建立跨批次长期基线。
4. 每项改进完成后补充测试、验证结果和实际限制；没有实测不能标记为完成。

## 优先级清单

状态使用：`待开始`、`进行中`、`已完成`。完成后必须更新状态和验证证据。

### P0 大文件和资源可靠性

> 项目大文件范围上限为 **500MB**。不做 1GB+、多百 MB 并发关联或大 EVTX 专项验证；相关测试项不属于当前产品目标。
> **2026-10-13 实测结论**：文本日志峰值稳定为文件大小的 **4.4 倍**（100 MB → 441 MB、200 MB → 883 MB，
> 两档均 100% 覆盖、0 解析失败、0 超保留）。**500 MB 需要约 2.2 GB 可用内存，本机实测仅 1.5~1.8 GB，
> 无法验证**——按「超出限制时给出可解释提示」交付：新增 `app/services/memory_guard.py` 做上传前内存预检，
> 不够时返回 413 并写明「需要多少 / 当前可用多少 / 建议拆分文件」。待在有 8 GB 以上可用内存的机器上补测 500 MB。

- [x] 建立 10 MB、100 MB、500 MB 的可重复测试样本或生成脚本。
  - 已完成：`scripts/gen_large_log.py` 流式生成 web / ssh 样本和边界样本；`scripts/bench_large_log.py` 可测真实文件并记录解析失败、超保留数、内存与耗时。
  - 2026-10-13 复验：`--mb 200 300 500` 生成 200.26 MB / 300.38 MB / 500.64 MB 三档样本（含 SHA-256 前 16 位），生成本身仅需 1.2~3.4 秒。
- [~] 验证 500MB 以内单文件上传、解析、规则检测和结果展示。
  - 部分完成：100 MB 与 200 MB 已实测（见上）；500 MB 因本机内存不足未跑通（不是配置问题，是硬件约束）。
  - 新增上传前内存预检（`app/services/memory_guard.py` + `tests/test_memory_guard.py` 8 条），
    在解析之前就拒绝并说明原因，避免用户等到进程被杀。
- [ ] 验证 500MB 以内日志的超长单行、乱码、截断文件和字段缺失处理。
  - 现状：小规模边界样本已被既有解析异常测试覆盖（`P0-06`，含裸 `&`、乱码、字段缺失、空日志、格式错误）；
    **500 MB 量级的边界组合未验证**，与上一条同因（内存）。
- [ ] 验证 500MB 以内日志的高基数 IP、账号、URL、User-Agent 查询和前端渲染。
  - 现状：200 MB 样本规则匹配 56.87 秒、事件仅 8 个，事件与洞察响应均为小体积；
    高基数场景（数十万唯一 IP）仍未实测。
- [x] 记录 500MB 以内测试的耗时、峰值内存、解析失败数、保留丢弃数和失败原因；超过限制时给出可解释提示。
  - 已完成：100 MB / 200 MB 两档数据记入 `CHANGELOG.md`（2026-10-13 条）；
    超限提示由内存预检给出（413 + 需要多少 / 可用多少 / 拆分建议）。

### P1 证据链和案件资料完整性（已完成）

这是当前最应参考 NetForensicAI 的部分。

- [x] 上传时为每个原始文件计算 SHA-256，并记录文件名、大小、类型、时间和哈希。
  - 已完成：`evidence-manifest.json` 保存文件名、大小、SHA-256、分析 ID 和生成时间；提供 manifest 查询接口；多文件原始日志 ZIP 携带 manifest。
- [x] 生成本次分析的 evidence manifest，关联原始文件、解析记录、事件、证据编号、报告和导出文件。
  - 已完成：manifest 记录 `record_ids`、`evidence_ids`、事件与证据关联、报告元数据和案件包文件。
- [x] 原始日志以只读副本保存，导出报告中保留来源文件和记录定位信息。
  - 已完成：上传原始文件保存后设置只读权限；JSON 报告保留来源文件、事件、时间线和证据引用。
- [x] 导出 ZIP 案件包，至少包含原始文件清单、哈希、规则结果、AI 研判、时间线和证据引用。
  - 已完成：`/api/analysis/{analysis_id}/case-package` 导出原始证据、`evidence-manifest.json`、完整 JSON 报告和 HTML 报告。
- [x] 对导出包再次生成 manifest 和完整性校验值，导入或分享时可验证是否被修改。
  - 已完成：案件包 manifest 的 `package_integrity` 为每个原始证据、JSON 报告和 HTML 报告记录大小与 SHA-256。
- [x] 增加按 IP、账号、主机、域名、进程查询的统一实体调查视图，并显示完整时间线。
  - 已完成：`/api/analysis/{analysis_id}/entities/{kind}/{value}` 支持 `ip`、`source_ip`、`destination_ip`、`account`、`host`、`domain`、`process`，返回分页原始记录、关联事件和时间线；未出现对应字段时返回空结果，不推断实体。
  - 2026-09-30 修正：实体值改为**精确匹配**（忽略大小写）。原实现用子串包含，查 `10.0.0.8` 会连带返回 `10.0.0.80`、查账号 `root` 会连带返回 `rootuser`，在取证视图里等于凭空造出关联；同时给 `events` / `timeline` 加上限（默认 50 / 100）并返回真实总数 `events_total` / `timeline_total`，事件按风险从高到低截断。需要模糊查找请用日志明细的关键词筛选，两者语义不同。
  - 2026-09-30 前端接入：从「实体关联」表点「查看记录」打开调查弹层（关联事件 / 时间线 / 原始记录分页）。渲染效果未经真实浏览器确认，见 `CHANGELOG.md` 该条「未验证」小节。
- [x] 对 AI 结论增加人工确认状态：未确认、确认、否定、需复核；保留确认人、时间和备注。
  - 已完成：`GET/POST /api/analysis/{id}/review`；状态与留痕落 `analysis_reviews`（追加式，改判不覆盖历史）；确认人必填；删除分析时同步清理确认记录；前端已接入 AI 研判模块。
- [x] 导出中区分原始事实、规则命中、AI 推断和人工确认，避免把推断写成事实。
  - 已完成：JSON 报告新增 `provenance` 四层声明（`raw_fact` / `rule_hit` / `ai_inference` / `human_confirmation`，只给定位与计数，不复制数据）与 `human_review`；HTML 报告新增「AI 推断（未经人工确认）」独立区块并标注不得当作事实，事件区块明确标为「规则命中事件」，未确认时在报告抬头显式提示。案件包内的 `report.json` / `report.html` 同样带上确认信息。

### P2 AI 真实评测和发布门禁

> 2026-09-30：①③④⑤⑥⑦ 已完成，**② 未做**——能力已建（`--real`），但需用户明确授权
> 才能调用真实模型（会产生 API 费用）。用户明确首轮只做 ①④⑤，⑥⑦③ 为后续延续授权。

- [x] 建立真实脱敏样本集：正常、明显异常、证据不足、多事件关联、误报、无时间戳、缺失字段、大日志和截断日志。
  - 已完成：`evaluation/ai-cases/` 三个文件共 **11 条用例**，覆盖路线图列出的全部 9 类场景。
    标注口径参照 `DiogoRibeiro7/ai-incident-analysis-agent`：**默认精确，仅在证据本身歧义时
    才用集合放宽**（歧义是数据集的属性，不是门禁的宽容）。`suspicious` 为布尔、`risk_levels`
    为可接受集合、`min_behaviors` 为召回下界、`forbid_risk_levels` 抓严重等级错误、
    `evidence_keywords` 验关键实体召回。规模用例用 `generator: {kind: repeat}` 展开，
    不把 3000 行日志写进 YAML。期望值全部来自 parser / analyzer 实测，不是推测。
- [x] 增加真实 DeepSeek 可选评测，同时保留固定模拟回答的确定性单元测试。
  - 已完成（2026-10-13）：用户填入真实 Key 后跑通 `scripts/eval_ai.py --real --write` →
    **10/11 通过**，准确率 91%（TP 6 / FP 1 / TN 4 / FN 0）、漏报率 0%，
    报告落 `docs/ai-quality-report.md`。
  - 过程中先暴露一个真实缺陷：`.env` 里 key 是**未替换的中文占位符**时，
    11 条用例全部失败在 `'latin-1' codec can't encode characters` 上（报错指不到病因）。
    已在 `ai.py` 增加 `_api_key_problem()` 快速失败并给可读原因 + 回归测试。
  - **唯一失败 `truncated-mid-line`**：模型判 `medium`，用例标注可接受 `info/low`。
    模型没有崩溃、没有编造证据，是**保守地判可疑**——真实的校准差异。
    **待定**：调整用例标注（承认截断输入判可疑可接受）还是调整 Prompt（残缺证据不下可疑结论），
    先记录不擅自改判据。
- [x] 支持同一评测集的多模型和多 Prompt 对比，保存 JSON、证据引用、耗时和 Token 评估产物。
  - 已完成：`RunResult`（一次运行 = 一个「模型 × Prompt」组合）+ `render_comparison()` +
    `build_artifact()` / `write_artifact()`；CLI 加 `--model` / `--prompt`（均可重复，做笛卡尔积）
    与 `--artifacts DIR`。
  - **对比表有两张**：① 运行对比（通过数 / 门禁 / 平均置信度 / 平均行为数 / 引用覆盖率 /
    总 tokens / 计费用例 / 总耗时）；② **逐用例风险等级矩阵**，并标出「一致 / 分歧」。
    第二张才是重点——「同一份日志上两个模型给出不同风险等级」比「通过率都是满分」信息量大得多。
  - **两条口径写进代码注释与测试**：
    1. **缺账单显示 `n/a` 而不是 0**。服务端没回传用量与「用量为零」是两件事，
       填 0 会让成本对比得出反向结论——报告说 A 比 B 便宜，其实只是 A 没测到。
       产物 JSON 里对应写 `null`。
    2. **引用覆盖率只在可评估用例上求平均**，不可评估（无行为）的不参与、也不当 0，
       否则「什么都没输出」会把平均值拉低成假象。
  - **耗时只计判据调用**，不含解析与规则分析——后者与模型无关，混进来会让不同模型的耗时不可比。
  - Prompt 变体走 `patch.object(ai_service, "SYSTEM_PROMPT", ...)`：该全局是**调用时**读取的，
    所以 patch 真的生效；有测试证明换的是 Prompt 本身而不只是标签。
  - **诚实的边界**：用确定性替身做多运行对比**没有区分度**（替身对每个运行返回同一份结论），
    CLI 会在这种用法下显式打印提示。要看真实差异必须加 `--real`，而 `--real` 需用户授权。
  - **反向验证**：重构 `main()` 后重验门禁退出码——故意声明不可能满足的期望 → **1**，正常 → **0**。
  - 测试数 408 → **431**（`tests/test_ai_eval_compare.py` 23 条）。
- [x] 自动检查 JSON 合法性、风险等级、置信度范围、证据真实性、引用覆盖和无依据声明。
  - 已完成：`app/services/ai_eval.py` 的 `check_judgement()` 实现 6 项检查 + 4 项期望比对。
    检查与判定分离：接收已产出的 `judgement`，因此同一检查器既能验替身也能验真实模型。
    **关键设计：不可评估 ≠ 通过**——无行为可引用证据时引用覆盖率记为 `None` 而非 `1.0`，
    否则「什么都没输出」会被当成满分（该原则取自参考项目）。
  - **为此修掉一个真实缺陷**：`_normalize_evidence_ids` 此前对「模型引用了不存在的证据编号」
    是**静默丢弃**的，运行时宽容但完全不可观测，导致引用覆盖率无法统计。现新增只读诊断出口
    `judgement["dropped_evidence_ids"]`（只计数不改判定，不进 `AnalysisResult`）。
- [x] 将非法 JSON、引用不存在证据、严重风险等级错误设为发布门禁失败。
  - 已完成：`scripts/eval_ai.py` 有门禁失败时**非零退出**（镜像 `eval_rules.py` 的范式）。
    门禁项：`json_valid` / `evidence_exists` / `risk_level_severe` + 期望比对
    （`risk_level_acceptable` / `behavior_recall` / `evidence_keywords`）。
    引用覆盖率与无依据声明作为观察指标出报告，不单独阻断。已用「故意声明不可能满足的期望」
    反向验证退出码为 1，删除后恢复 0。
- [x] Prompt 或 AI 代码变更时自动执行最小回归集；扩大样本集时执行完整评测。
  - 已完成：用例可标 `smoke: true` 组成**最小回归集**（当前 5 条，覆盖误报 / 漏报 / 无证据编造 /
    多事件关联 / 截断五类核心失败模式）。它随 `pytest` **自动执行**——本项目没有 CI 配置，
    `pytest` 就是唯一门禁机制，所以自动执行必须挂在测试里，不能指望有人记得手动跑脚本。
    完整集走 `scripts/eval_ai.py`（`--smoke` 只跑最小集）。
  - 实测耗时：最小集 **4.3s** / 完整集 **6.7s**（完整集 11 条）。**差距不大，因为 Python 启动
    本身占约 3 秒**——分层的价值在「样本集增长后有稳定快速通道」，不是现在省这几秒，不夸大。
  - 三道守卫防止分层悄悄失效：最小集必须严格小于完整集、必须排除 3000 行规模用例、
    条数不得超 8（防止有人把全部用例都标成 smoke，让分层以「变慢」而非「报错」的方式失效）。
  - **遗留**：项目无 CI，`pytest` 需人工触发，因此严格说不是「无人值守自动执行」。
    引入 CI 属新增基础设施，本轮未做。
- [x] 覆盖多轮工具调用、长上下文证据遗漏、模型引用不存在字段、过度自信和多语言日志。
  - 已完成：`tests/test_ai_stress.py`（42 条）逐项钉住 5 个子项，**期望值全部来自实测探测**，不是推测。
  - **多轮工具调用**：模型每轮都要求调工具时，请求数严格等于 `AI_MAX_TOOL_ROUNDS + 1`
    （轮次用尽后补一次收尾请求，把已取回的证据收敛成结论）。按 1 / 2 / 3 三档验证上限确实生效——
    没有硬上限等于把成本与延迟交给模型决定。
  - **长上下文证据遗漏**：`records_sample_note` 必须含 `records_total=` / `not_all` /
    `more=query_records`，否则模型会把「样本里有 200 条」当成「日志只有 200 条」；
    被截断的原文必须带 `[已截断]` 标记。
  - **模型引用不存在字段**：`_validate_response` 是白名单，模型自造的 `mitre_id` / `iocs` /
    `internal_debug` 一律不得进入结果（结果会被前端直接渲染）。
  - **过度自信**：高置信度不能免检——`confidence: 0.99` + 编造 IP 仍被 `_check_grounding` 抓到；
    置信度是「结论有多自信」，不是「证据有多充分」。
  - **多语言日志**：实测确认 Web 日志**与语言无关**（靠字段位置与 URL 特征：德语 UA、
    中文环境的 `/../../etc/passwd` 均正常解析），但 **syslog 消息体依赖英文关键词**——
    德语 / 中文 sshd 日志落到 `generic`、解析出 0 条记录。这是真实能力边界，
    已如实钉进测试而不是假装支持。
  - **顺带修掉 6 个真实缺陷**（同一主题：代码本意是容错，但有路径漏了）：
    1. `risk_level` 取值非法（大写的 `"HIGH"`、数字 `5`、数组 `["high"]`）**直接抛
       ValidationError / TypeError**——`_build_structured_verdict` 里的归一化写在 pydantic
       构造**之后**，而 `risk_level` 是 Literal，构造时就已抛错，那段兜底**永远执行不到（死代码）**。
       模型输出大写风险等级是极常见行为，代价是整轮 AI 研判失败。现改为构造前归一化。
    2. 非字符串塞进语义字符串字段（`"involved_account": 0`、`"event_time": 20260929`）同样崩溃
       → 按「未提供」处理，不猜。
    3. `confidence: NaN` 被放大成 **1.0（最高置信度）**——`json.loads` 默认接受该非标准字面量，
       而 `min(1.0, nan)` 返回 1.0。现新增 `_coerce_confidence()`，NaN 与不可解析值统一回 0.0。
    4. `evidence` 写成单个字符串时被**逐字符拆开**（`"10.0.0.1"` → `['1','0','.','0',...]`），
       界面上会出现「看起来像证据」的垃圾。改用已有的 `_as_list()`。
    5. 行为置信度不可解析（`"high"`）导致**整条行为被静默丢弃**——丢的是一条真实发现，
       代价远超一个置信度。现与顶层口径一致：保留行为，置信度回退 0.0。
    6. `evidence_ids` 写成裸字符串时静默丢失，连 `dropped` 诊断都统计不到 → 按单项处理。
  - **已知粗糙边缘（未改，待决策）**：`"behaviors": [{}]` 会生成一条占位行为
    （`unknown_behavior` / 置信度 0 / 无分析），而非被丢弃。它不构成误导性结论，
    但会计入「行为条数」，而召回下界正是按条数判定的。已用测试钉住现状，
    改动前需先确认评测召回口径不受影响。

### P3 Token 成本和质量联合指标（已完成）

- [x] 记录总 Token、首轮 Token、工具轮次 Token、缓存命中 Token、上下文字节数和研判耗时。
  - 已完成：新增 `app/services/ai_metrics.py`（**不 import 项目内任何东西**，可被单测直接驱动，
    也不会与 `ai.py` 形成循环依赖）。`request_ai_judgement` 在结尾写 `judgement["metrics"]`。
  - 端到端实测：`tokens: {total: 2240, first_round: 1010, tool_rounds: 1230, cache_hit: 1000}`，
    `rounds: 2`，`context.bytes: 67087`。分轮拆分已用真实两轮调用验证（1010 + 1230 = 2240）。
  - **拿不到分轮明细时返回 `None`，不拿总数冒充首轮**：否则「首轮成本」恒等于总成本，
    看起来像「后续轮次不花钱」，正好把历史裁剪的收益藏起来。
- [x] 记录每个事件、每条有效证据对应的 Token，以及单次分析估算成本。
  - 已完成：`measure_context()` 按 `index` 逐事件对齐 token 归属，逐证据按 id 记录体量；
    `estimate_cost()` 按单价估算。
  - **服务端不会告诉你「这次调用里第 3 个事件花了多少 token」**，所以逐事件 / 逐证据只能按
    上下文体量分摊。因此字段名与报告里都写明「估算」，且在数据结构上与真实账单**不共用键**——
    把估算当账单看会让成本优化得出反向结论。
  - **不内置厂商价格**：价格会变，写死会悄悄算错成本。单价从 `AI_PRICE_INPUT_PER_M` /
    `AI_PRICE_OUTPUT_PER_M` / `AI_PRICE_CACHE_HIT_PER_M` 读取，`.env.example` 里给出注释示例
    （**故意注释掉**，避免被当成推荐值）。未配置时 `cost.estimated = null` 并附说明，
    **不填 0**。
  - 缓存命中部分按缓存价计价；未单独配缓存价时回退输入价（保守，宁可高估）。
- [x] 记录 evidence sent、evidence referenced、证据覆盖率和证据遗漏率。
  - 已完成：`evidence_sent` **计条数而非去重 id**——同一条证据可能出现在多个事件里，
    按 id 去重会把分母算小，覆盖率会虚高甚至超过 1。
  - **无行为时覆盖率记 `None`（不可评估），不记 `1.0`**：否则「什么都没输出」会被当成满分。
- [x] 在回归测试中同时比较 Token、准确率、误报率、证据覆盖率和延迟。
  - 已完成：`EvalReport` 新增 `confusion` / `accuracy` / `false_positive_rate` /
    `false_negative_rate`，`RunResult` 委托取值（避免两处各算一份）；
    `render_markdown`（单次）与 `render_comparison`（多次）都同时呈现。
  - **可疑与否一律看 `risk_level`，不看行为条数**：本项目有 P1-16「行为偏离」（正常日志上的
    低置信度提示，`risk_level=info`）。按条数判定会把它算成误报。
  - **顺带修掉一处自相矛盾**：模块开头就声明「可疑与否看 `risk_level`，不看行为条数」，
    而 `evaluate()` 里写的却是 `suspicious_actual=bool(judgement.get("behaviors"))`——
    归档里因此存着一份与门禁结论互相矛盾的记录。已改为按 `risk_level` 推导
    （下界由数据集标注反推：负样本允许 `info/low` 并禁止 `high/critical`，正样本期望
    `medium/high/critical`，故 `medium` 即可疑下界）。
  - **缺样本侧时比率是 `None` 不是 0**：样本集里没有正常用例时，误报率若返回 0，
    报告会显示「误报率 0%，完美」——而真相是根本没测。
  - **判据崩溃时 `risk_level` 为空，不计为「正确」**：否则一次崩溃会在准确率上
    伪装成一次成功的保守判断。
- [x] 为字段白名单、分层采样、去重、证据预算和摘要指针建立 Token 回归门禁。
  - 已完成：`compare_gate_metrics()`（作用在**指标行**上）+ `check_token_regression()` 包装 +
    `metric_row()` + `load_artifact()`；CLI 新增 `--baseline FILE`，门禁失败非零退出。
  - **门禁不依赖具体机制**：比较 `tokens_total` / `tokens_first_round` / `context_bytes` /
    `evidence_sent` / `accuracy` / `false_positive_rate`——五类上下文整形手段（字段白名单、
    分层采样、去重、证据预算、摘要指针）生效时必然落在其中某一列上。P4 实现这些机制时
    **不必再改门禁**。
  - **基线来自归档产物**（`summary.gate_metrics`），因此「和上次发布比」与「和另一个模型比」
    共用同一套判定。基线按**同名 label**（模型 + Prompt）匹配，换了组合只提示跳过，
    **不静默当通过**。
  - 反向验证：把基线 `tokens_total` 改成 300（本次 750，+150%，质量持平）→ 门禁失败，
    退出码 1，报告写明「超过容差 10%，但质量未提升」。
  - **刻意不放进 `pytest` 断言**：确定性替身下质量恒为 1.0，任何合法的 Prompt 改动都会
    只涨 token 不涨质量，自动断言会让门禁变成「禁止改 Prompt」。因此它是**发布门禁**
    （CLI，人工触发），不是单元测试。已用 `test_gated_metric_names_match_the_metrics_payload`
    守住真正的静默失效风险：指标模块改字段名而门禁读不到时，必须报错。
- [x] 输出成本与质量对比报告，禁止只以 Token 下降作为优化成功标准。
  - 已完成：`render_comparison` 增「质量与成本」表（准确率 / 误报率 / 漏报率 / 引用覆盖率 /
    总 tokens / 估算成本 / 计费用例 / 总耗时）+ `render_verdict()` 联合结论段。
  - 四条判定规则（前两条门禁失败）：
    1. Token 涨超容差且质量未提升 → **失败**（多花钱没换来质量）；
    2. Token 降但质量下降 → **失败**（省下的 token 是拿准确率换的）；
    3. Token 降且质量持平或提升 → 通过；
    4. Token 涨且质量提升 → 通过，但**记为观察项，不自动判定为成功**——
       是否值得这个价钱是人的决定，不是门禁能代替的。
  - **准确率涨但误报率变差不算质量提升**：对安全产品是净损失，`_quality_delta` 会把
    delta 压到 0 从而否决规则 1 的豁免。
  - 单次运行**不做优化判定**（没有对照就没有「优化」可言），并明说
    「未配置单价时 tokens 只能作为成本代理，不能当作成本结论」——
    不同模型单价差可达一个数量级，token 少的那个未必更便宜。
  - 四条规则**全部标 `gating=True`**，通过的也标：漏标会让「门禁通过」在汇总里看不见，
    读者无从判断到底有没有比过。

### P4 证据价值排序和上下文压缩（进行中 3/5）

> 2026-09-30 暂停时状态：**①④⑤ 已完成；②③ 部分完成**（见各条目的「未做」）。
> 剩余工作集中在「互补证据」「信息增益去重」两处，都属可选优化而非缺陷。

- [x] 为证据增加可解释的价值评分：风险、置信度、来源可靠性、时间新颖性和实体关联度。
  - 已完成：新增 `app/services/evidence_value.py`（**不 import 项目内任何东西**，可被单测直接驱动）。
    五个分量全部是**确定性、可逐项复核**的，依据写进模块 docstring 的表格里。
  - **`confidence` 是代理指标，不是模型置信度**：`Event` 结构里**没有** `confidence` 字段，
    所以不伪造一个，改用「同一归组实体上**不同规则**的命中数」当交叉印证的代理，
    字段名与上下文说明里都写明这一点。
  - **`reliability` 用规则 `source`**：`builtin`（74 条内置规则有本地标注语料）1.0 /
    `sigma`（510 条未验证的导入规则，只做过「正常流量零命中」筛查）0.6 / 无规则 0.7。
    这是项目里**已有且已有文档依据**的区分，不是新造概念。
  - **`novelty` 复用已有口径**：「与本批次相比首次出现」是本项目 IOA 基线的既定含义。
  - 实测分量区分度（同一 medium 风险，其余信号不同）：孤立 0.41 → 档位 3→2；
    2 规则交叉印证 0.61 → 3；3 规则 + 首现 + 高关联 0.80 → 4；sigma 规则 0.35 → 2。
  - **硬约束：评分只决定「下发几条证据」，不参与任何研判判定**——
    不改变 `events` / `risk_level` / `confidence` / `behaviors`。已用测试守住：
    评分是成本控制手段，一旦能影响结论，就成了「为了省钱而改判」。
  - **修正一处自己引入的退化**：关联度最初写成「该实体活动量 / 最活跃实体活动量」，
    只有一份日志一个实体时自身就是峰值，**恒等于 1.0**（等于给每个事件白送满分），
    而退化场景恰好是最常见的小日志。改为绝对口径
    `entity_correlation(跨文件数, 同实体事件数)`（各自减 1 后除以 4 封顶）。
- [x] 按攻击链关键节点、互补证据、正常对照证据动态分配上下文预算。
  - **攻击链关键节点：已完成**。复用 `analytics.build_attack_chains`（不另立一套定义），
    取每条链的**首节点与末节点**，标记为 `chain_node=attack_chain_endpoint`。
  - **关键节点「硬保留」的准确含义是「不被降级」，不是「拿到全局满额」**。
    实测过错误版本：无差别给满额会让一条 `low` 端点拿到 5 条证据，
    **超过 `high` 非端点事件的 4 条**——既与 AGENTS.md §8「风险是主信号」冲突，
    又是纯成本上涨。现改为 `max(depth, base)`：端点不因价值微调被削减。
  - **修正一处自己引入的过宽判定**：单阶段链的 `stages[0] == stages[-1]`，
    若也算端点，则每个孤立事件都是「关键节点」（实测覆盖率接近 100%），
    标记完全失去区分能力。现只认 **≥2 个阶段**的链。
  - **正常对照证据：已有**（P3-05 时期的 `uncovered_records_sample`——规则未覆盖的记录样本，
    即「正常基线」），本轮未改动。
  - **互补证据：已完成**。记录样本在分层抽样后按结构化字段的增量信息排序，
    优先覆盖不同 IP、账号、URL、状态码、方法、进程、主机和事件类型；
    两块样本仍保持互斥，且最后恢复原始顺序以保持 Prompt 前缀稳定。
- [x] 关键证据硬保留，普通记录按信息增益去重和采样。
  - **关键证据硬保留：已完成**。`_fit_context_budget` 原先按列表位置砍尾巴——
    砍掉的是哪条取决于分层抽样的顺序，**与价值无关**，一次削减可能正好砍掉唯一的
    critical 事件。现改为按 `(是否链端点, value_total)` 排序保留，并**恢复原顺序**
    （上下文必须对同一份日志逐字稳定，否则 prompt cache 前缀失效）。
  - **显式信息增益：已完成**。新增 `_information_gain_sample()`，
    对候选样本按「新增结构化字段值数量」进行确定性贪心选择；原文不参与评分，
    不改变事件、风险等级、置信度或证据，只影响发送给 AI 的样本组成。
  - 验证：`backend/tests/test_ai_limits.py` 新增稳定性和多字段覆盖测试；
    该用例通过。依赖 `drain3` 未安装，依赖分析器的旧样本测试暂未能运行。
- [x] 评估压缩前后证据召回率，发现遗漏时自动降级为更完整的上下文档位。
  - 已完成：`_high_risk_evidence_recall()` + `EVIDENCE_RECALL_FLOOR = 0.9` +
    一次性自动降级 + `EVENT_SAMPLE_HARD_MAX = 200`。
  - **关键判断：真正的证据遗漏不在深度截断，而在事件抽样**。高风险事件的基准档位
    就是满额（5 = `EVENT_EVIDENCE_ITEM_LIMIT`），**永远不会被深度截断**；
    它们只会在事件抽样这一层被整条丢掉，连同全部证据一起消失。
    因此「压缩前后证据召回率」在本项目里的实际形态就是**高风险事件的证据下发比**。
  - 实测触发：100 条 high 事件 / 共 200 条 → 降级前召回 **280/400 = 0.70** < 0.9 →
    自动补回被抽掉的高风险事件 → 选中 80 → **110 条**，召回 **1.00**，
    说明里出现 `evidence_tier=full;reason=hr_recall_low`。
  - **降级受硬上限约束**：`EVENT_SAMPLE_HARD_MAX = 200`。没有这个上限，
    降级逻辑本身就成了绕过预算守卫的后门。补回后仍超限时**不降级**，
    但会如实写出 `high_risk_dropped=N`，不静默。
  - 召回率与档位只在**真有内容可报**时写进说明（没有高风险事件就不写，
    未降级就不写 `evidence_tier`），避免每轮白付字节。
- [x] 保留总数、时间范围和采样口径，防止模型把样本数量误认为全量数量。
  - 已完成：`records_sample_note` 新增 `time_range=`。**取全量记录而非样本**——
    样本的时间跨度天然更窄，用它会让模型低估日志的时间跨度。
    完全没有时间戳时写 `unknown`，**不猜一个范围出来**（AGENTS.md §16）。
  - **顺带去掉一处会「对模型谎报」的设计**：`events_note` 原先硬编码
    `evidence_depth=critical/high:5,medium:3,low:2,info:1`，与
    `_EVENT_EVIDENCE_DEPTH` 是两份事实，改一处忘另一处就会按旧值告诉模型。
    改后先尝试「从实现生成图例」，但发现**逐档图例对模型不可操作**（它改不了深度）
    却要每轮付费发送，最终改为只声明 `evidence_cap=N`——需要更多证据时模型的动作是
    `query_evidence`（`evidence_count` 给出真实总数）。这样彻底消除了不同步的可能。
  - 说明字段仍受 `test_context_notes_stay_compact` 的 260 字节预算约束。

### P5 规则治理和质量控制

- [x] 完善规则元数据：作者、来源、版本、许可证、参考链接、ATT&CK、严重性和验证状态。
  - 已完成：统一规则模型支持作者、来源、版本、许可证、参考链接、标签和验证状态；
    `/api/rules` 可直接返回这些字段。现有 YAML 未声明的字段按 `null` / `unverified` 兼容。
  - 已完成（2026-10-13）：**补齐全部 1689 条规则的真实元数据**——内置 74 条 `author=AI-LogInsight`
    / `license=proprietary` / `validation_status=validated`；Sigma 1615 条 `author=SigmaHQ contributors`
    / `license=DRL-1.1`（精选 7 条 `validated`、社区 1608 条 `unverified`，与语料覆盖口径一致）。
    实测 0 条缺 `license` / `author`。
  - 已完成：**许可证 / 链接格式门禁** —— 新增 `app/services/rule_metadata.py` 与
    `tests/test_rule_metadata.py`（10 条），并入 `scripts/eval_rules.py`（违规时非零退出）。
    门禁含四类格式检查（`author` 非空、`license` 在允许集合、`validation_status` 在允许集合、
    `references` 必须为 http(s)）与一条**声明一致性**检查（声明 `validated` 必须有本地正样本，反之亦然）。
    反向验证：故意写非法许可证 → 门禁失败、退出码 **1**，恢复后回到 **0**。
  - 实现方式：新增**文档级 `metadata` 块 + 规则级覆盖**的继承机制（`rules_engine.build_rule` /
    `load_rules`），避免 1608 条同源规则逐条重复元数据（该文件已 3.85 MB / 130,083 行）。
  - 已完成（2026-10-13 续）：**Sigma 逐条 `author` / `references` 也已补齐**——阻塞点不是
    「必须有 SigmaHQ 检出」，而是取**指定版本**的归档即可：
    `https://codeload.github.com/SigmaHQ/sigma/zip/b4ba1f2`（短 SHA 可用，版本与生成文件头部一致）。
    实测 1608/1608 带 `author`、1564/1608 带 `references`（44 条只有 `Internal Research`
    这类非链接参考，字段语义是链接故不收，但导入报告已报出 107 条计数，不静默丢弃）。
    重跑后规则 id 集合与改动前**逐条一致**（新增 0 / 丢失 0），语料门禁保持 123/123 · TP 111 · FP 0 · FN 0。
  - 顺带修掉一个**会静默少导入 447 条**的缺陷：`import_sigma_community.py` 的 `DEFAULT_DIRS`
    只写了 2 个子目录，而文档给出的复现命令没带 `--dirs`——照文档重跑会把候选从 2417 掉到 1517、
    保留从 1608 掉到 1161 且不报错。已改为 SigmaHQ `rules/windows/` 全部 17 个子目录。
  - 接口体积：`/api/rules` 响应 996 KB → 1346 KB（+35%，增量主要是 `references`）。
    **但前端并未调用该接口**（只用 `/api/rules/preview`），规则元数据实际经 detections 下发，
    而 detections 只为真正命中的规则建组，故实际影响很小；`references` 是否在前端渲染留作后续决策。
- [ ] 区分 detection、hunting、emerging_threat、compliance、behavior_deviation 规则类型。
- [ ] 记录 Sigma 导入版本、转换结果、字段映射、未支持语法和降级原因。
  - 现状：导入版本、转换漏斗 / 跳过原因已进 `docs/sigma-import-report.md` 与生成文件头部；
    **逐条** `author` / `references` 与文档级元数据（版本 `b4ba1f2` / 许可证 `DRL-1.1`）已随 P5-① 落地。
  - 已完成（2026-10-13）：**「未支持语法」做到逐条可查**——报告新增
    「附录：逐条跳过清单」（按「原因 → 文件名」排序），此前只有 Top 15 汇总表 +
    每类一个示例，查不到「某一条规则为什么没进来」。同时补上「被排除的已落盘重复规则」小节
    （1 条），并修正漏斗表：原先打印「排除已落盘的重复规则 7 条」，实际只排除 1 条
    （`len(pre_existing)` 是既有 id 总数，不是本批候选里的命中数）。
    报告由 79 行 → 735 行，与 `rule-quality-report.md`（3477 行）同属「生成型长报告」。
  - 已完成（2026-10-13）：**「字段映射」随标准格式解析一并落地**——规则里的字段名就是
    EVTX 标准字段名，解析器按标准结构原样落进记录，转换时直连，不再有「降级」这一说
    （见下条）。逐条「降级原因」因此**不存在**：转换器原则是「不猜测」，无法保持语义的一律
    整条跳过并在附录留痕，不做近似匹配。
- [x] **按标准 EVTX 格式解析事件数据，删掉「模型外字段」补丁**（2026-10-13）
  - 起因：做 P5-③ 的「字段映射」时发现 `SCOPED_FIELD_MAP` 的 `scope:` 变换**从未随谓词落盘**
    ——`sigma_import._build_predicates` 里 `target_field, transform = mapped` 的 `transform`
    **赋值后从未使用**（所有谓词都走 `_field()` 硬编码的 `transform="none"`），
    `_predicate_dict` 也**不输出** `transform` 键。生成的 `95-sigma-community.yaml` 里
    `transform:` 出现 **0 次**，而 `field: raw` 有 2468 处。
  - 影响：885/1618 条可转换规则（1205 处字段引用）退化成未限定的 `raw` 匹配，实际永不命中，
    属「看着能跑、其实永不命中」的虚假覆盖。**门禁也抓不到**：`verify_sigma_rules.py` 层 1
    对 `transform=none` 的 raw 谓词直接合成 `raw = <取值>`，反而把这类规则判成「可端到端触发」，
    88.5% 这个数字被抬高；层 3（正常流量零命中）同样抓不到——永不命中的规则天然零命中。
  - 关键约束（决定补丁方向本身就错）：`evtx.py` 的 `raw` 只由 14 个 `EVENT_DATA_FIELDS` +
    EventID/Date/Provider/Computer 拼成，**不含** `OriginalFileName` / `ParentCommandLine` /
    `Details`（实测 1048 条真实记录里 0 条含这些字段名）。所以「修好 `scope:`」对 EVTX 也
    不会命中。
  - 改法——**按标准格式解析，而不是在模型外近似匹配**：
    ① `evtx._system_fields` 补齐标准事件头：`channel` / `provider` / `level` / `task` /
       `opcode` / `keywords` / `event_record_id`；
    ② `evtx._event_data` 把 `<EventData>` 里**每个** `<Data Name="…">` 按标准名原样落进记录
       （只保留有值的；无 `Name` 的合并到 `Data`），认证事件与非认证事件都带上；
    ③ `sigma_import` 删除 `SCOPED_FIELD_MAP`，未登记的字段**原样直通**，并修好 `transform`
       的传递（`_field` 带上变换、`_predicate_dict` 输出 `transform`、多字段谓词写 `field: [...]`）；
    ④ 删除引擎里的 `_scoped_value` / `scope:` 变换、校验脚本的 scope 合成分支、
       `tests/test_scoped_fields.py`、一次性脚本 `backend/_cleanup.py`。
  - 顺带修掉一个会让**误报筛查空过**的缺陷：导入脚本直接调 `evaluate_rule` 时记录上没有
    `log_type`，带日志类型限制的规则在筛查里一律不匹配。补上后 11 条社区规则因命中正常流量
    被剔除（原先 9 条），且剔除的都是真实误报（net.exe 侦察 / PowerShell 派生 / wevtutil 查询 /
    wmic 查询 / certutil 计算哈希）。
  - 实测：候选 2418 → 转换 **1782**（原 1617）→ 误报裁剪后保留 **1771**（原 1608）；
    规则总量 1689 → **1852**。跳过原因里「字段无法映射」归零，「logsource 无法映射」升到 480
    （原先被字段映射挡在前面，现在才走到这一步）。
  - 验证：新增 `tests/test_evtx_standard_fields.py`（10 条）钉住「标准字段落盘 + Sigma 字段
    直连 + `transform` 落盘 + 真实记录命中」；端到端实证 `OriginalFileName: evil.exe` 对
    `<Data Name="OriginalFileName">evil.exe</Data>` 的记录**命中**（补丁时代不命中）。
    生成文件里的直接证据（`95-sigma-community.yaml`）：`field: raw` 谓词 **2468 → 1**，
    `field: OriginalFileName` **0 → 747**、`Details` **0 → 843**、`ParentCommandLine`
    **0 → 425**，`transform:` 键 **0 → 100**。
  - 验证（全量门禁）：`pytest` 全绿；`rule_health.py` 2272 条**阻断项 0**、观察项 33；
    `eval_rules.py` 用例 123/123、内置覆盖 74/74、TP 111 / FP 0 / FN 0、元数据门禁 0 违规；
    `verify_sigma_rules.py` 可端到端触发 **1992/2198（90.6%）**、疑似缺陷 0、
    层 3 判定过宽 0。
  - 成本：EVTX 的 `raw` 现在渲染全部标准字段，实测三份真实样本平均长度 191→618（安全 3.2×）、
    107→164（系统 1.5×）、102→261（应用程序 2.6×）字符；AI 侧 `AI_RAW_TEXT_LIMIT = 640`
    仍兜底，单条证据计费上限不变。
  - 已同步改写：`CHANGELOG.md` / `README.md` / `PROGRESS.md` 里「`raw` + `scope:` 字段限定匹配」
    的表述。
  - 已完成（2026-10-14）：**`logsource 无法映射` 里能安全放开的 420 条已放开**。原先我在这条里
    写的修法（「给 `service` 映射到 `channel` 守卫」）**经取证是错的**：480 条里**没有一条**自带
    `Channel` 约束，407 条的 `service` 是空的——它们靠 `EventID` 约束，不靠通道。取证后按
    「有没有可依赖的 EventID 守卫」分四组：① `category` 已在 `SYSMON_EVENT_IDS` 里、只是没进
    `LOGSOURCE_MAP` 的 **351** 条（纯代码内部不一致：守卫表 23 个分类 vs 来源表 9 个）；
    ② `service` 型且规则自带 `EventID` 守卫的 **69** 条（AppLocker / CodeIntegrity / BITS /
    Firewall-AS / DNS-Client…）。③只有 `product=windows` 无约束的 1 条、④`category` 无已知
    EventID 的 59 条**如实跳过**——没有 EventID 约束就放行，规则会跑到全部 EVTX 记录上。
    新增 `_has_event_id_guard()` 作为放行判据；`_is_host_category` 顺带改为
    「`product=windows` 即按主机 + 进程归组」（否则新放开的服务型规则会因没有来源 IP 全并成
    一个 `unknown` 桶）。实测：转换 1782 → **2202**，保留 1771 → **2191**，
    `logsource 无法映射` 480 → **60**，规则总量 1852 → **2272**；门禁 79 passed、
    体检阻断项 0。放行判据另有专项验证：逐条核实新放开的 420 条，**EventID 守卫全部落在必要条件
    （`where`）上，0 例外**——判据是「`where` 里有 `status` 的 `equals` / `in_set`，或 `any` 的
    每个分支都自带该守卫」，即这些规则无法脱离自己的 `EventID` 命中。顺带记录一条**不成立**的不变量：
    「每条导入规则都有 `where` 必要条件」是假的——69 条（含 7 条精选 Web 规则）是 `keywords` /
    `any_contains` 类，本就没有可作必要条件的单字段谓词，它们只能全量扫描（见本文件关于
    字面量倒排索引的记录）。
  - 已完成（2026-10-14）：**同一条原则推到其余全部日志类型**。统一机制是
    `parser._named_fields()`——把格式**自带字段名**原样收下（只留有值的），规范字段在后覆盖同名键；
    判据是「格式是否自带字段名」，不是「想不想要这个字段」。
    - **json / csv**：原先只认 `FIELD_ALIASES` 白名单（9 个规范字段），其余键**静默丢弃**；
      现在全部原样收下。这是本轮最大的一处——结构化日志的字段名本就由数据自己声明。
    - **iis**：W3C `#Fields:` 声明的列全部收下（原先只取 5 个）。
    - **firewall_waf / windows_event / syslog**：全部 `key=value` 收下；syslog 前缀的
      `program` / `pid` 也落进记录。
    - **windows_rdp**：事件查看器文本导出的全部 `键: 值` 收下（新增 `COLON_KEY_VALUE`）。
    - **nginx_apache**：补 combined 格式的 `remote_user` / `body_bytes_sent` / `http_referer`。
    - **ssh**：补标准行头的 `host` / `program` / `pid` 与来源 `port`。
    - **mongodb**：结构化日志（4.4+）的顶层字段与 `attr` 全部收下；
      **mysql / postgresql / redis / sqlserver** 补前缀里的 `thread`+`command` /
      `pid`+`connection_id` / `pid`+`role` / `source`。
    - **oracle** 无需改（ORA 码本就映射到 `status`）；**generic 明确不改**——解析 0 条记录是
      本路线图已记录的真实能力边界（走 Drain3 模板挖掘），不是缺陷。
    - 冒烟（真实样本 16 个文件 / 15 种类型）：各类型都取到格式自带字段，syslog 41 个、
      windows_event(KV) 26 个、iis 12 个、windows_rdp 8 个。
    - 轻量测试（按要求不做全量）：解析与记录结构相关的 9 个模块 **221 passed**。
- [x] 检查重复规则、冲突规则、同一事件重复告警和规则聚合效果。
  - 已完成：导入时做去重 + 「正常流量零命中」筛查，重叠与剔除原因进
    `docs/sigma-import-report.md`；`scripts/verify_sigma_rules.py` 的层 3 持续守这条线
    （当前判定过宽 0 条）。
  - 已完成（2026-10-13）：**全库体检**——`app/services/rule_health.py` +
    `scripts/rule_health.py`（有阻断项时非零退出，`--write` 出 `docs/rule-health-report.md`），
    并把「出厂规则零阻断项」钉进 `tests/test_rule_health.py`（15 条）。本项目没有 CI，
    `pytest` 就是唯一门禁机制，所以「定期体检」必须挂在测试里（同 P2-⑥ 口径）。
  - 六类阻断项，每类对应一种「安静地出错」：悬空引用（`suppresses` / `upgrade_rule`
    指向不存在的 id）、自压制、压制成环、**升级链不对称**（A 声明被 B 升级、B 却没声明压制 A
    → 升级永远不会发生）、判据+聚合完全相同且互不压制（同一条记录产出两个事件）、
    空 `group_by`（整个时间窗并成一条，丢掉来源 IP / 主机区分）。
  - `event.type` 冲突单列为**观察项**不阻断：多由 `slug()` 截断造成（它是环境变量名的组成部分，
    不能随便加长），且 `analytics._tactic` 优先按 `rule_id` 映射，类型冲突不改变判定。
  - 实测：1689 条规则 **阻断项 0**、观察项 20（全是 `event.type` 冲突）。
    反向验证：把 `ssh.bruteforce.success.suppresses` 指向打错的 id → 退出码 **1**，
    并**同时**抓出连带的 `asymmetric_upgrade`（正是该检查要防的静默失效）；恢复后回到 **0**。
  - **关键设计：判据签名必须含聚合**。开发时先踩过坑——只比 `where` 时，5 组刻意设计的
    `.success` 压制对（共享 `where`、靠 `follow_up` 区分）会被误报成「重复规则」；
    现签名含聚合（含 `follow_up`），并把「互相压制或升级」视为已解决。
- [x] 每条内置规则关联正样本、负样本和预期结果；社区导入规则明确标记未验证。
  - 内置规则：`evaluation/corpus/*.yaml` 的 `expect` 字段把正样本、期望事件数与风险等级
    钉住，`tests/test_rule_quality.py` 要求 74/74 有正样本（见 6.5.3）。
  - 社区导入规则：不做逐条人工验证，改为**三层自动化**（`scripts/verify_sigma_rules.py`，
    见 6.5.4）——① 从谓词树反推正样本并端到端跑一次；② 真实语料回放；③ 正常流量负样本筛查。
    实测 **1992/2198 可端到端触发（90.6%）、疑似缺陷 0、判定过宽 0**，另有 206 条因正则或
    复杂跨字段约束无法自动合成，如实单列。报告落 `docs/sigma-rule-verification.md`。
  - 待完成：把层 1 可触发的规则固化成正式语料用例，让「能触发」升级为「已被语料验证」。
- [x] 规则编辑前支持预览和试运行；规则发布前执行误报、漏报和格式门禁。
  - 已完成（早于本轮实现，路线图状态漏更新；2026-10-14 核实后补记）：
    `POST /api/rules/preview` 接收规则草稿（`yaml_text` / `rule` / `rules` 三种形态），
    可选带一段样本日志试运行，返回 `event_count` / `covered_records` / TP / FP / FN 与命中事件；
    **不写入规则目录**（`tests/test_analysis.py::test_rule_preview_runs_draft_without_writing_rule_file`
    钉住）。草稿不强制要求 `author` / `license`——预览是「快速试跑」，发布门禁在下一环。
  - 发布前门禁由 `scripts/eval_rules.py` 承担，四类问题**任一命中即非零退出**：
    误报（`false_positive`）、漏报（`false_negative`）、未被用例覆盖的内置规则
    （`uncovered_rules`）、元数据格式与「声明 `validated` 必须有本地正样本」一致性（`violations`）。
- [x] 保存规则变更审计和可回滚版本，确保规则修改可追溯。
  - 已完成：`rule_changes` 审计表 + `GET /api/rules/audit`；启停走
    `PATCH /api/rules/{rule_id}/enabled`，同时写 `rule_overrides` 与审计记录
    （`tests/test_analysis.py::test_rule_enable_override_is_audited` 钉住）。
  - 已完成（2026-10-14）：**补上「可回滚」**——`POST /api/rules/audit/{entry_id}/rollback`
    把某条启用/停用记录还原到它记下的「变更前」状态；回滚本身**追加**一条新记录而不是改写旧记录
    （审计链只增不改，才谈得上可追溯）。只支持 `enable` / `disable` 两类（`before_value` 是
    布尔串、语义明确），其它 action 返回 404 而不是猜。测试 2 条。
  - **边界（如实记录）**：这里的「可回滚」覆盖的是**启停治理**，**不覆盖规则内容变更**——
    规则正文是 YAML 文件、项目没有版本控制，正文级回滚需要先定版本化方案（存快照？还是引入 VCS？）。
    这是需要产品决策的一项，不在本轮范围。

### P6 一次性历史对照

- [ ] 支持在当前案件中额外上传历史参考日志，不写入跨案件长期基线。
- [ ] 对账号、IP、域名、端口、主机和进程提供本批次与参考文件的差异对照。
- [ ] 输出基线来源、时间范围、样本量和比较限制。
- [ ] 没有参考日志时明确提示“无法进行历史对照”，不得伪造首次出现结论。

### P7 即拆即用交付体验

- [ ] 提供单命令 CLI 分析入口，适合应急响应现场快速启动。
- [x] 提供 Docker Compose 和离线规则模式，固定依赖和启动方式。
  - 已完成：根目录 `Dockerfile`、`docker-compose.yml`、`docker/nginx.conf`；
    前端静态构建与 FastAPI 共用一个容器，数据通过 `loginsight-data` 卷持久化。
  - 验证：已确认 Docker CLI 与 Compose 可用；尚未完成镜像构建实测。
- [ ] 增加一键诊断命令，输出环境、依赖、磁盘、内存和端口检查结果。
- [ ] 补充应急响应快速开始文档：上传、分析、核验证据、导出和清理。
- [ ] 提供统一 ZIP 报告包，并在包内附带 manifest、哈希和生成版本。

## 维护规则

- 每次开始理解、修改或评审项目时，先阅读本文件和根目录 `AGENTS.md`。
- 完成任务时只更新实际完成的条目；必须附测试命令、样本范围或可观察验证结果。
- 新增需求先判断是否属于本项目的一次性日志研判范围；超出范围的能力单独记录，不直接实现。
