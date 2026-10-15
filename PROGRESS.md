# 项目进度（当前状态）

更新时间：2026-09-30

> 本文件只保留**当前状态与下一步**，保持短小易读。
> 逐次变更的明细（改动文件、原因、验证证据、遗留问题）见 `CHANGELOG.md`；
> 2026-09-16 之前的过程记录已归档到 `docs/archive/PROGRESS-历史记录-2026-09.md`。

## 一句话定位

AI 日志智能分析与可疑行为研判平台：**只读日志 → 解析 → 规则检测 → 证据 → AI 研判 → 报告**，不做自动处置。

> **按需独立分析，不做跨批次历史基线**（用户 2026-09-22 明确）：每次分析只看本次上传的日志，「首次出现」的含义始终是「本批次内首次」，不与其他批次联合判断。跨分析实体基线（P2-04）与配套的历史数据保留策略（P2-05）因此不做。

## 当前能力

| 维度 | 已具备 |
| --- | --- |
| 日志类型 | SSH、Nginx/Apache、IIS（W3C）、Windows Security/RDP（文本）、**Windows EVTX（二进制与 XML 导出）**、**Windows 事件日志键值化导出（`时间 级别 主机 提供程序 EventID=N 键=值`）**、**syslog / 容器日志（`时间 级别 主机 程序[PID]:` 前缀，内层访问日志与应用键值日志自动分派）**、通用 JSON/CSV、Firewall/WAF 键值、**MySQL / PostgreSQL / MongoDB / Redis / SQL Server / Oracle 数据库日志**、**域控异常登录列表 XLSX（`windows_auth_export`）**、Generic |
| 解析容错 | Web 支持标准 combined / 无引号 / 脱敏（剥离 `/` `:`）/ **无 `[时间]`（时间由外层提供）** 四种写法；时间戳兼容多种格式；EVTX 兼容事件查看器导出；DB 兼容 general/error/慢查询/stderr/JSON/单行/errorlog/alert.log；**各类格式自带的字段名一律原样落进记录**（EVTX 的 `<Data Name>`、W3C 的 `#Fields:` 列、`key=value` 键值对、JSON/CSV 键、SSH 行头、syslog 前缀的 program/pid 等），不按白名单静默丢弃 |
| 未知日志 | `generic` 类型走在线模板挖掘（Drain3）：输出模板、次数、占比，并标记仅出现一次的罕见模板 |
| 规则体系 | 规则以 YAML 声明式表达（`backend/rules/`），支持条件 / 时间窗聚合 / 跨记录关联三类原语；支持 Sigma 社区规则导入（8 条精选 + **2289 条社区导入**，覆盖 SigmaHQ 全部 17 个 Windows 子目录）；共 **2371 条规则**（74 内置 + 8 精选 + 2289 导入） |
| 规则治理 | 标注语料 123 个用例覆盖全部 **74 条内置规则**（含 4 个整份真实日志用例，其中 2 个属**攻击链场景 family**），`eval_rules.py` 与 `GET /api/rules/quality` 输出 TP/FP/FN 并作为测试门禁；**导入的社区规则没有本地正样本，单独列为「未验证的导入规则」，只做「正常流量零命中」筛查**；质量 Markdown 报告现在同时输出 `unverified_rules` 完整 ID 清单与重复检出明细；**规则元数据已补齐全部 2371 条**（内置 `AI-LogInsight`/`proprietary`/`validated`；Sigma `SigmaHQ contributors`/`DRL-1.1`，精选 8 条中 7 条 `validated`、社区 2289 条 `unverified`；社区规则**逐条**还带源规则的 `author`（2289/2289）与 `references`（2227/2289，非链接参考如 `Internal Research` 不计入但在导入报告里报出条数）），并新增**格式门禁 + 「声明 validated 必须有本地正样本」一致性门禁**（`app/services/rule_metadata.py`，违规非零退出）；元数据走**文档级 `metadata` 块 + 规则级覆盖**的继承，避免 2289 条同源规则逐条重复 |
| ATT&CK 覆盖 | 以外部参考集（EVTX-to-MITRE-Attack，>270 样本，**未打包**）的技术清单当尺子：`GET /api/rules/attack-coverage` 与 `scripts/attack_coverage.py` 输出「有规则 / 有本地正样本 / 缺口」三个口径（当前 120/120 有规则、46/120 有本地正样本）。清单里每项技术标了 `origin`：**外部参考集原有 27 项 / 本项目补充 93 项，两个来源分开统计、不合并成一个百分比**，避免把自选技术算成外部基准的覆盖率。刻意把「有标签」与「已验证」分开，避免假覆盖 |
| 检测可信度 | **检测覆盖度**（总记录 / 含可判定字段 / 命中规则 / 未覆盖 / 未纳入检测）随分析结果返回并展示在概览与 HTML 报告；未纳入检测进一步区分 **`parse_errors` 解析失败** 与 **`retention_drops` 超出单次保留上限**（`parse_failures` 保留为总数，接口向后兼容）；无事件时结论分三态：已覆盖未发现异常 / **覆盖不完整无法确认**（缺行为字段、解析失败或超保留上限）；`scripts/coverage_gaps.py` 输出未覆盖记录清单 |
| IOA 行为偏离 | **没有攻击特征时也给出判断**：层 1（同批次低频实体）+ 层 2（内置白名单：私有网段 / 常用端口 / 常用域名 / 非公网主机名），5 类偏离（首次出现的目的地址 / 域名、非常用端口外联、低频公网来源、罕见路径）；输出独立于 `events`、**不改变风险等级**；无事件但有偏离时结论为「未发现明确攻击特征，但存在 N 项行为偏离（低置信度）」。设计见 `docs/ioa-behavior-baseline.md` |
| 误报控制 | **用户白名单**（IP/网段、账号、User-Agent、域名、进程、路径、端口）：命中的记录不参与规则判定（因此不告警），但原始日志仍保留在明细里并标记「被哪条白名单放过」，覆盖度单独计数 `whitelisted_records`；每次新增/启停/删除都写入变更审计。Web 访问日志现已解析并保留 `user_agent` 字段 |
| 降噪 | **规则级聚合**：74 条内置规则与 2297 条 Sigma 导入规则全部声明聚合（内置按来源 + 时间窗，导入按「主机 + 进程」或来源 + 时间窗合并为一条，保留计数与代表性证据）；Sigma 导入时自动补轻量聚合兜底，避免社区规则逐条刷事件 |
| 异常评分 | 同源多事件按权重累计（CRS 思路），**归组对象优先来源 IP、主机侧日志退回目标资产**（否则 Sysmon/Windows 事件拿不到评分），两类维度互不叠加；默认关闭；开启后达到阈值升级风险等级 |
| 关联分析 | 实体关联（来源 IP / 目的 IP / 账户，跨日志类型串联）+ 统一时间线（事件与证据按时间合并）；**杀伤链按「来源 IP → 目标资产（主机）→ 规则」三级归组**（主机侧日志无来源 IP，按主机名归组后同一主机的行为合成一条链）；**终端证据链按目标资产聚合进程、文件、注册表、DNS 与外联节点，每个节点保留 `evidence-record-N`，支持前端展示与 AI 只读查询** |
| 研判交付 | 风险等级 + 置信度 + 规则编号（`rule_id`）+ 证据编号 + 时间线 + 排查建议；规则结果与 AI 结果合并，AI 失败保留本地结论；**AI 强制结构化研判（11 字段：事件时间/攻击源IP/目标资产/涉及账号/异常行为/关联日志/攻击类型/风险等级/判断依据/成功迹象/建议处置）** |
| 证据链与案件资料 | 原始文件 SHA-256 清单（`evidence-manifest.json`，关联记录 ID / 证据 ID / 事件 / 报告）、原始件只读落盘、案件包 ZIP（原始证据 + JSON/HTML 报告 + manifest，逐个文件记大小与 SHA-256）、实体调查接口（IP / 来源·目标 IP / 账号 / 主机 / 域名 / 进程，**精确匹配**，返回分页记录 + 关联事件 + 时间线，事件与时间线带上限并给出真实总数、事件按风险从高到低截断；**前端已接入**：从「实体关联」表点「查看记录」进入调查弹层）；**AI 结论人工确认（未确认 / 确认 / 否定 / 需复核，保留确认人、时间、备注，追加式留痕）**；**导出按「原始事实 / 规则命中 / AI 推断 / 人工确认」分层**：JSON 报告给 `provenance` 四层声明与 `human_review`，HTML 报告把 AI 内容单独成块并标注「未经人工确认，不得当作事实」 |
| AI 评测与门禁 | `evaluation/ai-cases/` **11 条标注用例**覆盖 9 类场景（正常 / 明显异常 / 证据不足 / 多事件关联 / 误报 / 无时间戳 / 缺失字段 / 截断 / 大日志），规模用例用生成器展开；`scripts/eval_ai.py` 输出报告并在门禁失败时**非零退出**（`--write` 落 `docs/ai-quality-report.md`）。检查 6 项（JSON 合法性 / 风险等级取值 / 置信度范围 / **证据真实性** / 引用覆盖率 / 无依据声明）+ 4 项期望比对。门禁项为非法 JSON、引用不存在证据、严重风险等级错误与期望不符；覆盖率与无依据声明只出报告不阻断。**不可评估 ≠ 通过**：无行为时引用覆盖率记为 `n/a` 而非 100%。标注口径参照 `DiogoRibeiro7/ai-incident-analysis-agent`：默认精确，仅在证据真有歧义时才用集合放宽。**分层**：5 条标记 `smoke` 组成最小回归集（覆盖误报/漏报/无证据编造/多事件关联/截断五类失败模式），随 `pytest` 自动执行；完整集走 CLI（`--smoke` 只跑最小集）。**默认判据是确定性替身，不是真实模型**（`--real` 才调真实模型），报告头会写明条件。**压力场景**（`tests/test_ai_stress.py` 42 条）：多轮工具调用硬上限（请求数严格等于 `AI_MAX_TOOL_ROUNDS + 1`，1/2/3 三档验证）、长上下文采样必须声明 `not_all` 与 `more=query_records`、模型引用不存在字段不得泄漏、高置信度不免检（`confidence: 0.99` + 编造 IP 仍被抓）、多语言日志（**Web 日志与语言无关；syslog 消息体依赖英文关键词，德语/中文 sshd 日志解析出 0 条——真实能力边界，如实钉住不假装支持**）。**多模型 / 多 Prompt 对比**：`RunResult` + `render_comparison()` + `build_artifact()`；CLI `--model` / `--prompt` 可重复做笛卡尔积、`--artifacts` 落 JSON（含证据引用 / 耗时 / token）。对比输出两张表，**逐用例风险等级矩阵**标出「一致 / 分歧」——「同一份日志上两个模型给出不同等级」比「通过率都是满分」信息量大得多。口径：缺账单 `n/a` 不填 0、引用覆盖率只在可评估用例上平均、耗时只计判据调用。**质量比率**：单次与对比报告都输出准确率 / 误报率 / 漏报率（`confusion` 四格齐全），**可疑与否一律看 `risk_level` 不看行为条数**（P1-16「行为偏离」会在正常日志上合法产生行为，按条数判会把合法偏离算成误报）；**缺样本侧时比率是 `n/a` 不是 0**（没有正常用例时误报率返回 0 会显示成「完美」）；判据崩溃（`risk_level` 为空）**不计为「正确」**。**Token × 质量回归门禁**：`scripts/eval_ai.py --baseline FILE` 与归档产物比对，四条规则——Token 涨超容差且质量未提升**失败**、Token 降但质量下降**失败**、Token 降且质量持平或提升通过、Token 涨且质量提升通过但**记为观察项不自动判成功**；准确率涨但误报率变差不算质量提升。门禁比较 `tokens_total` / `tokens_first_round` / `context_bytes` / `evidence_sent` / `accuracy` / `false_positive_rate`，**不依赖具体压缩机制**，P4 实现字段白名单 / 分层采样 / 去重 / 证据预算 / 摘要指针时无需再改门禁 |
| 成本与质量联合指标 | **Token 成本与研判质量必须同时呈现**：`app/services/ai_metrics.py`（**不 import 项目内任何东西**，可被单测直接驱动）记录总 / 首轮 / 工具轮次 / 缓存命中 Token、上下文字节数、研判耗时、逐事件与逐证据 Token 归属、evidence sent / referenced / 覆盖率 / 遗漏率、单次估算成本；接入 `request_ai_judgement`（`judgement["metrics"]`）、`AnalysisResult.ai_metrics`、AI 台账归档与 HTML 报告。**两类数字在数据结构上就分开**：真实账单（服务端 `usage`，拿不到就是 `null`）与估算归属（按上下文体量分摊，字段名与报告都写明「估算」）不共用键——把估算当账单看会让成本优化得出反向结论。**不内置厂商价格**（价格会变，写死会悄悄算错）：单价从 `AI_PRICE_INPUT_PER_M` / `AI_PRICE_OUTPUT_PER_M` / `AI_PRICE_CACHE_HIT_PER_M` 读取，未配置时 `cost.estimated` 为 `null` 并附说明，**不填 0**；缓存命中按缓存价计价，未单独配则回退输入价（保守，宁可高估）。`evidence_sent` **计条数而非去重 id**（同一证据可能出现在多个事件里，去重会把分母算小导致覆盖率虚高甚至超 1）；**无行为时覆盖率记 `n/a` 不记 100%** |
| AI 接入 | 18 个内置 Provider 预设 + 通用 OpenAI-compatible；请求前脱敏；支持连接测试与页面配置 |
| 证据价值与上下文压缩 | **谁进上下文由可解释评分决定，不再只按风险查表**：`app/services/evidence_value.py` 给每个事件算 5 个分量——风险 / **交叉印证**（同一归组实体上不同规则的命中数；`Event` 结构里没有 `confidence` 字段，**不伪造一个**，这是代理指标且字段名写明）/ **来源可靠性**（规则 `source`：builtin 1.0、sigma 0.6，后者是未验证的导入规则）/ **时间新颖性**（复用「与本批次相比首次出现」口径）/ **关联度**（跨来源文件数 + 同实体事件数，**绝对口径**——相对口径在单实体小日志上恒等于满分）。评分只做 ±1 微调，不按评分从 0 重映射（否则 critical 在其余分量偏低时会掉到比 high 还少，风险单调性被打破）。**硬约束：评分只决定下发几条证据，不改变 events / risk_level / behaviors**。**攻击链关键节点**复用 `analytics.build_attack_chains`，取每条 **≥2 阶段**链的首末节点，标记 `chain_node` 并**不被降级**（单阶段链的 `stages[0]==stages[-1]`，若也算端点则每个孤立事件都是关键节点）。**压缩前后证据召回率**：高风险事件基准档位即满额、**永远不会被深度截断**，只会在事件抽样这一层被整条丢掉，因此召回率的实际形态就是高风险事件的证据下发比；低于 `EVIDENCE_RECALL_FLOOR=0.9` 时**一次性自动降级**到更完整档位（补回被抽掉的高风险事件，受 `EVENT_SAMPLE_HARD_MAX=200` 约束——否则降级本身成了绕过预算守卫的后门）。实测 100 条 high / 共 200 事件：召回 0.70 → 补回后 110 条、召回 1.00。**预算削减按价值保留**（原先按列表位置砍尾巴，砍掉哪条取决于抽样顺序、与价值无关），并恢复原顺序以保住 prompt cache 前缀。`records_sample_note` 新增 `time_range=`（取**全量**记录，样本跨度天然更窄；无时间戳写 `unknown` 不猜）。**去掉一处会「对模型谎报」的设计**：`events_note` 原先硬编码逐档图例，与 `_EVENT_EVIDENCE_DEPTH` 是两份事实，改一处忘另一处就会按旧值告诉模型；现只声明 `evidence_cap=N`（逐档图例对模型**不可操作**却每轮付费） |
| AI 工具层 | 研判前只自动预取轻量只读工具（`log_metadata` / `log_statistics` / `query_events` / `timeline`），**返回结果以指针形式并入上下文**（`_auto_tool_pointer()` 只留摘要 + 计数锚点，避免与既有 `metadata`/`statistics`/`events`/`timeline` 块同源重复，实测 9733 → 1121 字节）；模型仍可按需追加调用 `query_evidence` / `query_behavior_deviations` / `query_uncovered_records` / `query_terminal_chains` / **`query_records`（按字段 + 包含/精确值 + 类型查原始记录）**；**模型按需查询的返回也做字段裁剪**（`query_terminal_chains` 节点去 null 与重复字段、单链上限 40 节点，71.8 KB → 17.4 KB，`evidence_id` 全保留）；**轮次按场景分档**：无事件干净日志 1 轮、有事件默认 4 轮、≥2 万条记录自动翻倍，`AI_MAX_TOOL_ROUNDS` 显式配置始终优先；模型不再调工具时立即早停；不支持工具的 Provider 自动降级为单次调用 |
| AI 时长与深度 | **在准确性和 Token 成本之间取平衡**：单次请求超时默认 300 秒（`AI_TIMEOUT_SECONDS`）、工具轮次默认 4、输出上限 4096 tokens（`AI_MAX_OUTPUT_TOKENS`）；**未显式配置时按日志规模自适应**（≥2 万条记录自动翻倍、无事件收敛为 1 轮）；超时提示区分「模型慢」与「服务不可用」并给出已等待时长；前端轮询无次数上限；**每次研判的 token 用量与缓存命中率归一化后写入 `ai_tool_trace` 并在 AI 研判模块展示**（DeepSeek/OpenAI/Anthropic 三家字段口径统一，服务端未回传时明确省略而非显示 0%） |
| AI 泛化输入 | **不让模型只盯着规则产出**：`records_sample` / `uncovered_records_sample` 改为**分层采样**（按来源/目标/账号/状态码/动作/路径/进程/文件/域名 9 个维度分组后轮流取，上限 200 条、≥2 万条记录时 500 条、**无事件且覆盖完整时降为 60 条轻量档**），并附 `records_sample_note` 写明总数与采样口径；**两块样本互斥**（实测重叠率曾达 96%~97%，去重后并集不变、体积 −21%~−47%）；**记录样本按日志类型走字段白名单**（`slim_records()` 剔除 `timestamp_iso`/`correlation_basis` 等派生字段，保留全部证据字段且不丢未知字段）；**事件块按风险分层**（critical/high 带 5 条证据、medium 3、low 2、info 1，另给 `evidence_count` 总数）；AI 上下文会移除与事件证据重复的记录原文；**第二轮起把首轮完整上下文替换为摘要占位**（`_shrink_history_context()`，超 20 KB 才触发），明细交模型按需查询；prompt 明确「规则只是线索、规则未命中不等于正常、涉及数量以总数为准」 |
| 证据溯源 | 结论中的 IP / 记录编号 / 涉及账号 / 目标资产必须存在于本次日志（先查结构化字段，对不上再回退查日志原文——**把日志事实报成幻觉，和对正确结论的误报是同一类问题**）；`evidence_ids` 兼容 `record-N`、裸字符串写法并自动映射；未支撑声明在前端提示，不篡改模型输出。**该检查已被反向验证**（`tests/test_ai_grounding.py` 14 条：逐类构造编造 IP / 记录编号 / 账号 / 目标资产，证明每一类都真能被抓到，并含子串陷阱与词边界守卫） |
| 模型输出容错 | 模型输出形状不符合约定时**降级而不是崩溃**：非法风险等级（大写 `"HIGH"`、数字、数组）归一化为 `info`；语义字符串字段收到数字/数组按「未提供」处理；`NaN` 置信度记 `0.0`（`min(1.0, nan)` 会把它放大成最高置信度）；`evidence` / `evidence_ids` 写成单个字符串时按单项处理（否则会逐字符拆开）；行为置信度不可解析时**保留整条行为**只把置信度置 0（此前整条被静默丢弃）；未知字段一律不进结果（`_validate_response` 是白名单，结果会被前端直接渲染）。`tests/test_ai_stress.py` 42 条钉住 |
| 数据与接口 | SQLite 持久化、历史列表/删除、明细分页与筛选、CSV 导出、JSON/HTML 报告、规则清单接口、演示日志库、**原始日志下载（`data/uploads/` 落盘，单文件直下/多文件 zip，演示日志除外）**、**AI 洞察接口（`GET /api/analysis/{id}/insights`：时间频次分桶 48 个 + 攻击链，链按 `chain_limit` 默认 20 条返回并给出 `attack_chains_total`）** |
| AI 研判进度 | **异步任务 + 真实阶段轮询**（`POST /api/analysis/{id}/ai/start` + `GET /api/ai/tasks/{task_id}`）：准备上下文 → 执行工具 → 调用模型 → 解析 → 溯源校验，前端浮层显示真实百分比；旧同步接口保留 |
| 终端取证可读性 | 日志明细已暴露 Sysmon / Windows 关键字段：进程镜像、命令行、目标文件、注册表路径、DNS 查询、目标资产、目的端口、事件编号；**所有普通记录统一生成 `evidence-record-N` 证据编号**，AI 可通过 `query_evidence` / `query_uncovered_records` 直接引用未命中规则的 Sysmon、Windows、进程和文件记录；**终端证据链将进程创建、文件活动、注册表修改、DNS 查询和外联行为按目标资产与时间聚合**；AI 工具自动查询 IOA 行为偏离、未覆盖记录和终端证据链 |
| 前端 | 日志列表（客户端分页 + 常驻筛选栏）；分析详情为**模块化分区**（模块导航 + 滚动高亮 + 单模块折叠 + **折叠状态 localStorage 持久化** + 分层配色，空模块自动隐藏并重编号）；**概览看板（仿 Zircolite Overview：五档严重度卡片「事件数 + 规则数」+ 中轴双向时间分布（上=记录数、下=事件按风险分层）+ ATT&CK 战术网格 + Top 规则/主机/来源 IP 三榜；点卡片可在事件模块按等级过滤）**；**AI 洞察模块（时间频次柱状图含峰值高亮 + ATT&CK 风格攻击链阶段流）**；**威胁情报模块（按需查询 + 命中/未收录/失败分色 + 强制重查）**；AI 配置使用自定义选择器（搜索 + 头像 + 副标题 + 对勾，非原生 select）；**AI 日志分析工具品牌标（明暗两版，透明底）+ 明暗双主题切换（localStorage 持久化，暗黑标签彩色描边增色）**；圆角/投影令牌柔化；状态徽章按语义差异化；日志明细筛选栏带图标卡片式重构；**AI 研判浮层进度条（真实阶段 + 百分比 + 动画）**；**筛选下拉选项色点 + 日志类型彩色标签**；**原始日志下载按钮（演示日志隐藏）**；**整体外观对齐 Zircolite（青绿 signal 强调色 + 拼接网格 + 4px 圆角 + 无阴影）** |
| 威胁情报富化 | **把研判里的公网 IP / 域名拿去公开情报库比对**（ThreatFox / URLhaus 免 key，AbuseIPDB 可选需 key）：`GET /api/analysis/{id}/threat-intel`；结果**独立展示、不进 `events`、不改风险等级、不进 AI 上下文**；默认关闭（`THREAT_INTEL_ENABLED`，外发查询必须显式开启），关闭时返回带说明的空报告且**不发任何请求**；只查公网指标（内网 IP 与常见厂商域名不外发）；按「指标 + 来源」缓存 24 小时并支持 `refresh=true` 强制重查；**「未收录」明确标注不等于安全**，来源无 key 时状态是 `skipped` 而不是「未收录」 |
| MCP 只读接口 | **外部 AI 客户端（Claude Code / Cursor 等）可直查本机分析结果**：`backend/scripts/mcp_server.py`（stdio，13 个只读工具：分析列表 / 总览 / 元数据 / 统计 / 事件 / 证据 / 时间线 / 行为偏离 / 未覆盖记录 / 终端证据链 / 记录查询 / AI 台账 / 威胁情报）；**与页面同源**——除四个入口外全部转调 `agent_tools.execute_tool`，不另写一套取数逻辑；**只读边界进测试**（工具名白名单 + 禁写关键词断言）；依赖锁 `mcp==1.9.4`（2.x 会把 pydantic/starlette 拉到与 fastapi 0.115.6 冲突的版本） |
| 概览看板与检测视图 | **概览看板**（五档严重度卡片「事件数 + 规则数」、中轴双向时间分布（上=记录数、下=事件按风险分层）、ATT&CK 战术网格、Top 规则/主机/来源 IP）与**检测视图**（按规则归组：等级、战术、技术、`N 个事件 · 触发 M 次` 双口径、可展开看规则来源与命中明细、可跳转实体调查）。两者都是**纯展示层**，全部由既有事件与记录推导，不新增判定 |
| ATT&CK 标签映射 | `app/services/tactics.py`：把 Sigma 规则的 `attack.<tactic>` / `attack.Txxxx` 标签翻成本项目中文战术名与技术编号（内置规则仍用 `_TACTICS` 手写映射，认不出时回退标签）。**没有这层映射，2289 条导入规则在战术网格里全落「其他」**——实测 IIS 样本里那条 Sigma 规则从「其他」变为「发现 / T1083」 |
| ATT&CK 矩阵 / 搜索语法 / 字段 facet | `GET /attack-matrix`（战术 × 技术两级，含「清单外技术」标记）、`GET /search`（`字段:值` + 排除 + 全文，未知字段告警）、`GET /facets`（字段覆盖率 + 取值 Top，`raw` / `command_line` 刻意不列）；前端新增「ATT&CK」「查询」视图、明细字段侧栏与「进程树」视图（由终端链节点构建，不猜父进程） |
| 外观（Zircolite 设计系统） | 视觉全部对齐 Zircolite 4.5.0 的 `app.css`：色板换成 `paper/panel/ink/ink-2/rule/signal` + 五档 `sev-0..4`（含 `sev-unknown`），暗色主题同步；字体栈改 Atkinson Hyperlegible（本机无此字体，回退 Inter/JetBrains Mono）；正文 15px/1.45；圆角统一 4px/3px；**去卡片阴影**（改 1px 边框分层）；指标卡与战术格改为 **Zircolite tiles 式拼接网格**（共享分隔线）；侧栏改为 NavRail（40px 行高 + 左侧 3px signal 竖条）。**技术栈不变**（Vue3 + FastAPI）：AI 研判/持久化/情报外呼/取证交付在纯浏览器 WASM 架构里无法实现 |
| 导入规则批量验证 | `backend/scripts/verify_sigma_rules.py` + `docs/sigma-rule-verification.md`：三层自动化验证（**合成正样本端到端可触发** / 真实语料回放 / 正常流量负样本筛查）。实测 **2070/2297 可触发（90.1%）、疑似缺陷 0、判定过宽 0**；其余 227 条因正则或复杂跨字段约束无法自动合成，如实单列。**回答「2289 条要不要逐条人工验证」：不需要**——机器把「逻辑成立」「真实数据跑得动」「不在正常流量乱报」三件事都验了，人工只看机器试出问题的少数 |
| 上传内存预检 | **把「机器跑不动这份日志」在动手前变成一句能看懂的话**（`app/services/memory_guard.py`）：文本日志峰值实测为文件大小的 **4.4 倍**（100 MB → 441 MB、200 MB → 883 MB，两档线性），上传前按「4.4 倍 + 300 MB 余量」与当前可用内存比对，不够则 413 并写明**本次多大 / 约需多少 / 当前可用多少 / 建议拆分**；读不到系统内存信息时**放行**，不误拒 |

## 检测规则（2371 条 = 74 内置 + 8 精选 Sigma + 2289 社区导入）

```text
认证类   ssh.bruteforce / ssh.bruteforce.success / ssh.password_spray / ssh.privileged_login
        rdp.bruteforce / rdp.bruteforce.success / windows.privileged_logon
        auth.bruteforce / auth.bruteforce.success / auth.password_spray (JSON / CSV)
Windows  windows.lolbin_download / windows.suspicious_executable_in_temp
        windows.archive_with_password / windows.masquerade_extension
        windows.credential_file_access / windows.payload_cleanup
        windows.registry_certificate_store / windows.suspicious_dns_query
        windows.discovery_command / windows.payload_outbound_connection
        windows.executable_drop_in_temp / windows.registry_bulk_write
        windows.script_interpreter_encoded / windows.command_shell_suspicious_parent
        windows.scheduled_task_persistence
        (Sysmon 行为事件；脚本编码/隐藏命令、可疑父进程启动 cmd、计划任务创建分别覆盖 T1059.001、T1059.003 与持久化场景)
Web 类   web.sensitive_path / web.path_traversal / web.404_scan
        web.5xx_burst / web.sql_injection / web.xss / web.command_injection
        web.cloud_metadata_access / web.sensitive_interface / web.webshell / web.scanner_user_agent
        web.sensitive_file_access / web.sensitive_file_access.success
        web.auth_bruteforce / web.auth_bruteforce.success        (登录失败聚集 + 后续 2xx)
网络类   firewall.port_scan
数据库类 db.bruteforce / db.bruteforce.success                   (MySQL/PG/Mongo/Redis 认证爆破)
        db.sql_injection / db.destructive_query / db.privilege_escalation
        db.data_exfiltration / db.privileged_login
应用层类 app.sensitive_path_probe / app.auth_threshold_block
        app.restricted_resource_access                          (syslog 内层 security 程序的安全信号)
Windows事件 windows.account_lockout / windows.service_install / windows.protection_service_stopped
            (4740 账户锁定 / 7045 新服务安装 / 7036 防护服务被停止)
域控导出 windows.auth_export.suspicious_ip / windows.auth_export.abnormal_time
            (异常IP / 异常时间标记，按来源IP + 目标资产 + 标签聚合)
终端行为 windows.inhibit_recovery / windows.ransomware_extension            (影响：破坏恢复 / 勒索扩展名)
        windows.security_service_stop / windows.data_destruction
        windows.lsass_memory_dump / windows.sam_registry_dump                (凭证访问：LSASS 转储 / SAM·NTDS 导出)
        windows.credential_hunting                                           (文件内搜索口令)
        windows.eventlog_cleared / windows.defender_exclusion_added          (防御规避：清日志 / 加排除项)
        windows.certutil_decode / windows.uac_bypass / windows.hidden_file_attrib
        windows.create_local_account / windows.account_manipulation          (账户：建号 / 加入管理员组)
        windows.registry_run_key                                             (自启动持久化)
        windows.network_connection_discovery / windows.file_directory_discovery
        windows.account_discovery
        (Sysmon 行为事件；三条发现类规则要求时间窗内重复出现，
         判据刻意避开 windows.discovery_command 已覆盖的进程清单，避免同一行为被两条规则重复检出)
```

规则清单与实时启停状态：`GET /api/rules`；阈值与开关在 `.env`（示例见 `.env.example`）。

另有 **2297 条 Sigma 导入规则**（`rules/90-sigma.yaml` 8 条精选 + `rules/95-sigma-community.yaml` 2289 条批量社区导入）。批量导入覆盖 SigmaHQ 全部 17 个 Windows 子目录（进程创建 / 文件 / 注册表 / DNS / 网络连接 / 镜像加载 / 命名管道 / WMI / 脚本块 / 驱动加载 / 安全通道等）。规则里的字段名就是 EVTX 标准字段名，EVTX 解析器按标准结构把 `<System>` 事件头与 `<EventData>` 里每个 `<Data Name="…">` 原样落进记录（`OriginalFileName` / `ParentCommandLine` / `Details` 等），转换时直连；只保留「能严格转换且不在正常流量用例上误报」的规则，跳过与剔除原因见 `docs/sigma-import-report.md`。**社区规则没有本地正样本**，事件名带 `[Sigma]` 前缀，`RULE_SIGMA_IMPORTED_ENABLED=false` 一键停用。

## ATT&CK 技术覆盖（外部参考集当尺子）

外部参考集：**EVTX-to-MITRE-Attack**（>270 个第三方 EVTX 样本，按 ATT&CK 映射）。**270 是外部规模，未打包进本仓库、产品也不解析第三方样本**——只引用其中出现过的 27 项技术作为覆盖标尺；另有 **18 项本项目补充技术**（原参考集未覆盖、由本项目为补齐空白战术自行加入，标 `origin: project`）。

```
报告：GET /api/rules/attack-coverage
刷新：cd backend && .venv\Scripts\python.exe scripts\attack_coverage.py --write
当前：技术覆盖 120 / 120、本地正样本验证 46 / 120（2026-10-13；清单由 45 项扩到 120 项，新加入技术暂无本地样本）
      其中 外部参考集原有 27 / 27、本项目补充 18 / 18
```

报告刻意把口径分开，避免把「有标签」当成「已验证」，也避免把「自选清单」当成「外部基准」：

| 口径 | 含义 | 当前 |
|---|---|---|
| 有规则（covered） | 存在映射到该技术的规则 | 120 / 120 |
| 有本地正样本 | 标注语料里有用例真的命中过这条规则 | 46 / 120 |
| 外部参考集原有 | 技术来自外部参考集，构成外部标尺 | 27 / 27 |
| 本项目补充 | 为补齐空白战术自行加入，**不构成外部基准** | 93 / 93 |
| 外部参考样本 | 第三方样本集规模，只作标尺，未打包 | >270 |

> ⚠️ **45 项是「优先清单 + 本项目补充」，不是 ATT&CK 全量**（Enterprise 有 200+ 技术）。报告到 100% 只说明这份清单补齐了，下一步价值仍在**继续扩充清单**（把新技术的规则与样本一起加），而不是宣布检测能力到顶。


## 运行与验证

```bash
# 启动（两个终端）
cd backend && .venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
cd frontend && npm run dev -- --host 127.0.0.1 --strictPort
```

- 后端测试：`cd backend && .venv\Scripts\python.exe -m pytest -q` → 当前 **646 passed**（本轮新增规则元数据门禁 10 条、规则库体检 15 条、声明一致性 1 条，并修正 1 条断言「内置规则元数据未声明」旧状态的用例；此前 P8 系列新增概览看板 / 检测视图 / ATT&CK 矩阵 / 搜索 / 字段 facet / 威胁情报 / MCP / 内存预检等，更早证据价值评分与上下文压缩 30 条、成本 × 质量联合门禁 29 条、P3 指标 27 条、多运行对比与产物 23 条、压力场景 42 条、防幻觉反向验证 14 条、AI 评测与分层 30 条、人工确认与导出分层 10 条、实体调查精确匹配与截断 8 条；测试使用临时 SQLite，不写 `data/loginsight.db`）。**注意套件耗时波动较大**（2026-10-13 两次完整运行实测 **14m35s / 18m57s**，后者与另一条重负载命令并发），主因疑似本机可用内存在 1.0~3.4 GB 间浮动，与代码改动无关。
- AI 评测门禁：`cd backend && .venv\Scripts\python.exe scripts\eval_ai.py` → 11/11 通过、退出码 0；有门禁失败时非零退出。`--smoke` 只跑最小回归集（5 条，4.3s）；`--write` 落 `docs/ai-quality-report.md`。**默认判据是确定性替身，不是真实模型**（`--real` 才调真实模型），报告头会写明这一点。最小回归集已挂进 `pytest` 自动执行。
- AI 多模型 / 多 Prompt 对比：`scripts\eval_ai.py --real --model <M1> --model <M2> --prompt <文件> --artifacts <目录>` → 按「模型 × Prompt」笛卡尔积逐个运行，输出**运行对比表**与**逐用例风险等级矩阵**（标「一致 / 分歧」），并把含证据引用 / 耗时 / token 的 JSON 产物落盘。**缺账单显示 `n/a` 不显示 0**（「没测到」与「零成本」是两件事，填 0 会让成本对比得出反向结论），引用覆盖率只在可评估用例上求平均，耗时只计判据调用。**用确定性替身做多运行对比没有区分度**，CLI 会显式提示。
- 规则质量：`cd backend && .venv\Scripts\python.exe scripts\eval_rules.py` → 用例 123/123、内置规则覆盖 74/74、TP 111 / FP 0 / FN 0（另报告 2289 条未验证的社区规则与重复检出数）；同时执行**规则元数据门禁**（许可证 / 链接格式 / 验证状态取值 + 「声明 `validated` 必须有本地正样本」一致性），违规时非零退出（已反向验证：非法许可证 → 退出码 1）。
- 规则库体检：`cd backend && .venv\Scripts\python.exe scripts\rule_health.py` → 2371 条规则**阻断项 0**、观察项 33（`event.type` 冲突，`slug()` 截断所致，不阻断）；有阻断项时非零退出，`--write` 落 `docs/rule-health-report.md`。检查六类：悬空引用 / 自压制 / 压制成环 / **升级链不对称** / 判据+聚合完全相同且互不压制 / 空 `group_by`。`tests/test_rule_health.py` 15 条把「出厂规则零阻断项」钉进 `pytest`（本项目无 CI，`pytest` 即门禁机制）。**判据签名含聚合**——只比 `where` 会把 5 组刻意设计的 `.success` 压制对误报成重复（本轮实际踩过）。
- Sigma 批量导入：`cd backend && .venv\Scripts\python.exe scripts\import_sigma_community.py --sigma-dir <SigmaHQ 检出目录> --source-version <commit> --write` → 2418 候选 → 2416（先排除与既有仓库重复的 id）→ 2302 转换 → 2289 保留（去重 + 正常流量零命中裁剪）。**没有检出目录时不必 clone 整个仓库**：直接取指定版本归档即可，`https://codeload.github.com/SigmaHQ/sigma/zip/<commit>`（支持短 SHA，如 `b4ba1f2`，12.7 MB），解压后把该目录当 `--sigma-dir` 传入。**`--dirs` 默认已是全部 17 个子目录**（曾因默认只写 2 个、而文档命令没带 `--dirs`，照文档重跑会静默少导入 447 条）。归档已留在项目根目录 `SigmaHQ-b4ba1f2.zip`（与 `Zircolite-4.5.0.zip` 同一惯例，12.7 MB），离线可复用：解压后把该目录当 `--sigma-dir` 传入即可。
- ATT&CK 覆盖：`cd backend && .venv\Scripts\python.exe scripts\attack_coverage.py` → 技术 120/120、本地正样本 46/120（其中外部参考集原有 27/27、本项目补充 93/93，两个来源分开统计；`--write` 刷新 `docs/attack-coverage-report.md`）。
- AI Token 控制：**实测多轮累计降幅 85%~88%**（域控 4.45 MB → 691 KB）。十四项优化：① 工具结果指针化去重（−88%）；② 第二轮起首轮完整上下文替换为摘要占位（243 KB → 5.3 KB）；③ 轮次按场景分档 + 早停；④ 记录样本按日志类型字段白名单；⑤ 事件证据按风险分档（5/3/2/1）；⑥ 无事件且覆盖完整时启用轻量档（60 条样本）；⑦ System Prompt 压缩 3563 → 2895 字节（并删去 prompt 内重复的工具名清单）；⑧ **prompt caching 按服务端分流接入**（Anthropic/OpenRouter 显式打 `cache_control`、DeepSeek/OpenAI 走自动前缀缓存，`AI_PROMPT_CACHE=false` 可关）；⑨ **用量与缓存命中可观测**（归一化 DeepSeek/OpenAI/Anthropic 三家 usage 字段，写进 `ai_tool_trace` 并在 AI 研判模块展示，不计入工具调用次数）；⑩ **工具返回结果裁剪**（`query_terminal_chains` 节点去 null/去重字段 + 40 节点上限，71.8 KB → 17.4 KB，−76%，`evidence_id` 全保留；同时修掉按 `kind` 过滤时 `record_count` 报整链计数的语义缺陷）；⑪ **两块记录样本互斥去重**（实测重叠率 96%~97%，去重后两块并集不变、体积 −21%~−47%）；⑫ **`query_records` 按查询字段投影下发**（只查 `source_ip` 时不再带回 `command_line`/`raw` 等无关字段，−47%；`evidence_id`/`record_id`/`timestamp` 恒保留，未指定 `field` 时行为完全不变）；⑬ **用量历史趋势**（`GET /api/ai/usage-history` 用 `json_each` 在库内抽取，不全表反序列化；缺失记 `null` 不填 0，前端缺失点不画柱并注明「近 N 次中 M 次有账单」；列表页柱状图可切输入 tokens / 缓存命中率）；⑭ **工具轮次失败降级不再丢轨迹与用量**。成本模型、实测数据见 `docs/ai-token-cost.md`，复测用 `scripts/bench_ai_context.py`。
- 已评估后不做：AI 上下文上限**按模型自适应**——实测典型日志仅占 2 MB 预算的 0.3%~1.3%、实测最大值 31%，该预算从不构成瓶颈，其职责是防跑飞而非限流（依据见 `docs/ai-token-cost.md` §3.12，已归入 §7「评估后决定不做的项」以免重复评估）。
- 已评估后不做：**记录样本增量发送**——实测第二轮起首轮完整上下文已被摘要占位替换，占位中**不含任何记录明细**（三份真实日志首轮样本 101~148 KB，占位里只剩 170 B 计数说明），故「增量」没有对象可发；即便把占位删光，可省也仅占累计 2.2%~19.2%（域控 4 轮 2.2%）。记录样本的重复发送问题早在历史裁剪与两块互斥时已解决（依据见 `docs/ai-token-cost.md` §3.15）。
- 已修复的两个真实缺陷：轮次用尽时收尾提示把最后一条 tool 结果挤出末尾（模型看不到刚取回的证据就被要求作答，§3.14）；**工具轮次失败降级时 `except: pass` 丢弃已完成的轨迹与用量**——用量那条 `tool=="usage"` 也在 trace 里，被一并丢掉，这是生产库 49 条已完成分析 0 条带用量的直接原因（§3.16）。两条均有反向验证过的回归测试。
- Sigma 导入：`cd backend && .venv\Scripts\python.exe scripts\import_sigma.py --write` → 9 条样例中 7 条转换成功、2 条因字段无法映射被明确跳过。
- 前端检查：`cd frontend && npx vue-tsc --noEmit -p tsconfig.json`。
- 上传空间治理：单文件默认 50 MB、单次分析默认 200 MB、全局 `data/uploads/` 默认 2 GB，均可通过 `.env` 调整；落盘失败会自动回滚目录与记录。
- 上传目录自检：`cd backend && .venv\Scripts\python.exe scripts\clean_uploads.py`（只列孤儿目录，确认后加 `--apply` 执行删除）。
- 大日志基准：`cd backend && .venv\Scripts\python.exe scripts\bench_large_log.py`（默认 1/5/10 MB，可 `--mb 50` 压测上传上限）。
- EVTX 二进制依赖 `python-evtx`，模板挖掘依赖 `drain3`。
- 演示日志：网站展示 6 份代表性样本（SSH / IIS / Windows XML / CSV / Firewall / 未识别应用日志），前端默认体验可直接命中规则的认证 CSV；数据库目录提供 MySQL/PostgreSQL/MongoDB/Redis 4 份样本。

## 已知问题

1. 普通访问日志解析成功但没有命中规则时，结果仍是“无可疑事件”；这表示分析完成，不代表上传失败。若日志未被识别为已知类型（`generic`），详情页会用「日志模板」给出结构与罕见模板，可据此判断是否需要补充规则或解析器。
2. 历史日志列表已改为服务端分页与筛选；分析详情记录仍通过 `/api/analysis/{id}/records` 分页查询。
3. `npm run build` 在部分沙箱环境会因 `rmSync` 安全删除 shim 超时；改用 `vite build --outDir <新目录>` 可产出。
4. 契约类冗余未清理（`LogStatistics.total` 与 `metadata.total_lines` 同值、`top_users` 无消费方、`Event.evidence` 与 `evidence_items` 重叠）—— 属 API 变更，需评估后再动。
5. AI 任务状态以 SQLite 持久化，服务重启时会扫描遗留的 `running` 任务并重新接管执行；由于模型请求不可断点续跑，恢复机制会从头重跑本次研判，而不是恢复到模型中途 token。已结束任务按 TTL（30 分钟）与容量上限（200 条）清理，运行中任务不受影响。
6. 上传失败回滚和历史孤儿目录清理已实现（落盘失败自动回滚；`scripts/clean_uploads.py` 可自检清理），容量限制已生效，达到全局上限时会拒绝新上传。
7. **大记录的事件列表按分页返回**：详情接口默认返回前 200 个事件，普通查询每页最多 1000 个，通过 `event_offset` + `event_limit` 增量读取，真实总数在 `events_total`；完整报告仍从存储读取。`event_limit=0` 不再允许，避免通过接口重新拉取几十 MB 响应。**事件列表按风险从高到低排列**（同级按触发次数降序），所以第一页是最严重的事件，而不是最早产出的事件。
8. **攻击链同样按分页返回**：`/api/analysis/{id}/insights` 默认返回前 20 条链，普通查询每页最多 100 条，通过 `chain_offset` + `chain_limit` 增量读取，真实条数在 `attack_chains_total`。`chain_limit=0` 不再允许，避免认证导出一次返回 1999~2214 条链。链按 **风险 → 阶段数 → 触发次数** 排序，截断时留下的是行为最完整的链。
9. **洞察数据不进 AI 上下文**：`timeseries` / `attack_chains` 不在 `AnalysisResult` 里，`build_ai_context()` 也不引用，因此不消耗 token。AI 上下文的成本来自采样后的 events 与记录样本，并且已针对成本做过十四项优化（见「运行与验证 → AI Token 控制」）：无事件且覆盖完整时样本降为 60 条、事件证据按风险分档、工具结果以指针形式并入、两块记录样本互斥、第二轮起首轮完整上下文替换为摘要占位、prompt caching 按服务端分流接入、用量与缓存命中可观测、模型按需查询的工具返回也做字段裁剪与字段投影。**实测多轮累计降幅 85%~88%**（域控 4.45 MB → 691 KB）；`event.evidence` 与 `evidence_items[].raw` 的重复也已去掉（同一段原文只发一次）。
10. syslog 解析只支持 **ISO 时间戳前缀**；经典 `Mon DD HH:MM:SS 主机 程序[PID]:` 前缀暂不剥壳（该形式的认证日志已由 SSH 解析处理，其余程序需要时再扩展）。
11. **大日志性能**（`scripts/bench_large_log.py` 实测，2026-09-22）：11 MB / 6 万条时解析 0.85 秒、规则匹配 2.2 秒、峰值内存 **49 MB**（约 820 字节/条）。规则匹配已由「每条记录跑全部规则」收敛为按日志类型与必要条件索引挑选候选规则；记录侧已去掉两处全量字典复制并让重复字段值共享对象（此前为解析 0.75 秒 / 规则 9.5 秒 / 峰值 90 MB）。按 50 MB 上传上限外推，峰值约 0.25 GB 量级。
    **2026-09-30 复测（真实文件、`--file` 口径）**：11.13 MB → 解析 0.90s、规则 2.99s、峰值 49 MB；**100.13 MB → 解析 8.19s、规则 28.20s、峰值 441 MB**，两档覆盖率均 100%、解析失败 0、超保留 0，峰值稳定为 **4.4× 文件大小（856 字节/条）**。据此外推 500 MB 需约 2.2 GB、1 GB 需约 4.4 GB 峰值，**文本日志路径没有保留上限**（只有 EVTX 有 `AUTH_RECORD_LIMIT` / `OTHER_RECORD_LIMIT`），因此 1 GB 文本日志在本机（可用内存 1.0 GB）不可验证，属架构约束而非配置问题。样本生成与复测命令见 `scripts/gen_large_log.py`（流式写盘，避免「生成样本本身先 OOM」）。
12. **AI 上下文增加最终硬上限**：默认 `AI_CONTEXT_MAX_BYTES=2000000`，上下文在追加说明和删除低优先级块后仍会再次校验，最终序列化 JSON 绝不超过该字节预算；基础字段本身超限时明确失败，不发送超限请求。该预算可通过 `.env` 调整。
13. **AI 上下文第二轮内存优化**：不再先为全部日志记录生成完整脱敏副本；先按分层策略抽取样本，再只复制并脱敏将要发送的样本，规则覆盖统计仍基于原始记录。大日志分析基准保持 49 MB 峰值，AI 上下文构建的额外复制量已降低。
14. **人工确认的粒度是「整条分析的 AI 结论」**，不是逐条 `ai_behaviors`。入口在 AI 研判模块内，因此只跑了规则、没跑 AI 的分析目前没有确认入口（该模块整体隐藏）；确认人由用户手填，没有登录态（与规则审计的 `actor` 同一类问题）。
15. **待处理的既有问题**（本轮只记录、未改动，避免顺手扩大改动范围）：① 上传与案件包全量驻留内存（`upload_log` 读全文件、`case-package` 在内存组包）；② manifest 的 `record_ids` / `evidence_ids` 随记录数线性膨胀。另有同类但**未改**的一处：日志明细的 `source_ip` / `destination_ip` 筛选仍用子串包含（`database.get_record_page`），那是**搜索筛选**语义，与实体调查的**身份精确匹配**不同，本轮按外科手术原则未动。
    （原 ① 实体调查子串匹配过宽、② 实体调查 events/timeline 未分页已于 2026-09-30 修复，见 CHANGELOG。）
16. **实体调查弹层与人工确认区块的渲染效果未经肉眼确认**（2026-09-30）。已验证到数据层：经前端 5173 代理请求三类实体均 200、字段与模板读取项一一对应且都有值、dev server 服务的确认是改后组件、人工确认「改判后保留旧记录」成立。但本机未安装浏览器运行时（`agent-browser` 缺失，装一次约 500 MB，可用内存仅 1～2 GB），**样式、布局、翻页按钮的实际观感仍待人在浏览器里看一眼**。
17. **`/api/rules` 响应因规则元数据补齐增大 35%**（实测 996 KB → 1346 KB，2026-10-13）：增量主要来自 Sigma 规则的 `references`。**核实后确认前端并未调用该接口**（`App.vue` 只用 `/api/rules/preview`），规则元数据实际经 **detections** 接口下发，而 detections 只为**真正命中的规则**建组，因此实际影响很小。`references` 前端只声明未渲染，是否渲染留作后续决策。

## 项目完善执行清单

> 状态约定：`已完成` = 已实现并通过验证；`进行中` = 已开始但仍有验收项；`待完成` = 尚未实现。
> 后续每完成一项，必须同步更新本表、验证结果和 `CHANGELOG.md`。

### P0：检测可信度

| 编号 | 任务 | 验收标准 | 状态 | 完成日期 |
|---|---|---|---|---|
| P0-01 | 统一证据编号 | 普通记录生成 `record-N` / `evidence-record-N`，AI 可查询引用 | 已完成 | 2026-09-19 |
| P0-02 | 检测覆盖度提示 | 区分已检测、未覆盖、解析失败、超出保留上限，不能把未覆盖表述为正常 | 已完成 | 2026-09-18 |
| P0-03 | 解析失败可见化 | 展示文件、行号、失败原因和原始内容摘要 | 已完成 | 2026-09-20 |
| P0-04 | XML 单条事件降级解析 | 单条 XML 失败不影响后续事件；失败记录保留为可追溯证据 | 已完成 | 2026-09-20 |
| P0-05 | 解析失败前端模块 | 详情页提供解析失败明细和覆盖范围说明 | 已完成 | 2026-09-20 |
| P0-06 | 解析异常测试 | 覆盖裸 `&`、乱码、字段缺失、空日志、超大日志、格式错误日志 | 已完成 | 2026-09-20 |
| P0-07 | 文档基线同步 | `PROGRESS.md`、README 与实际测试数、规则数、覆盖结果一致 | 已完成 | 2026-09-20 |

### P1：终端证据链

| 编号 | 任务 | 验收标准 | 状态 | 完成日期 |
|---|---|---|---|---|
| P1-01 | 终端证据链基础聚合 | 按目标资产和时间聚合进程、文件、注册表、DNS、外联行为 | 已完成 | 2026-09-19 |
| P1-02 | 关联时间线与证据跳转 | 前端显示节点、时间和证据编号，可跳转日志明细 | 已完成 | 2026-09-19 |
| P1-03 | 父子进程关联 | 支持 `ProcessId`、`ParentProcessId`、`ParentImage` 关联进程树 | 已完成 | 2026-09-20 |
| P1-04 | DNS 到外联关联 | DNS 查询结果与后续目的 IP、端口、进程建立可解释关联 | 已完成 | 2026-09-20 |
| P1-05 | 关联置信度 | 节点关系标记 strong / medium / weak，并展示关联依据 | 已完成 | 2026-09-20 |
| P1-06 | 修正弱目标资产聚合 | 缺少 `target_asset` 时避免仅按来源文件错误合并多个终端行为 | 已完成 | 2026-09-20 |

### P1：大日志与文件生命周期

| 编号 | 任务 | 验收标准 | 状态 | 完成日期 |
|---|---|---|---|---|
| P1-07 | 历史日志后端分页 | `/api/logs` 支持 page、page_size、类型、风险、状态、关键词筛选 | 已完成 | 2026-09-20 |
| P1-08 | 上传空间治理 | 支持单文件、单分析、全局目录容量限制 | 已完成 | 2026-09-20 |
| P1-09 | 上传失败回滚 | 分析创建或文件落盘失败时清理对应目录和数据库记录 | 已完成 | 2026-09-20 |
| P1-10 | 孤儿目录清理 | 提供安全的定期清理或手动清理机制，不误删有效上传 | 已完成 | 2026-09-20 |
| P1-11 | 大日志性能验证 | 流式/分块处理大日志，验证内存、耗时和解析覆盖率 | 已完成 | 2026-09-20 |
| P1-17 | 规则匹配性能优化 | 把 O(规则数 × 记录数) 的逐条匹配改成按日志类型分组或建立索引；目标：10 MB 日志规则匹配降到 2 秒内 | 已完成 | 2026-09-22 |
| P1-18 | 记录内存占用优化 | 单条约 1360 字节，50 MB 日志峰值到 0.5 GB 量级；需瘦身记录表示或分批处理 | 已完成 | 2026-09-22 |
| P1-19 | 域控异常登录导出解析与规则识别 | 识别域控异常登录列表 XLSX；保留异常标签和原始字段；按真实发生次数聚合；两份真实附件解析失败数为 0 | 已完成 | 2026-09-21 |

### P1/P2：误报控制与规则治理

| 编号 | 任务 | 验收标准 | 状态 | 完成日期 |
|---|---|---|---|---|
| P1-12 | 用户白名单 | 支持可信 IP/网段、账号、User-Agent、域名、进程、路径和端口 | 已完成 | 2026-09-21 |
| P1-13 | 白名单审计 | 白名单不删除原始证据，页面显示命中项并记录变更历史 | 已完成 | 2026-09-21 |
| P1-14 | Sigma 聚合语义 | 支持次数、时间窗、分组字段和去重实体等轻量聚合 | 已完成 | 2026-09-21 |
| P1-15 | 事件聚合降噪 | 相同来源、规则和时间窗内的重复事件聚合为一条，保留计数和代表性证据 | 已完成 | 2026-09-21 |
| P1-16 | 时间维度异常 | 支持非工作时间、高频突发、周期心跳等低置信度行为偏离；保持低置信度提示，不改变风险等级 | 已完成 | 2026-09-24 |

### P2：AI 与历史基线生产化

| 编号 | 任务 | 验收标准 | 状态 | 完成日期 |
|---|---|---|---|---|
| P2-01 | AI Provider 重试 | 区分网络、限流、鉴权、超时、格式错误并按策略重试 | 已完成 | 2026-09-22 |
| P2-02 | AI 流式输出 | AI 中断不影响规则结果；最终输出仍经过结构化和证据校验 | 已完成 | 2026-09-22 |
| P2-03 | AI 任务持久化与恢复 | 服务重启后接管 `running` 任务；缺失分析记录时明确失败；同一任务不重复启动 | 已完成 | 2026-09-22 |
| P2-09 | AI 上下文最终硬上限 | 追加说明后再次校验，最终 JSON 不超过 `AI_CONTEXT_MAX_BYTES`；无法容纳基础字段时拒绝发送 | 已完成 | 2026-09-22 |
| P2-10 | AI 上下文复制优化 | 只对最终采样记录脱敏，不生成全量 `safe_records` 副本，样本与覆盖统计保持一致 | 已完成 | 2026-09-22 |
| P2-04 | 跨分析终端实体基线 | 保存资产、IP、域名、进程、端口等统计，支持历史首次出现判断 | **不做**（用户决定） | 2026-09-22 |
| P2-05 | 历史基线隐私治理 | 明确保留周期、脱敏范围和删除机制，不保存不必要的原始日志 | **不做**（随 P2-04 取消） | 2026-09-22 |
| P2-06 | 规则预览和质量门禁 | `POST /api/rules/preview` 支持草稿 YAML/JSON 校验、样本日志试运行、TP/FP/FN 评估；预览不写规则目录，失败无需回滚（**前端已接入**，`App.vue` 规则预览调用） | 已完成 | 2026-09-24 |
| P2-07 | 规则变更审计 | `PATCH /api/rules/{rule_id}/enabled` 写入启停覆盖并记录审计（覆盖优先级高于 `.env`，立即生效无需重启）；`GET /api/rules/audit` 可查操作者、动作、前后状态和时间（`actor` 当前恒为 `console`，未接登录态）（**后端接口已交付，前端未接入**） | 已完成 | 2026-09-24 |
| P2-08 | README / AGENTS 去重 | 保留 AGENTS 约束、README 使用说明，删除重复设计规范。用脚本量化两份文档各章节相似度定位真重复（≥0.50 的 5 组），按「**约束与判定口径留 AGENTS、产品定义（字段表 / JSON schema / 技术栈 / 工具清单）留 README**」的原则各自收敛，中间用 `§N` 指针连接；**AGENTS.md 1362 → 1186 行（−13%）**、README 2017 → 1946 行；相似度 ≥0.50 的重复组 **5 → 0**、≥0.40 从 22 → 4；36 个编号小节与全部约束条款逐条核对无缺失 | 已完成 | 2026-09-24 |

### P3：对标开源同类项目后的补强（2026-09-22 新增）

| 编号 | 任务 | 验收标准 | 状态 | 完成日期 |
|---|---|---|---|---|
| P3-01 | 检测覆盖面量化（ATT&CK 标尺） | 外部参考集（EVTX-to-MITRE-Attack，>270 样本）**只作标尺、不打包**（第三方样本有许可与恶意样本处置风险）；报告分三个口径：外部参考规模 / 有规则 / 有本地正样本，且必须显式说明 27 项不等于 ATT&CK 全量；补上清单里的缺口技术并配正负样本，门禁保持 FP 0 / FN 0 | 已完成 | 2026-09-22 |
| P3-02 | Sigma 规则扩容（7 条 → 数百条） | 从 SigmaHQ 主库批量导入 Windows/Sysmon/认证类规则；导入后 `evaluation/corpus` 门禁保持 FP 0 / FN 0，重复与互相冲突的规则去重，每条规则可追溯到原 sigma id 与导入版本；质量报告列出全部 `unverified_rules` ID | 已完成 | 2026-09-23 |
| P3-03 | AI 研判审查台账（investigation ledger） | 每次 AI 研判落一条可追溯台账：模型与请求参数、每次工具调用与返回摘要、结论引用的 evidence id、溯源校验拦下的无效引用、耗时与结束状态；`GET /api/analysis/{id}/ai/ledger` 接口可查看，`/export?format=json/html/csv` 可导出，服务重启后仍可查（**前端已接入**，`App.vue` 台账查看与导出） | 已完成 | 2026-09-24 |
| P3-05 | AI 研判 Token 成本优化（P0/P1/P2 十四项 · 已收口） | 量化上下文成本结构并逐项削减：工具结果指针化去重、历史上下文裁剪、轮次分档与早停、记录字段白名单、事件证据按风险分档、轻量档、System Prompt 压缩、prompt caching 分流接入、用量与缓存命中可观测、工具返回结果裁剪、两块记录样本互斥、`query_records` 按查询字段投影下发、**用量历史趋势端点与前端趋势图**；多轮累计降幅 85%~88%、单条终端链返回体积 −76%、两块样本重叠率 96%→0%、`query_records` 收窄查询 −47%，且样本并集、证据锚点与测试门禁均不退化；顺带修掉两个真实缺陷：轮次用尽时收尾提示挤掉最后一条 tool 结果、**工具轮次失败降级时丢失已完成的轨迹与用量**（后者是生产库 0/49 带用量的直接原因）；**两项经实测否决并留证**：按模型自适应预算（§3.12）、记录样本增量发送（§3.15，前提不成立）。**§6 已无待办** | 已完成 | 2026-09-23 |
| P3-06 | 内置检测规则扩容 + ATT&CK 基准清单扩充 | 补 **18 条内置规则**并各配 1 正 1 负样本，重点补齐**原本完全空白的影响（Impact）战术**（勒索加密 / 破坏恢复 / 服务停摆 / 数据破坏）与凭证访问（LSASS 转储、SAM·NTDS 导出、文件内搜口令）、清空事件日志、账户建号与加组等高价值缺口；新增技术进基准清单时标 `origin: project`，与外部参考集原有 27 项**分开统计**，不让自选清单冒充外部标尺；门禁从 85/85·56/56 提升到 **123/123·74/74、TP 111、FP 0 / FN 0**，精确率与召回率保持 100%；并修掉 `db.destructive_query` 把日常 `DELETE ... WHERE` 判成 high 的误报（详见同轮 CHANGELOG） | 已完成 | 2026-09-24 |
| P3-04 | MCP 接口（外部 AI 客户端直查分析结果） | 先做 P3-03 再评估：把「查事件 / 查证据 / 看覆盖度 / 看台账」暴露为 MCP 只读工具，供 Claude Code、Cursor 等客户端调用 | 待定 | — |

**P3-01 交付记录**（2026-09-22）：与最初设想相比**范围收窄并说明理由** —— 原计划「外部样本纳入仓库作为独立基准」，实际改为**只引用技术清单、不打包第三方样本**（规避许可与恶意样本处置风险，也避免仓库膨胀）。交付物：`app/services/attack_coverage.py` + `evaluation/attack-benchmark.json`（27 项技术）+ `scripts/attack_coverage.py` + `GET /api/rules/attack-coverage` + `docs/attack-coverage-report.md`；并补齐清单里最后两个缺口 —— **T1059.001 PowerShell**（编码命令 / 隐藏窗口组合，high）与 **T1059.003 Windows Command Shell**（文档 / 压缩包启动 cmd，medium），各配正样本与负样本。门禁 78/78 用例 · 59/59 规则 · TP 88 · FP 0 · FN 0。

> ⚠️ 覆盖报告到 **120/120** 只是「这份清单补齐了」，不是检测能力到顶：清单 120 项（外部参考集原有 27 + 本项目补充 93），ATT&CK Enterprise 有 200+ 技术；且新加入的 75 项**只有规则、没有本地正样本**（46/120 有样本），下一步的价值在**给它们补样本**，而不是宣布满覆盖。

**为什么新增这些条目**（2026-09-22 对标 GitHub 同类项目后的结论，star 数截至当日；P3-01 已完成，P3-02/03 为主线，P3-04 待定）

| 类别 | 代表项目（Star） | 它强在哪 | 我们的差距 |
|---|---|---|---|
| SIEM / 采集平台 | [wazuh](https://github.com/wazuh/wazuh)（17k）、[loki](https://github.com/grafana/loki)（29k）、[signoz](https://github.com/SigNoz/signoz)（32k）、[graylog](https://github.com/Graylog2/graylog2-server)（8.1k） | 采集代理、索引、海量检索、告警 | 只支持手动上传单批日志；**这是定位差异，不追** |
| AIOps / 告警治理 | [keep](https://github.com/keephq/keep)（12.3k） | 告警融合、AI 关联、工作流 | 无告警接入与工作流 |
| 检测规则库 | [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma)（11k）、[Splunk security_content](https://github.com/Splunk/security_content)（1.7k） | 数千条规则、跨平台、有转换工具链 | **59 条（52 内置 + 7 Sigma），量级差距仍在 → P3-02** |
| Windows 事件检测 | [chainsaw](https://github.com/WithSecureOpenSource/chainsaw)（3.7k）、[hayabusa](https://github.com/Yamato-Security/hayabusa)（3.4k）、[LogonTracer](https://github.com/JPCERTCC/LogonTracer)（3.2k）、[Zircolite](https://github.com/wagga40/Zircolite)（853） | Sigma 原生、极快、覆盖全 | 规则量与样本量差距，实现速度已接近 |
| 攻击样本集 | [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)（2.6k）、[EVTX-to-MITRE-Attack](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack)（642） | 按 ATT&CK 组织、可复现 | 只有 4 个整份真实日志用例（其中 2 个攻击链 family）；已用其技术清单做覆盖尺子 → **P3-01 已完成**，缺口即「清单本身只有 27 项」 |
| AI 研判 / SOC Agent | [AiSOC](https://github.com/beenuar/AiSOC)（2.4k）、[Vigil](https://github.com/Vigil-SOC/vigil)（311）、[SecurityClaw](https://github.com/SecurityClaw/SecurityClaw)（272）、[EFF-Monitoring](https://github.com/Fausto-404/EFF-Monitoring)（46） | Agent 编排、多 Agent 分工、**研判审查台账**、MCP 接入 | 有 `ai_tool_trace` 但只展示、不留痕 → **P3-03 / P3-04** |
| 日志解析研究 | [loghub](https://github.com/logpai/loghub)（2.9k）、[logparser](https://github.com/logpai/logparser)（2k）、[loglizer](https://github.com/logpai/loglizer)（1.4k） | Drain 等标准算法 + 公开数据集基准 | 自研模板挖掘，没有公开基线对比 |
| 情报联动 | [MISP](https://github.com/MISP/MISP)（6.4k） | IOC / 威胁情报共享 | 无任何上下文富化（IOC、地理位置、资产库） |

结论：**同赛道里 star 最高的是「采集平台」和「规则库」，不是「AI 用法」。** 我们在「AI 判得准不准、说不说得清依据」上不落后（证据溯源校验、覆盖度三态是多数同类没有的），短板在**规则与样本的量**，其次是**AI 研判的留痕**。

### P8：对标 Zircolite 的界面与功能补强（2026-10-13 新增，当前最高优先级）

> 参考源码：`Zircolite-4.5.0.zip`（Svelte 5 + DuckDB-WASM 的离线检测工具，GUI 在 `gui/source`）。
> **仿照的是信息架构与交互（概览卡片、中轴双向时间轴、ATT&CK 网格、Top 榜单、左侧分区导航、规则分组视图、查询语法），
> 不搬技术栈**：本项目继续用 Vue 3 + FastAPI，配色沿用自身企业级语义色，并保留我们独有的能力
> （AI 研判、证据溯源、覆盖度三态、威胁情报、白名单、人工确认、provenance 分层导出）。

| 编号 | 任务 | 验收标准 | 状态 | 完成日期 |
|---|---|---|---|---|
| P8-01 | 概览看板 | 严重度卡片（事件数 + 规则数）、`N 个可疑事件` 标题、中轴双向时间分布（上=记录数、下=事件按风险分层）、ATT&CK 战术网格、Top 规则/主机/来源 IP；**事件数与记录数不混、事件与记录共用同一套桶边界** | 已完成 | 2026-10-13 |
| P8-02 | 检测视图（规则分组） | 按规则聚合的检测列表：等级分段、规则标题、战术、事件数、展开看规则元数据与命中明细，可跳转过滤 | 已完成 | 2026-10-13 |
| P8-03 | 左侧分区导航重排 | 顶部横向模块导航改为左侧分区导航（各视图一次只显示一个），窄屏退化为横向条；同时删除失效的滚动高亮与「折叠关联分析」死代码 | 已完成 | 2026-10-13 |
| P8-04 | ATT&CK 矩阵视图 | 战术 × 技术两级矩阵，计数取自规则映射；与「攻击链」模块并存、口径互不覆盖 | 已完成（含标签映射 + `GET /attack-matrix` + 矩阵视图；**顺带修掉标尺清单「凭证访问 / 凭据访问」不一致导致 8 项技术被静默丢列**） | 2026-10-13 |
| P8-05 | 搜索语法查询 | `字段:值` + `-排除` + 裸词全文，作用于本次分析的记录与事件；**不引入 SQL 引擎** | 已完成：`GET /search` + 查询视图 + 顶部搜索框；未知字段给出警告并退回按值全文匹配 | 2026-10-13 |
| P8-06 | 进程树视图 | 复用终端证据链的父子进程关联，展示进程树（PID/父 PID/关联证据） | 已完成：前端由终端链节点构建，只连日志中真实存在的父子关系，父进程缺失时标注而不猜 | 2026-10-13 |
| P8-07 | 字段侧栏与 facet | 日志明细增加字段侧栏（覆盖率 + 取值 Top + 加/排除筛选） | 已完成：`GET /facets` + 明细左侧字段栏；能走服务端筛选的走筛选，其余转搜索语法查询 | 2026-10-13 |

### 暂不纳入当前主线

| 项目 | 当前决定 | 原因 |
|---|---|---|
| 深度 WAF 分析 | 暂缓 | 普通用户终端通常不存在 WAF，当前优先服务 Windows/Sysmon 应急响应 |
| 网络设备类规则扩容（防火墙/WAF 深度检测） | 暂缓（2026-09-24 复核） | 同上优先级判断；且实测 WAF 日志的 URL 内容**已被 Web 规则覆盖**（Web 规则用 `exclude_log_types` 黑名单，本就作用于 `firewall_waf`），设备级规则收益有限 |
| 数据库 sqlserver / oracle 查询级检测 | 不做（2026-09-24 复核） | **当前支持的日志格式本身不含查询文本**：SQL Server errorlog 只有登录成败、Oracle alert.log 只有 ORA- 错误码，改解析器也提取不到。要做得先支持 SQL Server Audit / Oracle Unified Audit 等新日志格式，属**新增日志类型**而非补规则（见 `AGENTS.md` §33） |
| Redis 命令级检测（`FLUSHALL` / `CONFIG SET dir` / `MODULE LOAD`） | 数据源不支持 | redis-server 默认日志**不记录命令**（样本仅「Ready to accept connections」「Invalid password」）；需依赖 `MONITOR`、Redis 6+ ACL 日志或代理，属另一条数据链路 |
| 自动封禁、隔离、执行命令 | 不实现 | 超出只读日志分析和人工研判边界 |
| 复杂规则编辑器 | 暂缓 | 先完成规则预览、质量评估、启停和审计，再确定编辑模型 |
| SIEM 式采集 / 索引 / 海量存储 | 不实现 | 项目定位是「对一份日志做研判」，不是常驻采集平台；追规模会偏离主线 |
| 主机 Agent / EDR 传感（Wazuh 式） | 不实现 | 同上，属另一条产品线 |
| 把公开 star 数当目标 | 不适用 | 本项目未公开，star 是热度不是质量；只对标能力不追数字 |

### 终端场景取舍

WAF 暂不作为当前最高优先级。普通用户终端通常不产生 WAF 日志，现有 Firewall/WAF 键值解析和端口扫描规则保留作为扩展能力；后续优先投入 Windows/Sysmon、认证、进程、文件、注册表、DNS 和网络连接证据链。
