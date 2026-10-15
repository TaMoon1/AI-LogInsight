# AI 研判 Token 成本模型与优化

本文说明 AI 研判的 token 成本从哪来、各项优化如何生效、以及如何自行复测。
优化实现位于 `backend/app/services/ai.py` 与 `backend/app/services/sanitizer.py`。

## 1. 成本模型

Chat Completions 协议是**无状态**的：每轮请求都必须把
`system + 全部历史 user/assistant/tool 消息`整份重发。因此一次研判的实际输入成本是

```
累计输入 = Σ(第 i 轮实际发送的消息体)     i = 1..轮次
```

而不是「首轮上下文 × 1」。工具调用轮次因此是**乘法级**的成本杠杆：

| 场景 | 首轮上下文 | 轮次上限 | 未优化累计输入 |
| --- | --- | --- | --- |
| access.log（6591 记录 / 7 事件） | 242 KB | 4 | 约 1.67 MB ≈ 83 万 tokens |
| 安全.evtx（4132 记录 / 9 事件） | 340 KB | 4 | 约 1.76 MB ≈ 88 万 tokens |
| 域控 XLSX（12510 记录 / 3955 事件） | 648 KB | 4 | 约 4.45 MB ≈ 222 万 tokens |

中文 JSON 大致 **2 字节 = 1 token**。

## 2. 上下文构成（优化前）

以域控导出为例，648 KB 的构成：

| 区块 | 体积 | 占比 | 说明 |
| --- | --- | --- | --- |
| `events` | 383 KB | 59% | 80 个抽样事件，含原始证据 |
| `records_sample` | 189 KB | 29% | 200 条分层抽样记录 |
| `timeline` | 39 KB | 6% | 事件与证据合并的时间线 |
| `tool_results` | 14 KB | 2% | 自动预取的 4 个工具结果 |
| 其余分析块 | 30 KB | 5% | 元数据、统计、覆盖度、实体、模板等 |

此外每轮固定携带：**System Prompt 3.5 KB + 工具 JSON Schema 4.3 KB**（不随日志变化）。

## 3. 已实现的优化

### 3.1 工具结果指针化

自动预取的 4 个工具里，`log_metadata` / `log_statistics` / `timeline` / `query_events`
的返回与上下文的 `metadata` / `statistics` / `timeline` / `events` **同源**，
两边都发等于同一份数据每轮付两次钱。

现在 `_run_auto_tools()` 把这些结果换成**摘要指针**（`data_in` + `note` + 计数锚点），
告诉模型「数据在哪个字段、总数是多少」。工具仍然真实执行，`trace` 轨迹完整保留，
前端展示不受影响。实测 `tool_results` **9733 → 1121 字节（−88%）**。

### 3.2 多轮历史裁剪（收益最大）

`complete_with_tools()` 从第二轮起，把首轮那条超大 user 消息替换成
**摘要占位**（`_history_context_placeholder()`）：
保留日志类型、总数、时间范围、覆盖度、风险等级、事件数、统计与说明字段，
丢掉大块原始原文（可用 `query_records` / `query_evidence` 按需取回）。

实测同一份 243 KB 上下文：

```
第 1 轮  243,477 字节   （完整上下文）
第 2 轮    5,326 字节   （摘要占位 + 工具结果）
第 3 轮    7,679 字节   （摘要占位 + 工具结果）
```

只对超过 `_HISTORY_SHRINK_THRESHOLD`（20 KB）的上下文做替换：小上下文重发成本本来就低，
替换反而可能让模型丢细节。

### 3.3 事件证据按风险分档

`events` 是最大区块，其中 `evidence_items[].raw` 又是大头。低风险事件几乎没有深挖价值，
因此证据条数按风险给：

| 风险等级 | 证据条数 |
| --- | --- |
| critical / high | 5（完整） |
| medium | 3 |
| low | 2 |
| info | 1 |

证据条目数减少**不等于丢证据**：每个事件都带 `evidence_count` 表示证据总数，
模型可按 `event_id` 调 `query_evidence` 取回未展示的部分。

### 3.4 记录样本字段白名单

`slim_records()` 按日志类型挑选字段（`sanitizer.record_sample_fields()`）：

- 保留判定字段（`source_ip` / `status` / `url` / `username` / `action` / `result` 等）；
- 终端类日志额外保留 `process_image` / `command_line` / `parent_image` / `query_name` 等，
  否则 Sysmon 规则证据会被裁掉；
- 数据库日志额外保留 `database` / `query` / `client_ip` 等；
- 剔除派生字段（`timestamp_iso` 与 `timestamp` 同源）、体积字段（`correlation_basis`）；
- 白名单外的自定义字段**仍保留**，避免解析器后续新增字段被静默丢弃。

体积下降约 19%（`raw` 原文占样本多数，压缩空间主要在那儿）。

### 3.5 轻量模式

`_is_light_context()` 判定条件：**没有命中任何事件，且覆盖完整**
（`coverage.limitation` 为空、`parse_failures == 0`、`retention_drops == 0`）。

命中时：

- 记录样本配额降到 `LIGHT_SAMPLE_LIMIT`（60 条，正常为 200 / 大日志 500）；
- 工具轮次收到 `CLEAN_LOG_TOOL_ROUNDS`（1 轮）；
- `records_sample_note` 明确写明「未命中任何检测规则且覆盖完整，因此只提供精简样本，
  这不等于日志正常」——避免模型把精简当成「没问题」。

刻意要求覆盖完整：覆盖不完整时「没事件」可能只是没解析出来，
这时恰恰需要更多原始记录让模型发现盲区。

### 3.6 缓存友好排序

`_order_context_for_cache()` 把字段重排为**稳定 → 易变**：
元数据、统计、覆盖度、结论在前；事件、样本、时间线、证据链、预算说明在后。

只改顺序、不改内容，对模型语义无影响。prompt caching 按前缀命中，
稳定前缀越长，后续轮次可复用的缓存越多（DeepSeek 命中缓存约按 1/10 计价）。

### 3.7 预算校验收口

修复了一个缺陷：`tool_results` 原先在 `_fit_context_budget()` **之后**才挂载，
导致这部分体积既不参与削减、也不计入硬上限（等于绕过预算）。

现在 `request_ai_judgement()` 的顺序是：

```
build_ai_context()  →  _run_auto_tools()  →  挂载 tool_results  →  _fit_context_budget()
```

`tool_results` 也加入了「预算不足时优先丢弃」的序列（它与主块同源，丢掉只是少一份副本）。
说明字段的预留量改为按预算比例给（`max(512, min(budget//20, 4096))`），
并在删块后仍越界时把说明收缩为短提示，而不是直接判失败。

### 3.8 前缀缓存接入

3.6 的排序只是结构准备，真正的缓存还得让请求带上服务端认得的信号。
两类服务端的语义不同，因此**按 base_url 分流**（`_needs_explicit_cache_marker()`）：

| 服务端 | 缓存方式 | 我们的处理 |
| --- | --- | --- |
| Anthropic / OpenRouter | 必须**显式**标记 | 在 system prompt 上打 `cache_control: {"type":"ephemeral"}` |
| DeepSeek / OpenAI | **自动**前缀缓存 | 不传额外字段，只靠 3.6 的稳定前缀排序 |

实现上由 `_post()` 统一处理：只对 `role == "system"` 的消息做转换，
**user 上下文不打标记**——它是易变内容（尤其第二轮起会被摘要占位替换），
打标记反而让缓存前缀每轮失效。

这与 3.6 是一对：排序让前缀稳定，标记让服务端认账。
DeepSeek 命中缓存约按 **1/10** 计价，因此这部分是纯收益。
可用 `AI_PROMPT_CACHE=false` 关闭，回归到纯字符串 content。

### 3.9 用量与缓存命中的可观测性

前八项都在**减少请求体积**，但「发得少」不等于「花得少」——真正决定账单的是
服务端计费口径，其中缓存命中量是唯一能直接验证 §3.8 是否生效的信号。
各家回传字段名不统一，因此新增 `_usage_tokens()` 归一化：

| 服务端 | 命中数字段 |
| --- | --- |
| DeepSeek | `prompt_cache_hit_tokens` / `prompt_cache_miss_tokens` |
| OpenAI | `prompt_tokens_details.cached_tokens` |
| Anthropic | `cache_read_input_tokens` / `cache_creation_input_tokens` |

归一化后的口径：`prompt_tokens` / `completion_tokens` / `cache_hit_tokens` /
`cache_miss_tokens` / `cache_write_tokens` / `cache_hit_ratio`。
`_merge_usage()` 再把各轮汇总成一份总账（含整体命中率与轮数），
以 `{"tool": "usage", "usage": {...}}` 的形式追加进 `ai_tool_trace`，
前端「AI 研判」模块的轨迹折叠区单独一行展示，**不计入工具调用次数**。

两条刻意的设计约束：

- **缺失就省略，不编造 0**。服务端不回传 usage 时返回空字典，命中率也不输出——
  把「未上报」显示成「命中 0%」会误导对缓存是否生效的判断。
- **降级路径也记账**。`complete()`（无工具的单次调用）与 Anthropic 单次调用
  同样写 `last_usage`，否则「模型未走工具」时成本就成了盲区。

### 3.10 工具返回结果裁剪（`query_terminal_chains`）

前面九项都在管**上下文**，但有一条路径不经过上下文预算：**模型按需调用的工具返回**。
实测发现这里藏着最大的一块——

| 工具 | 返回体积（终端类日志） |
| --- | --- |
| `query_terminal_chains` | **71.8 KB** |
| `query_records` | 8.5 KB |
| `query_uncovered_records` | 8.5 KB |
| `query_evidence` | 7.9 KB |
| `timeline` | 3.0 KB |
| 其余 4 个 | < 2.5 KB |

`query_terminal_chains` 一条链就顶掉整轮上下文（首轮 213 KB 的三分之一），原因有两个：

1. **节点带 23 个字段，其中绝大多数对该类型恒为 `null`**——`file_activity` 节点
   不会有 `destination_ip`，但原实现用 `**node` 全量展开，把一半以上体积花在 `null` 上；
2. **`timestamp` 与 `timestamp_iso` 是同一时刻的两种写法**，重复下发。

修法（`_chain_nodes()`）：

- 只保留 `CHAIN_NODE_FIELDS` 白名单里有**判定价值**的字段；
- **丢弃 null / 空串字段**——字段缺席比显式 `null` 更省，语义也更清楚；
- 丢弃重复的 `timestamp_iso`；
- 单链节点上限 `MAX_CHAIN_NODES = 40`，并在返回里给出 `node_limit_per_chain`。

顺手修掉一个**语义缺陷**：按 `kind` 过滤节点时，`record_count` 仍在报整链计数，
与返回内容不符。现在过滤后按实际返回节点数计，摘要里也点明「仅 X 节点」。

实测：

| 场景 | 裁剪前 | 裁剪后 | 降幅 |
| --- | --- | --- | --- |
| 含 100 节点终端链 | 71,645 B | 17,445 B | **−76%** |
| 同上（另一份） | 73,145 B | 17,445 B | **−76%** |
| IIS 3 条小链 | 2,685 B | 1,900 B | −29% |

**证据完整性未损失**：每个节点都保留 `evidence_id`（实测 40/40 节点均带），
整份输出的 `null` 字面量归零。回归测试：
`test_terminal_chain_tool_drops_null_fields_and_duplicate_timestamp`、
`test_terminal_chain_tool_caps_nodes_and_reports_the_cap`、
`test_terminal_chain_tool_record_count_matches_returned_nodes_when_filtered_by_kind`。

### 3.11 两块记录样本互斥（去重 ≈47% 重复字节）

拆解首轮上下文构成后发现，**记录样本占了 70%**，且两块之间存在近乎完全的重叠：

| 块 | access.log 占比 |
| --- | --- |
| `records_sample` | 49% |
| `uncovered_records_sample` | 21% |

原实现刻意允许两块重叠，理由是二者语义不同（「整体形态」与「规则未覆盖的部分」）。
但实测**重叠率 96%~97%**：

```
records_sample           194 条     67,094 B
uncovered_records_sample 200 条     68,786 B
两边重复                  188 条   ← 重叠率 96.9%
去重可省                        64,578 B（两块合计的 47.5%）
```

原因是规则覆盖少时，「从全体抽样」与「从未覆盖池抽样」几乎命中同一批记录——
两条不同的抽样路径，落到同一群记录上。

**关键判断**：重叠的意图是保留**两种视角**，而不是把同一批原文发两遍。
视角靠 `records_sample_note` 里的计数表达（命中规则 N 条 / 未覆盖 M 条），
明细则各出一份、互不重复。因此让 `uncovered_records_sample` 在抽样时
排除已进入 `records_sample` 的记录，并要求两块 **id 交集为空**。

实测（并集 = 两块合起来能看到的记录种类）：

| 日志 | 并集（前） | 并集（后） | 体积（前） | 体积（后） | 降幅 |
| --- | --- | --- | --- | --- | --- |
| access.log | 213 | **213** | 148,345 B | 117,738 B | **−21%** |
| 1.log（306 条） | 207 | **207** | 175,776 B | 92,482 B | **−47%** |
| windows-event-kv.log | 207 | **207** | 181,701 B | 95,587 B | **−47%** |

**并集完全不变**——去重的只是重复字节，模型能看到的记录种类一条没少。
回归测试：
`test_record_samples_are_mutually_exclusive`（交集为空 + note 如实说明）、
`test_record_sample_union_is_not_shrunk_by_dedup`（并集不缩水）。

### 3.12 关于「按模型自适应预算」：实测后决定不做

原计划把固定的 `AI_CONTEXT_MAX_BYTES`（2 MB）改成按模型上下文上限自适应。
实测后**放弃**，因为该预算在真实数据里从不构成瓶颈：

| 场景 | 上下文 | 占 2 MB |
| --- | --- | --- |
| 典型小日志（14 份样本） | 6–26 KB | 0.3%–1.3% |
| access.log（6591 条） | 213 KB | 11% |
| 安全.evtx（4132 条） | 215 KB | 11% |
| 域控 XLSX（12510 条 / 3955 事件） | 613 KB | **31%（实测最大）** |

它的真实职责是**防跑飞**（源自一次真实的 HTTP 400「maximum context length」拒绝），
不是限流阀门。改成自适应只会增加配置面与失败模式，去解决一个不发生的问题；
若顺手调紧默认值，反而可能拒掉合法日志而省不下任何成本。故保持固定值并记录依据。

### 3.13 `query_records` 按查询字段投影下发

**问题**：`query_records` 的下发字段是固定的 21 项白名单 `RECORD_QUERY_FIELDS`，
与模型的查询条件无关。模型问「`username=root` 的记录有哪些」时，
每条记录仍会带回 `command_line`、`registry_key`、`query_name`、`process_image`
以及整条 `raw` 原文——既计费又与问题无关。

**先测后改**（合成 3000 条 sshd 日志，`limit=20` 满额返回）：

| 查询条件 | 改动前 | 改动后 | 降幅 |
| --- | --- | --- | --- |
| 不带 `field`（看全貌） | 6781 B | 6781 B | 0（刻意不动） |
| `field=source_ip` | 6780 B | 3587 B | **−47%** |
| `field=username` | 6732 B | 3546 B | **−47%** |
| `field=raw` | 6827 B | 5254 B | −23% |

**规则**（`_record_query_fields`）：

- 未指定 `field`，或 `field` 不在白名单内 → **原样返回完整白名单**，行为不变；
- 指定了 `field` → 投影裁剪，但：
  - `RECORD_QUERY_ALWAYS`（`evidence_id` / `record_id` / `timestamp`）**恒保留**，
    否则模型无法把结论挂到真实证据上；
  - 被查询字段本身恒保留；
  - `raw` 与解析明细**互斥**：查 `raw` 只给正文，查解析字段不给正文。

用合成日志实测 3000 条记录、六个不同查询条件，
每条返回记录均带 `evidence_id` 与 `record_id`；
`total_matched` 与 `limit` 无关（裁剪只影响体积，不影响命中口径）。

回归测试：
`test_query_records_without_field_keeps_the_full_whitelist`、
`test_query_records_narrowed_by_field_drops_unrelated_heavy_fields`、
`test_query_records_always_keep_the_evidence_anchor`（遍历 21 个字段逐个验证）、
`test_query_records_raw_and_parsed_fields_are_mutually_exclusive`、
`test_query_records_total_matched_is_independent_of_limit`。

另外在 System Prompt 中把「条数上限」讲清楚（`查到条数上限后从结果里看分布`），
避免模型因拿到 20 条就以为全集只有 20 条——
这条只是补一句约束，字节数基本不变。

### 3.14 修掉「轮次用尽时把最后一条 tool 结果挤出末尾」

**这是做 §3.13 时顺带发现的一个真实缺陷，与成本无关，但影响结论质量。**

`complete_with_tools()` 在轮次用尽后会追加一句收尾提示，
原文是「请直接输出最终 JSON 结论，不要再调用工具」。问题是它**无条件追加**：

```python
messages.append({"role": "user", "content": "请直接输出最终 JSON 结论，不要再调用工具。"})
```

而当模型每轮都在调用工具、直到轮次被用尽才停下时，
`messages` 的末尾恰好是**刚回填的 `tool` 结果**。追加这条 user 消息后，
`messages[-1]` 变成了 user 提示——按 Chat Completions 的语义，
模型看到的是「别再调工具了」而不是「你刚查到的证据」，最后一轮工具调用等于白花。

实测（1 轮预算、模型调 `query_events`）：

| | 修复前 | 修复后 |
| --- | --- | --- |
| 终局请求末尾 role | `user` | **`tool`** |
| 模型能看到的内容 | 「不要再调用工具」 | **刚取回的事件证据** |

**修法**：新增 `_has_open_tool_round()` 判断消息是否停在「刚回填完工具结果、
模型尚未表态」的位置；仅当**不**处于该位置时才追加提示。
收尾文案也从「不要再调用工具」改为「请基于已获取的证据输出最终 JSON 结论」——
轮次用尽本就不该再要求模型收敛，只应提示可以作答。

回归测试：`test_exhausted_tool_round_does_not_bury_the_last_tool_result`
（已反向验证：移除守卫后该测试会失败）、
`test_exhausted_round_appends_hint_when_model_already_stopped_calling_tools`。

### 3.15 关于「记录样本增量发送」：实测前提不成立，决定不做

原计划：多轮时只发「新出现的记录」，而不是整批样本。
**实测后放弃，因为这个优化的前提已经不成立。**

关键在于第二轮起首轮那条超大 user 消息被替换为**摘要占位**（§3.2），
而占位里**不含任何记录明细**。实测三份真实日志：

| 日志 | 首轮样本明细 | 第二轮起占位中的样本明细 | 占位里的 note |
| --- | --- | --- | --- |
| access.log（6591 条） | `records_sample` + `uncovered_records_sample` ≈ 118 KB | **无** | 171 B |
| 安全.evtx（4132 条） | 101 KB | **无** | 171 B |
| 域控 XLSX（12510 条） | 148 KB | **无** | 170 B |

也就是说：**第二轮之后的请求里根本没有记录样本可供「增量发送」**，
只剩一句 170 字节的计数说明（「共 N 条，命中规则 X 条、未覆盖 Y 条…」）。
所谓增量发送能省的，最多是这句话里的计数——

再看占比。把占位**整个归零**（理论上限，实际不可能）能省多少：

| 日志 | 4 轮累计 | 归零可省 | 占比 | 8 轮累计 | 归零可省 | 占比 |
| --- | --- | --- | --- | --- | --- | --- |
| access.log | 194 KB | 12 KB | 6.2% | 210 KB | 28 KB | 13.4% |
| 安全.evtx | 156 KB | 14 KB | 9.2% | 175 KB | 34 KB | 19.2% |
| 域控 XLSX | 627 KB | 14 KB | **2.2%** | 645 KB | 32 KB | **4.9%** |

而这 2.2%~19.2% 是**把占位删光**换来的——真要做增量发送，还得保留计数与结论锚点，
实际收益趋近于零，却要引入「跨轮维护已发送记录 id 集合」的状态与相应失败模式。

**结论**：不是「收益小所以暂缓」，而是**这件事在现有架构下没有对象可做**。
记录样本的重复发送问题，早在 §3.2（历史裁剪）+ §3.11（两块互斥）时就已经解决掉了。
把它从待办里移除并留证，避免以后重复评估。

### 3.16 修复「工具轮次失败降级时丢失轨迹与用量」

做 §3.17 时先查数据，发现生产库里 **49 条已完成分析，0 条带用量记录**——
而用量展示功能早已上线。顺着这条线索查下去，找到了第二个真实缺陷。

**根因**在 `_request_content()` 的降级分支：

```python
try:
    return provider.complete_with_tools(...)
except Exception:
    pass          # ← 这里把 complete_with_tools 已累积的 trace 一起丢了
return provider.complete(...), []
```

`complete_with_tools()` 是**边执行边累积**的：第 3 轮请求失败时，
前 2 轮的调用轨迹与用量都已经真实发生（也真实计费了）。
但异常一抛，`pass` 让这些数据全部消失，降级路径固定返回空 `trace` `[]`。

后果有两层：

1. 前端「工具调用轨迹」整片空白；
2. **用量那条 `tool == "usage"` 也在 trace 里**，被一起丢掉——这才是
   实测 0/49 带用量的直接原因。

**修法**（三处，缺一不可）：

| 改动 | 作用 |
| --- | --- |
| `complete_with_tools()` 把 `trace` 挂到 `self.last_trace`，且**每轮都更新 `self.last_usage`** | 让已完成的部分在异常前就落在 provider 上 |
| 新增 `_recover_trace(provider)` | 从 provider 取回轨迹，并补一条 usage 记录 |
| 降级分支改为取回后返回 | 不再让 `pass` 抹掉已完成的调用 |

注意「每轮都更新 `self.last_usage`」这一条：原先只在**自然收敛**（模型主动停止调工具）
时才写 `last_usage`，中途失败就等于没有记录。改成每轮落一次才真正抗失败。

**反向验证**：把降级分支临时还原为 `pass`，
新增的 `test_tool_round_failure_keeps_completed_trace_and_usage` **会失败**
（`assert 'log_metadata' in []`），确认测试真的守得住缺陷，而不是恰好通过。

另修一个连带问题：`AnthropicProvider` 也补了 `last_trace` 字段，
避免上层统一取用时 `AttributeError`（它本身不走工具轮次）。

### 3.17 用量展示的历史趋势（`/api/ai/usage-history`）

最后一项待办：前端此前只显示**单次**研判的用量，没有跨分析对比。

**数据来源**：用量躺在 `analyses.result_json` 的 `ai_tool_trace` 里。
难点是**不能为了读一个用量字段就把整份结果反序列化**——单条 `result_json`
可达数百 KB，取 30 条就是十几 MB 的解析开销。

因此用 SQLite 的 json 函数**在库内定位**：

```sql
SELECT a.id, a.filename, a.log_type, a.created_at,
       (SELECT je.value
        FROM json_each(a.result_json, '$.ai_tool_trace') AS je
        WHERE json_extract(je.value, '$.tool') = 'usage'
        LIMIT 1) AS usage_json
FROM analyses AS a
WHERE a.status = 'completed' AND a.result_json IS NOT NULL
  AND json_valid(a.result_json)
ORDER BY a.created_at DESC LIMIT ?
```

**口径上的两条坚持**：

1. **缺失就是 `null`，绝不填 0。** `usage = None` 表示这次研判没留下账单，
   用 0 填充会把趋势图画出一个误导性的低谷（看起来像「这次几乎没花钱」）。
   接口同时返回 `with_usage` / `total_points`，前端如实注明
   「近 N 次中 M 次有账单，均值只按 M 次计算」。
2. **前端缺失点不画柱**，显式标注「无记录」，与「消耗很低」区分开。

**前端实现**（`App.vue`）：

- 列表页新增「AI 研判用量趋势」阻塞式柱状图，取最近 12 次；
- 两种视图可切换：**输入 tokens** / **缓存命中率**；
- 柱高取「相对本次序列最大值」的比例——比绝对值更便于横向比较；
- 缓存模式下缺 `cache_hit_ratio` 的点同样不画柱，不当成 0%。

**过程中修掉一个自己写出来的 bug**：柱高比例的分母原本写死 `Math.max(1, ...)`。
这对 token 计数是对的（不该除以 0），但缓存命中率是 0~1 的比例——
分母被兜底成 1 后，所有命中率柱子都会被压到不足 1% 高度、看起来全是空的。
改为按模式选择分母下限（`cacheMode ? 0.01 : 1`）后恢复正常。

回归测试 `tests/test_ai_usage_history.py`（7 个用例）锁定：
库内抽取、**缺失不填 0**、新的在前、limit 生效、
**均值排除无用量点**、端点字段结构、limit 参数校验。

## 4. 实测效果

复测命令：

```bash
cd backend && .venv\Scripts\python.exe scripts\bench_ai_context.py
```

| 文件 | 记录/事件 | 优化前首轮 | 优化后首轮 | 首轮降幅 | 优化前累计 | 优化后累计 | 总降幅 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| access.log | 6591 / 7 | 314 KB | 182 KB | **43%** | 1.67 MB | 258 KB | **85%** |
| 安全.evtx | 4132 / 9 | 334 KB | 142 KB | **58%** | 1.76 MB | 220 KB | **88%** |
| 域控 XLSX | 12510 / 3955 | 872 KB | 613 KB | 30% | 4.45 MB | 691 KB | **85%** |

另：System Prompt **3563 → 2895 字节（−19%）**，语义规则一条未删
（`test_system_prompt_keeps_every_hard_requirement_after_compression` 逐项锁定）。

## 5. 质量不降的保证

所有优化都遵循同一原则：**减少的是重复发送与低价值细节，不是证据本身**。

- 工具结果仍有完整 `trace`，只是不再重复进上下文；
- 高风险事件证据给满 5 条；
- 被裁掉的记录字段仍可通过 `query_records` 按条件查询；
- 轻量模式只在覆盖完整时启用，且明确告知「不等于正常」；
- 关键证据字段（进程、命令行、注册表、DNS、原始原文）一律保留。

回归门禁：

```bash
cd backend && .venv\Scripts\python.exe -m pytest tests -q
cd backend && .venv\Scripts\python.exe scripts\eval_rules.py
```

**成本 × 质量联合门禁**（P3 ⑤⑥）：上面两条只保证「规则质量」和「管线自洽」不退化，
但**降 Token 这件事本身没人守**。因此新增一条，把成本和质量放在同一张表里比：

```bash
cd backend && .venv\Scripts\python.exe scripts\eval_ai.py --smoke --baseline evaluation/artifacts/<基线>.json
```

四条规则（前两条失败时非零退出）：

| 情形 | 判定 | 理由 |
| --- | --- | --- |
| Token 涨超容差（默认 10%）+ 质量未提升 | **失败** | 多花钱没换来质量 |
| Token 降 + 质量下降 | **失败** | 省下的 token 是拿准确率换的 |
| Token 降 + 质量持平或提升 | 通过 | 真优化 |
| Token 涨 + 质量提升 | 通过，**记为观察项** | 值不值这个价钱是人的决定，门禁不代为判定成功 |

准确率涨但**误报率变差不算质量提升**（对安全产品是净损失）。

门禁比较 `tokens_total` / `tokens_first_round` / `context_bytes` / `evidence_sent` /
`accuracy` / `false_positive_rate` 六项，**不依赖具体压缩机制**——§3 里任何一类手段
（字段白名单、分层采样、去重、证据预算、摘要指针）生效时都必然落在其中某一列上。
基线取归档产物（`--artifacts` 落下的 JSON）里**同名 label**（模型 + Prompt）的运行。

**它刻意不是 `pytest` 断言**：确定性替身下质量恒为 1.0，任何合法的 Prompt 改动都会
只涨 token 不涨质量，自动断言会让门禁变成「禁止改 Prompt」。所以它是**发布门禁**
（人工触发）。守住静默失效风险的是另一条单测：
`test_gated_metric_names_match_the_metrics_payload`——指标模块改字段名而门禁读不到时
必须报错，而不是悄悄退化成「无法比较 → 不计为失败」。

## 6. 后续可做

（当前无待办项。）

> 已完成：prompt caching 按服务端分流接入（§3.8）；工具返回结果字段白名单裁剪（§3.10）；
> `query_records` 按查询字段投影下发（§3.13）；用量与缓存命中可观测（§3.9）并补齐
> **跨分析历史趋势**（§3.17）。
> **成本 × 质量联合指标（P3 ①②③④⑤⑥）**：总 / 首轮 / 工具轮次 / 缓存命中 Token、
> 上下文字节数、耗时、逐事件与逐证据 Token 归属、证据下发 / 引用 / 覆盖率 / 遗漏率、
> 单次估算成本；`app/services/ai_metrics.py` 刻意不 import 项目内任何东西，可被单测直接驱动。
> **两类数字在数据结构上就分开**：真实账单（服务端 `usage`，拿不到就是 `null`）与估算归属
> （按上下文体量分摊，服务端不会告诉你「第 3 个事件花了多少 token」）不共用键——
> 把估算当账单看会让成本优化得出反向结论。**不内置厂商价格**（价格会变，写死会悄悄算错）：
> 单价从 `AI_PRICE_INPUT_PER_M` / `AI_PRICE_OUTPUT_PER_M` / `AI_PRICE_CACHE_HIT_PER_M` 读取，
> 未配置时 `cost.estimated` 为 `null` 并附说明，**不填 0**。
> 已修复：轮次用尽时收尾提示挤掉最后一条 tool 结果（§3.14）；
> **工具轮次失败降级时丢失已完成的轨迹与用量**（§3.16）。
> 已评估后**不做**：「记录样本增量发送」——前提不成立，记录样本在第二轮起已完全不下发（§3.15）；
> 按模型自适应预算——实测该预算从不构成瓶颈（§3.12）。

## 7. 评估后决定不做的项（留证，避免重复评估）

| 项 | 结论 | 依据 |
| --- | --- | --- |
| 记录样本增量发送 | 不做 | 第二轮起样本明细已完全不重发（仅剩 170 B 的 note），没有「增量」可发（§3.15） |
| 按模型自适应上下文预算 | 不做 | 固定 2 MB 在真实数据里最大仅占 31%，职责是防跑飞而非限流（§3.12） |

