# AI 研判质量报告

- 用例：**10/11** 通过
- 门禁：**失败**
- 判据：真实模型（输出有随机性，不适合作为阻断式门禁）
- 规则集：内置规则 + Sigma 社区规则
- 用例范围：完整集（11 条）
- 模型：deepseek/deepseek-chat
- Prompt：内置 SYSTEM_PROMPT

- 准确率：**91%**（TP 6 / FP 1 / TN 4 / FN 0）
- 误报率：**20%**（1/5 条正常用例被判为可疑）
- 漏报率：**0%**（0/6 条异常用例未被判为可疑）

| 用例 | 家族 | 判定 | 风险等级 | 行为数 | 引用覆盖率 | 未通过项 |
|---|---|---|---|---|---|---|
| normal-health-check | 核心研判（正常 / 异常 / 证据不足 / 多事件 / 误报） | 通过 | info | 1 | 100% | — |
| obvious-sensitive-path | 核心研判（正常 / 异常 / 证据不足 / 多事件 / 误报） | 通过 | medium | 1 | 100% | — |
| insufficient-evidence | 核心研判（正常 / 异常 / 证据不足 / 多事件 / 误报） | 通过 | info | 0 | n/a | — |
| correlated-failures-then-success | 核心研判（正常 / 异常 / 证据不足 / 多事件 / 误报） | 通过 | high | 2 | 100% | — |
| benign-monitor-polling | 核心研判（正常 / 异常 / 证据不足 / 多事件 / 误报） | 通过 | info | 0 | n/a | — |
| no-timestamp-but-visible-anomaly | 边界与退化输入（无时间戳 / 字段缺失 / 截断） | 通过 | medium | 1 | 100% | — |
| missing-status-code | 边界与退化输入（无时间戳 / 字段缺失 / 截断） | 通过 | medium | 1 | 100% | — |
| truncated-mid-line | 边界与退化输入（无时间戳 / 字段缺失 / 截断） | **失败** | medium | 1 | 100% | risk_level_acceptable |
| truncated-after-threshold | 边界与退化输入（无时间戳 / 字段缺失 / 截断） | 通过 | medium | 1 | 100% | — |
| one-anomaly-among-thousands | 规模（大日志） | 通过 | medium | 1 | 100% | — |
| all-benign-at-scale | 规模（大日志） | 通过 | info | 0 | n/a | — |

## 失败明细

### truncated-mid-line

> 最后一行被截断，URL 不完整。规则不命中残缺串是**正确**的：
不能凭 `/.env HTTP` 猜测意图。真正的失败是崩溃或把残缺串当成完整证据。


- `risk_level_acceptable`：risk_level='medium'，可接受 ['info', 'low']


## 不可评估项

以下 3 条用例没有输出行为，引用覆盖率**不可评估**（不记为 100%，避免「什么都没输出」被当成满分）：

- insufficient-evidence
- benign-monitor-polling
- all-benign-at-scale
