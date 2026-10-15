# 导入规则检测效果验证报告

生成时间：2026-10-14T10:24:32+08:00

本报告回答一个问题：**社区导入的 Sigma 规则有没有被逐条验证过、没验证的话该怎么办**。

## 一、先把结论说清楚

- 导入规则总数：**2198 条**（内置规则 74 条另有本地标注语料，不计入本报告）。
- **不需要逐条人工验证**，也不应该那样做：2198 条里绝大多数触发条件都是声明式的，机器可以自己构造样本去试。
- 真正需要人看的只有 **0 条**：判据是「机器试出来有问题」（0 条）与「在正常流量上就报」（0 条）。
- 另外 **2188 条在本地语料里从未命中**。这里必须再分一次：其中 **504 条**语料里连它要求的 EventID 都没出现过（例如它要求 Sysmon EventID 7，而语料里没有这类事件），它们的「未命中」说明不了任何事；剩下 **1684 条**有同类日志却没命中，才是真正「待补样本」的规则。两类都如实标为未验证，不冒充已验证。

## 二、三层验证各自回答什么

| 层 | 做法 | 回答的问题 | 需要人工吗 |
|---|---|---|---|
| 层 1 合成正样本 | 从规则谓词树反推一条必然满足它的记录，再用规则引擎端到端跑一次 | 这条规则的逻辑在我们的记录模型上能不能成立 | 不需要 |
| 层 2 真实语料回放 | 用本地真实日志把全部规则跑一遍 | 它有没有在真实数据上命中过 | 不需要 |
| 层 3 负样本筛查 | 在「正常流量」语料上跑 | 它会不会在正常流量上乱报 | 不需要 |

> 三层都只描述**规则的可验证状态**，都不构成「安全 / 不安全」的结论。层 1 通过只说明「能触发」，不说明「触发它的事件真的是攻击」。

## 三、层 1：合成正样本（端到端可触发）

覆盖 2198 条，其中：

| 结果 | 条数 | 占比 | 含义 |
|---|---|---|---|
| 端到端可触发 | 1992 | 90.6% | 合成记录能过条件匹配并产出事件，规则逻辑成立 |
| **疑似缺陷** | 0 | 0.0% | 合成记录本该命中却没产出事件，需要人看 |
| 无法自动合成 | 206 | 9.4% | 条件是正则或跨记录关联，机器反推不出取值（**不是缺陷**） |

没有发现「能合成样本却触发不了」的规则。

### 无法自动合成的原因分布（不是缺陷）

| 原因 | 条数 |
|---|---|
| 字段 command_line：条件之间互相冲突，构造不出同时满足的取值 | 61 |
| regex 无法反推出取值 | 47 |
| 字段 ImageLoaded：条件之间互相冲突，构造不出同时满足的取值 | 24 |
| 字段 target_filename：条件之间互相冲突，构造不出同时满足的取值 | 15 |
| 字段 process_image：条件之间互相冲突，构造不出同时满足的取值 | 14 |
| 字段 registry_key：条件之间互相冲突，构造不出同时满足的取值 | 12 |
| 字段 ScriptBlockText：条件之间互相冲突，构造不出同时满足的取值 | 11 |
| 字段 Details：条件之间互相冲突，构造不出同时满足的取值 | 4 |
| 字段 status：条件之间互相冲突，构造不出同时满足的取值 | 2 |
| 字段 ImagePath：条件之间互相冲突，构造不出同时满足的取值 | 2 |

这类规则的条件是正则表达式或跨记录关联，机器无法保证反推出的取值一定匹配。它们的验证依赖层 2 的真实语料，或需要人工补样本。

## 四、层 2：真实语料回放

- 语料文件：**50 个**（本地 `sample_logs/`、`data/uploads/` 与 `evaluation/scenarios/`）
- 参与回放的记录：**16,759 条**（单文件上限 8,000 条）
- 在真实数据上命中过的规则：**10 条**（占 0.5%）
- 从未命中：**2188 条**（占 99.5%），拆成两类：
  - 语料里**没有**该规则要求的 EventID：**504 条**（未命中说明不了任何事）
  - 语料里**有**同类日志但未命中：**1684 条**（真正待补样本）

### 语料的日志类型分布（记录数）

| 日志类型 | 记录数 |
|---|---|
| `nginx_apache` | 13,395 |
| `windows_event` | 1,842 |
| `syslog` | 1,104 |
| `windows_evtx` | 170 |
| `postgresql` | 42 |
| `csv` | 42 |
| `mongodb` | 36 |
| `mysql` | 35 |
| `ssh` | 25 |
| `json` | 21 |
| `redis` | 11 |
| `sqlserver` | 11 |

> 导入规则绝大多数面向 **Windows / Sysmon 事件**（要求 `status` 等于某个 EventID），而本地语料以 Linux 认证、Web 访问与服务日志为主。因此「层 2 几乎不命中」主要是**语料与规则的日志类型错配**，不是规则本身有问题——这也是本项目 ATT&CK 标尺里那 75 项新技术的样本还缺着的同一个原因。

### 命中次数最高的规则（真实命中，不是误报）

| 规则 | 等级 | 命中记录数 |
|---|---|---|
| `sigma.00bb5bd5-1379-4fcf-a965-a5b6f7478064` | low | 156 |
| `sigma.953d460b-f810-420a-97a2-cfca4c98e602` | medium | 94 |
| `sigma.b28e58e4-2a72-4fae-bdee-0fbe904db642` | high | 12 |
| `sigma.7745c2ea-24a5-4290-b680-04359cb84b35` | medium | 4 |
| `sigma.9fbf5927-5261-4284-a71d-f681029ea574` | medium | 4 |
| `sigma.863218bd-c7d0-4c52-80cd-0a96c09f54af` | high | 4 |
| `sigma.c09dad97-1c78-4f71-b127-7edb2b8e491a` | medium | 4 |
| `sigma.19aa4f58-94ca-45ff-bc34-92e533c0994a` | medium | 4 |
| `sigma.5513deaf-f49a-46c2-a6c8-3f111b5cb453` | high | 2 |
| `sigma.65354b83-a2ea-4ea6-8414-3ab38be0d409` | high | 1 |

> 语料里已经有 Sysmon 与 Windows 安全事件的 EventID（4624/4625/4634/11/1/3…），所以「1684 条有同类日志却没命中」不代表规则写错了：它们的额外条件（`Image` / `CommandLine` / `TargetFilename` 的具体取值）在现有日志里本来就不存在——现有日志里没有 mimikatz、没有 Cobalt Strike。这类规则的可信度**低于**有真实命中的规则，系统里也按「未本地验证」标注。要推进它们，正解是**补一段真实的恶意样本**，而不是改规则。

### 优先级建议

按「等级高 + 有同类日志却未命中」排。这批补一段真实样本就能立刻验证，性价比最高：

| 规则 | 等级 | 标题 |
|---|---|---|
| `sigma.0d18728b-f5bf-4381-9dcf-915539fff6c2` | critical | Suspicious Cobalt Strike DNS Beaconing - DNS Client |
| `sigma.1070db9a-3e5d-412e-8e7b-7183b616e1b3` | critical | Persistence Via Sticky Key Backdoor |
| `sigma.1de68c67-af5c-4097-9c85-fe5578e09e67` | critical | WCE wceaux.dll Access |
| `sigma.2111118f-7e46-4fc8-974a-59fd8ec95196` | critical | DiagTrackEoP Default Login Username |
| `sigma.24e3e58a-646b-4b50-adef-02ef935b9fc8` | critical | Hacktool Execution - Imphash |
| `sigma.25b9c01c-350d-4b95-bed1-836d04a4f324` | critical | Moriya Rootkit - System |
| `sigma.2704ab9e-afe2-4854-a3b1-0c0706d03578` | critical | HackTool - Dumpert Process Dumper Execution |
| `sigma.2f7979ae-f82b-45af-ac1d-2b10e93b0baa` | critical | Potential DCOM InternetExplorer.Application DLL Hijack |
| `sigma.2fdefcb3-dbda-401e-ae23-f0db027628bc` | critical | Sticky Key Like Backdoor Execution |
| `sigma.3268b746-88d8-4cd3-bffc-30077d02c787` | critical | HackTool - Empire PowerShell UAC Bypass |
| `sigma.39698b3f-da92-4bc6-bfb5-645a98386e45` | critical | Win Susp Computer Name Containing Samtheadmin |
| `sigma.42333b2c-b425-441c-b70e-99404a17170f` | critical | HackTool - Sliver C2 Implant Activity Pattern |
| `sigma.48d91a3a-2363-43ba-a456-ca71ac3da5c2` | critical | Audit CVE Event |
| `sigma.4ac47ed3-44c2-4b1f-9d51-bf46e8914126` | critical | TrustedPath UAC Bypass Pattern |
| `sigma.4f647cfa-b598-4e12-ad69-c68dd16caef8` | critical | DumpStack.log Defender Evasion |
| `sigma.5589ab4f-a767-433c-961d-c91f3f704db1` | critical | Potential SMB Relay Attack Tool Execution |
| `sigma.55e29995-75e7-451a-bef0-6225e2f13597` | critical | Potential Credential Dumping Via LSASS SilentProcessExit Tec |
| `sigma.614a7e17-5643-4d89-b6fe-f9df1a79641c` | critical | Wmiprvse Wbemcomn DLL Hijack - File |
| `sigma.7679d464-4f74-45e2-9e01-ac66c5eb041a` | critical | HackTool - SecurityXploded Execution |
| `sigma.797011dc-44f4-4e6f-9f10-a8ceefbe566b` | critical | WMI Backdoor Exchange Transport Agent |

## 五、层 3：负样本筛查（判定过宽）

没有导入规则命中「正常流量」语料。

## 六、两层合起来看：每条规则处在哪一档

| 状态 | 条数 | 含义 | 下一步 |
|---|---|---|---|
| 机器可触发 **且** 真实语料命中过 | 10 | 最高可信：逻辑成立，且在真实数据上跑得动 | 无需动作 |
| 机器可触发，但真实语料未命中 | 1982 | 逻辑成立，缺真实样本证明它在真实数据上会响 | 补一段真实/拟真样本即可升级 |
| 机器构造不出样本，语料也没命中 | 206 | 两个方向都没有证据 | 人工看条件或补样本 |

## 七、人工要做什么

按上表汇总，人工只需要处理这几类：

1. **疑似缺陷 0 条**：看合成记录为什么没触发——多半是字段映射没接上，或者条件写死了互相矛盾。
2. **判定过宽 0 条**：看命中的正常用例是不是真的正常，是的话给规则加聚合条件或收紧谓词。
3. **从未命中且等级为 high/critical 的规则**：优先补一段真实样本；暂时补不上就保持「未本地验证」标注，不要当成已验证。

其余规则（层 1 可触发、层 2 有真实命中、层 3 无过宽）**不需要人工逐条看**：机器已经把「逻辑成立」「真实数据上跑得动」「不在正常流量上报」三件事都验证了。
