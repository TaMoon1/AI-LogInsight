# CHANGELOG

本文件记录 AI-LogInsight 每次代码变更的内容、原因、验证证据与遗留问题。
日常进度汇总见 `PROGRESS.md`，开发约束见 `AGENTS.md`。

---

## 2026-10-15

### Windows 便携版（解压即用）与打包链路

用户要求「生成一个 exe（即拆即用，并保留源码）」。选型经确认：**one-dir 便携目录 + ZIP**、
**后端托管前端 dist（单进程）**、**GitHub 只准备本地文件（不推送远程）**。

**改动**

| 文件 | 内容 |
| --- | --- |
| `backend/app/runtime_paths.py`（新增） | 路径双模式统一入口：`backend_root()`（rules/evaluation）、`project_root()`（sample_logs、前端 dist）、`data_root()`（可写数据；打包后 = exe 同级 `data/`）、`env_files()`（`.env` 候选）。源码模式返回值与改造前**逐项核对一致** |
| `database.py` / `main.py` / `ai.py` / `ai_eval.py` / `attack_coverage.py` / `rule_quality.py` / `rules_engine.py` / `sigma_import.py` / `threat_intel.py` | 10 处 `Path(__file__).resolve().parents[N]` 改走 `runtime_paths`；`ai.py` 的 `.env` 读写改为写 exe 旁（`env_files()[0]`），并清掉因此失效的 `pathlib.Path` 导入 |
| `backend/app/main.py` | 文件末尾挂载 `frontend/dist`（`StaticFiles`，**在所有 API 路由之后注册**，`/api/*`、`/docs` 不被遮蔽；`dist` 不存在时跳过，纯 API 模式照常）。同时源码模式也支持「只起后端 + 打开 8000 端口」 |
| `backend/scripts/launcher.py`（新增） | 打包入口：加载 `.env`（不覆盖真实环境变量）→ 选空闲端口（`LOGINSIGHT_PORT`，默认 8000，占用则后移）→ 起 uvicorn → **服务可访问后**才开浏览器；`LOGINSIGHT_NO_BROWSER=1` 可关闭 |
| `backend/AI-LogInsight.spec`（新增） | PyInstaller 配置：`rules/`、`evaluation/`、`sample_logs/`、`frontend/dist/` 进 `_internal/`；`console=True`、`upx=False`（降低杀软误报）；excludes 去掉 tkinter/pytest/mcp 等 |
| `backend/scripts/build_exe.py`（新增） | 一键构建：前端构建检查 → PyInstaller → 补 `.env.example`/`使用说明.txt`/`data/` → 压 ZIP |
| `backend/requirements-build.txt`（新增） | 构建期依赖 `pyinstaller==6.22.3`（运行时不依赖，故与 `requirements.txt` 分开） |
| `README.md` | 新增「Windows 便携版（解压即用）」与「自行构建便携版」；本地运行补「前端构建后只起后端」 |
| `.gitignore` | 补 `build/`（PyInstaller 工作目录；`dist/` 原已忽略） |
| `THIRD-PARTY-NOTICES.md` | 新增 PyInstaller 条目（GPL-2.0 + 例外，仅构建期使用，exe 内嵌其 bootloader）；「不随仓库分发」补 `dist/`、`build/` |

**验证（便携版，全部实测）**

解压到仓库外的干净目录运行（`LOGINSIGHT_NO_BROWSER=1`，端口 8331）：

| 项 | 结果 |
| --- | --- |
| 启动 | 控制台横幅正常，`/api/health` 200 |
| 规则加载 | `/api/rules` 首次 **10.4s / 2371 条**（与源码模式 11.8s 同量级） |
| 前端 | `GET /` 200（0.06s，由后端托管 dist） |
| 文本日志 | 上传 `sample_logs/ssh/auth.log` 1.3s → medium / 1 事件 |
| EVTX | 上传 3.2 MB `安全.evtx` 23.3s → `windows_evtx` / 11 事件（`python-evtx` 在包内可用） |
| 数据落盘 | `loginsight.db`(8.1 MB) 与 `uploads/<id>/`（原始件 + 证据清单）均在 exe 同级 `data/` |
| 体积 | 目录 36.5 MB，ZIP 16.7 MB |

启动器行为单独验证：端口 8400 被占用 → 自动选 8401 ✓；`.env` 载入 4 项且**不覆盖**已存在的
`LOGINSIGHT_PORT` ✓；服务就绪后才调用浏览器打开 ✓。

**踩到的坑**

1. **pyyaml 的 C 加速真实模块是 `yaml._yaml`**（顶层 `_yaml` 只是兼容 stub）。只写
   `hiddenimports=["_yaml"]` 无效 → 打包版 YAML 退化为纯 Python 解析，规则加载
   10.4s → **23.3s**。改 `yaml._yaml` 后恢复。已核查 `_ssl`/`_sqlite3`/`httptools`/
   `websockets`/`_bz2`/`_lzma` 均正确进包。
2. `bundle_root()` 一度把「仓库根」与「backend/」混为一谈：`rules/`、`evaluation/` 在
   `backend/` 下，而 `sample_logs/`、`data/`、`.env` 在仓库根——拆成
   `backend_root()` / `project_root()` 两个函数后才对齐（源码模式逐项核对时发现）。
3. 首次加载 2371 条规则约 10s 是既有固有开销（非打包引入），前端首屏会有一次等待。

**回归**：`test_parser_archives_xml` / `test_detection_engine` / `test_evtx_standard_fields` /
`test_rule_metadata` / `test_rule_health` = **62 passed**；`test_analysis` / `test_rule_quality` /
`test_detection_coverage` = **138 passed**（合计 200 passed，源码模式无回归）。

### 便携版健壮性验证 + 发布工作流

**健壮性验证（继续解压到仓库外运行）**

| 场景 | 结果 |
| --- | --- |
| 中文 + 空格路径（`...\便携 测试 目录\AI-LogInsight`） | 规则 2371 条（10.0s）、`GET /` 200、上传 IIS 日志 1.2s → medium、`data/` 与 DB 正常落在该目录 |
| exe 旁 `.env` | 生效：端口由 `.env` 的 `LOGINSIGHT_PORT=8342` 决定，控制台正确显示配置文件路径；且不覆盖已存在的真实环境变量 |
| 从 `C:\` 启动（非 exe 目录为工作目录） | 服务正常，数据仍落在 exe 旁 |

**新增 `scripts/smoke_portable.py`**：启动 exe → 等就绪 → 查规则数（≥2000）与首页 →
上传示例日志 → 退出码判定。本地实跑通过（2371 条 / 首页 200 / 上传 medium 1 事件）。
CI 里原本写的是一段 PowerShell 冒烟脚本，因**本机 PowerShell 沙箱无法启动、无法校验其语法**，
改用这个 Python 脚本——它本地可复现、且顺带覆盖上传链路。

**新增 `.github/workflows/release.yml`**：推 `v*` 标签（或手动触发）时，先在 ubuntu 上跑
规则门禁（`eval_rules.py` / `rule_health.py`）与核心回归，再在 windows-latest 上构建前端与
便携版、跑同一个冒烟脚本，通过后把 ZIP 附到 Release 并上传构建产物。
**如实说明**：工作流的各条命令均已在本地等价执行过（`build_exe.py`、门禁、冒烟脚本），
但**工作流本身未在 GitHub Actions 上实跑过**——需要首次打 tag 时确认。

### 品牌标识替换：移除第三方 logo，改用项目自有标识

用户要求公开仓库不得出现第三方品牌标识。原品牌位用的是第三方品牌图（浅色 / 深色两版），
现改为项目自有的「AI日志分析工具」logo。

**素材处理**（源图 `AI日志分析工具logo_1.png`，1254×1254 RGBA，含明暗两版）

| 项 | 内容 |
| --- | --- |
| 选型 | 三张候选里选第 1 张：无损 PNG、明暗两版同一套图标语言、**不带副标题**（侧栏下方已有「安全日志分析平台」文案，再带一行会重复）；第 2 张无深色版，第 3 张浅色版元素过密，缩到 40px 会糊 |
| 裁切 | 浅色版取上半内容框 `(76,206,1181,480)`；深色版取下半内容框 `(128,817,1163,1086)`；均按 alpha/底色阈值定位，各留 10px 内边距 |
| 去底 | 浅色版原本就是透明底，仅清理 `alpha<24` 的噪点；深色版自带深蓝底 `(8,14,44)`，与界面深色侧栏 `#13232a` 色相差异明显（会露出色块），故**从四角泛洪抠底**——只清与边缘连通的背景，图标内部与文字不受影响 |
| 产出 | `frontend/public/logo-light.png`(918×240, 109KB) / `logo-dark.png`(876×240, 129KB)，两版宽高比 4.03 / 3.85 接近一致，显示尺寸统一（40px 高 → 约 153px / 146px 宽，侧栏可用宽度 176px，放得下） |
| 源图归档 | `docs/brand/logo-master.png`（1254×1254 原始文件，便于日后重新导出） |
| 验证 | 把两版分别合成到界面真实背景色（浅色 `#f8faf8` / 深色 `#13232a`）上出图检查：无底色方块、无毛边、明暗尺寸一致 |

**代码改动**

| 文件 | 内容 |
| --- | --- |
| `frontend/src/App.vue` | `brandLogo` 指向 `/logo-light.png` 与 `/logo-dark.png`；`alt` 由第三方品牌名改为「AI 日志分析工具」；注释同步 |
| `frontend/style.css` | 删除 `/* 第三方品牌标 */ .brand-mark-sxf`（红色渐变）——已无任何引用的死样式 |
| `PROGRESS.md` | 前端能力描述里的第三方品牌标改为「AI 日志分析工具品牌标（明暗两版，透明底）」 |
| 删除 | `frontend/public/` 下品牌位原用的两个图片文件，以及仓库根目录的同名冗余文件（无任何引用） |

**复查**：代码与素材中已无第三方品牌字样（行为基线的常用域名白名单里原本有两项该厂商域名，
一并移除，见下）；`docs/milestones/` 4 张里程碑图为装饰性图形，扫描无品牌红像素、不含 UI 截图，无需处理。

> 说明：`behavior_baseline.py` 的「常用域名后缀」白名单里原本含两项该厂商域名，已一并移除（公开发布不带入第三方品牌字样）。影响面：该域名不再被当作常见域名，行为基线可能对其解析多报一次外联信号，属预期内的极小代价。

**重建与验证**：前端重建 → 便携版重打（`AI-LogInsight-1.0.0-win64.zip` 16.7→**16.4 MB**，包内已无旧品牌素材、含新 logo）→ 冒烟通过（规则 2371 / 首页 200 / 上传 medium 1 事件）。

---

## 2026-10-14

### 开源发布准备（GitHub 公开）

用户决定以 **MIT** 协议把项目发布到 GitHub（运行环境先为本机演示，AI 按「配置了 key 才有」）。
本轮只做「不能公开」与「公开必需」的部分，不改任何业务功能。

**改动**

| 项 | 内容 |
| --- | --- |
| `.gitignore` | 由 8 行补到完整版：新增 `*.log`（并对 `sample_logs/**`、`backend/evaluation/**` 加否定规则，保留示例日志与场景语料）、`*.db`、`*.sqlite3`、`*.zip`、`.workbuddy/`、`.workbuddy-ai/`、`tsconfig.tsbuildinfo`、`.env.local`、`.DS_Store` |
| 客户标识脱敏 | 6 个会被提交的文件共 28 处真实客户标识（内网网段、来源 IP、计算机账户）替换为项目既有示例网段与示例主机名，原值不再保留：`evaluation/corpus/domain-auth-export.yaml`、`tests/test_domain_controller_export.py`、`tests/test_analysis.py`、`scripts/bench_ai_context.py`、`app/services/ai.py` 注释、`CHANGELOG.md` |
| `LICENSE` | 新增 MIT |
| `THIRD-PARTY-NOTICES.md` | 新增：SigmaHQ 规则的 DRL-1.1 声明（署名 / URI / 许可链接）、Zircolite 4.5.0 的 LGPL-3.0 参考说明（未复制源码）、依赖清单生成命令、不随仓库分发的内容 |
| `README.md` | 顶部新增面向使用者的首页（定位 / 支持输入 / 快速开始 / AI 可选 / 已知限制 / 许可致谢）；原开发与规格文档**原文保留**、章节编号未变动（AGENTS.md 等处有 7 处 `README.md §N` 引用，重命名会全部失效） |
| `.github/workflows/ci.yml` | 新增：后端核心门禁（解析检测 / 规则质量与体检 / AI 最小回归集）、前端构建、全量套件（手动触发） |
| `backend/requirements.txt` | 显式声明 `pyyaml==6.0.3`——`rules_engine` / `sigma_import` / `rule_quality` 等直接 `import yaml`，此前仅靠 `uvicorn[standard]` 的 extras 顺带安装 |

**为什么不移动 `data/` 与两个 zip**：`data/loginsight.db`（209.6 MB）是运行库、
`data/uploads/` 的原始件支撑「原始日志下载 / 案件包导出」、两个 zip 是离线参考与重导源；
三者均已由 `.gitignore` 排除，移动反而破坏功能。

**验证证据**

| 项 | 结果 |
| --- | --- |
| 真实标识残留 | 按脱敏规则重扫全部入库文件 → 无残留；命中的只剩本地忽略目录 `.workbuddy/memory/*` 与运行库 `data/loginsight.db`（两者均不入库） |
| 密钥 | 精确形态 `sk-[0-9a-f]{32}` 全仓仅命中 `.env`；`git ls-files` 确认 `.env` 未入库 |
| 忽略规则 | `git check-ignore -v` 对 `.env` / `data/` / `*.log` / `*.zip` / `.workbuddy/` / `node_modules/` / `dist/` 全部命中 |
| 待提交清单 | 195 个文件；无 `data/`、无 `.env`、无 `*.zip`、无 `pytest_*.log`；最大文件 `rules/95-sigma-community.yaml` 6.02 MB |
| 语料完整性 | `yaml.safe_load` 后 3 条用例结构完好、无残留真实串 |

**遗留（发布前仍需人工决定）**

1. `.env` 内的真实 DeepSeek Key 需在服务商控制台**吊销并轮换**（文件已不入库，但 key 已存在于本机磁盘与多轮工具上下文）。
2. Git 提交身份当前为 `TaMoon1 <TaMoon1@example.com>`，`example.com` 占位邮箱不会关联 GitHub 账号。
3. 首页暂无界面截图：`docs/milestones/` 的 4 张截图拍摄于 2026-09-30，早于外观对齐改动，需重新截图。

### 续：把「按标准格式解析」推到全部日志类型

昨天只改了 EVTX。用户判定：「不该围着『不存在的字段』打补丁，而该按标准的**各类型**日志格式
把事件数据真正解析出来」。本轮把同一条原则推到其余类型。

**统一机制**：新增 `parser._named_fields(fields)` —— 把日志格式**自带的字段名**原样收下
（只保留有值的），与规范字段并存（规范字段在后、覆盖同名键）。判据是**格式是否自带字段名**，
不是「想不想要这个字段」。

| 类型 | 改动 |
|---|---|
| json / csv | `_parse_structured_records` 原先只认 `FIELD_ALIASES` 白名单（9 个规范字段），**其余键静默丢弃** → 现在全部原样收下。保留一处判断：一个对象里**没有任何**已知别名键时不建记录（`_looks_like_json` 很宽松，任何合法 JSON 都算，这条是「看起来不像事件」的守门） |
| iis | W3C `#Fields:` 声明的列全部收下（原先只取 c-ip / s-ip / cs-method / cs-uri-stem / sc-status） |
| firewall_waf | 全部 `key=value` 收下（原先只取 src / dst / proto / dpt / action） |
| windows_event | 键值导出的全部 `key=value` 收下（原先只取 5 个） |
| windows_rdp | 事件查看器文本导出的全部 `键: 值` 收下（新增 `COLON_KEY_VALUE` + `_colon_fields`） |
| syslog | 应用层消息里的 `key=value` 全部收下；前缀的 `program` / `pid` 也落进记录 |
| nginx_apache | 补 combined 格式的 `remote_user` / `body_bytes_sent` / `http_referer`；`WEB_PREFIX` 的两个 `\S+` 改为命名组 |
| ssh | 补标准行头的 `host` / `program` / `pid` 与来源 `port`（新增 `SSH_HEADER` / `SSH_PORT`） |
| mongodb | 结构化日志（4.4+）的顶层字段与 `attr` 全部收下 |
| mysql / postgresql / redis / sqlserver | 补 `thread`+`command` / `pid`+`connection_id` / `pid`+`role` / `source` |
| oracle | 无需改：ORA 码本就映射到 `status` |
| windows_evtx | 昨天已完成（`<System>` 事件头 + 全部 `<Data>`） |

**明确不改**：`generic`（未识别类型）解析 0 条记录是 `docs/IMPROVEMENT_ROADMAP.md` 已记录的
真实能力边界（走 Drain3 模板挖掘），不是缺陷 —— `sample_logs/generic/app.log` 属此类。

**冒烟（真实样本，16 个文件 / 15 种类型）**：13+3 个类型都取到了格式自带字段，
其中 syslog **41** 个、windows_event(KV) **26** 个、iis **12** 个、windows_rdp **8** 个、
mongodb 7 个、json 6 个、firewall_waf 5 个、ssh 4 个、nginx_apache 3 个、
mysql / postgresql / redis 各 2 个、sqlserver 1 个。

**轻量测试**（按要求先不做全量）：

| 范围 | 结果 |
|---|---|
| 解析与记录结构相关 9 个模块（`test_analysis` / `test_evtx_standard_fields` / `test_detection_engine` / `test_detections` / `test_search` / `test_facets` / `test_dashboard` / `test_evidence_value` / `test_whitelist`） | **221 passed**（2m31s） |
| 规则门禁 4 个模块（`test_rule_quality` / `test_rule_metadata` / `test_rule_health` / `test_rule_verification`） | **46 passed**（4m42s） |

合计 **267 passed**，退出码 0 —— 记录结构大改之后，语料的 TP 111 / FP 0 / FN 0 与规则元数据
门禁、规则库体检全部保持不变。

**随后补跑一次完整套件**（收口）：**651 passed**（12m16s），退出码 0。

**本日改动全部完成后再次补跑完整套件**：**651 passed**（35m30s），退出码 0
（规则量 2272 后 `test_rule_quality` 明显变慢，单模块占了大部分时间）。

### 放开 `logsource 无法映射` 里能安全放开的 420 条

先取证再动手。480 条 `logsource 无法映射` 按「有没有可依赖的 EventID 守卫」分成四组：

| 组 | 条数 | 处理 |
|---|---:|---|
| ① `category` 已在 `SYSMON_EVENT_IDS` 里（`image_load` / `pipe_created` / `create_remote_thread` …），只是没进 `LOGSOURCE_MAP` | **351** | 放开 |
| ② `service` 型且规则自带 `EventID` 守卫（AppLocker / CodeIntegrity / BITS / Firewall-AS / DNS-Client …） | **69** | 放开 |
| ③ 只有 `product=windows`，无任何约束 | 1 | 跳过 |
| ④ `category` 无已知 EventID（`ps_module` / `ps_classic_start` / `file_access` …） | 59 | 跳过 |

**① 是纯代码内部不一致**：`SYSMON_EVENT_IDS` 写了 23 个分类的 EventID 守卫，`LOGSOURCE_MAP`
只认 9 个——同一个事实写在两张表里，漏掉的 14 个分类白丢。现在 `_logsource` 直接以
`SYSMON_EVENT_IDS` 为准，不再逐条复制表项。

**② 的判据是「规则自己把范围钉住了」**：EVTX 解析器能读任意通道，但认不出的服务名不能无条件放行
——没有 EventID 约束的规则会跑到全部 EVTX 记录上。新增 `_has_event_id_guard()`，只有规则自己
用 `EventID` 钉住事件时才放行；③④ 因此如实跳过，不靠放开白名单凑数量。

**顺带修正一处归组口径**：`_is_host_category` 原先按「服务名在白名单里 / 分类在
`HOST_CATEGORIES` 里」判断，新放开的服务型规则会落进「按来源 IP 归组」——AppLocker 事件没有
来源 IP，会全并成一个 `unknown` 桶。改为「`product=windows` 即按主机 + 进程归组」，
对既有规则是等价变换（现有 Windows 规则本就都命中前两条）。

**实测**：候选 2418 → 转换 **2202**（原 1782，+420，与取证完全一致）→ 误报裁剪后保留
**2191**（原 1771）；跳过里 `logsource 无法映射` **480 → 60**（正好是③④），
附录逐条留痕 800 → **215 条**。规则总量 1852 → **2272**。

**验证**：规则与解析门禁 7 个模块 **79 passed**（13m17s，退出码 0）——语料 TP 111 / FP 0 / FN 0
不变；规则库体检 2272 条**阻断项 0**、观察项 21 → 33（`event.type` 冲突，`slug()` 截断所致，不阻断）。

**放行判据的专项验证**：`_has_event_id_guard()` 只检查规则里**有没有** `EventID` 键——如果它落在
OR 分支里就不是必要条件，规则仍可能跑到全部 EVTX 记录上。逐条核实新放开的 420 条转换结果：
**守卫落在必要条件（`where`）上 351 + 69 = 420 条，0 条例外**（判据是 `where` 里有
`status` 的 `equals` / `in_set`，或 `any` 的**每个**分支都自带该守卫）。也就是说这 420 条都无法
脱离自己的 `EventID` 命中——这是「放行」而非「放开白名单」的实质。

### 性能复测：规则量 2272 后的耗时与内存

`scripts/bench_large_log.py --mb 10`（11.12 MB / 60,018 条）：

| 口径 | 规则耗时 | 峰值内存 | 每记录 |
|---|---|---|---|
| 全量 2272 条 | 15.75s（n=3，最大 23.11s） | 56 MB | 970 B（5.0× 文件） |
| 仅内置 74 条 | 8.61s（n=3，最大 17.09s） | 56 MB | 970 B |

- **规则耗时随规则量近似线性**：2198 条社区规则只多花 7.1s——说明「日志类型 + 必要条件」
  索引对导入规则是有效的（本轮新放开的 351 条带 `status in_set` 守卫、69 条带 `EventID` 守卫，
  都落在索引键上）。⚠️ 单次运行内离散很大（最大 23.11s），跨版本对比要看多轮均值，别拿单次数字下结论。
- **每条记录内存 820 B → 970 B（+18%）**：这是「按标准格式原样收下字段」的直接成本
  （Web 记录多 3 个字段，EVTX 记录多得多）。按 50 MB 上传上限外推，峰值约 0.25 → **0.3 GB**。
  口径已写进 `scripts/bench_large_log.py` 的结论段。
- 解析耗时 0.89s，与历史一致，仍是线性。

### 转换器补 4 个语法：规则量 2272 → 2371（P5-⑥/⑦ 之外的「字段处理」补强）

`sigma_import.py` 新增四个此前整条跳过的语法（按 sigmahq.io 规范实现）：

| 语法 | 实现 | 解锁 |
|---|---|---:|
| `windash` | 纯值侧展开：`-` → 5 种破折号变体（`-` `/` `–` `—` `―`），落入现有 any_contains / in_set | +82 条用法 |
| `base64offset` | 值侧 3 种对齐偏移的 base64 子串（数学推导：字符 c 覆盖比特 [6c,6c+6)，只有完全落在值字节区间内的字符才与前后缀无关） | 7 条 |
| 只有修饰符的键（`\|re: …`） | 隐式指向 keywords（url / raw） | 6 条 |
| 中间通配（`a*b`） | 全组转**锚定正则**（`^…$`，引擎 regex 是 re.search 语义必须加锚），不带 `*` 的取值也转精确匹配正则 | 12 条 |

**批量导入实测**（SigmaHQ b4ba1f2）：候选 2418 → 转换成功 **2303**（原 2202，+101）→
误报裁剪后保留 **2290**（13 条命中正常流量被自动剔除）；规则总量 2272 → **2371**。
跳过 215 → 114。验证：门禁 123/123 用例 · TP 111 / FP 0 / FN 0 · 体检阻断 0 / 观察 33（持平）·
可端到端触发 **2070** / 疑似缺陷 0 · `test_detection_engine` 20 passed（含 windash 触发、
base64offset 偏移命中、裸 `|re` 路由、锚定正则正反例 4 条新测试）· bench 10.13s（n=3）/ 56 MB，无回退。

### 上传支持压缩包自动解压 + 通用 XML（新日志类型）

**压缩包**（`parser.parse_upload` 重构为 `_parse_upload_content`，深度 ≤3、解压上限 256 MB）：
- gzip / bzip2：整包解压后递归解析（`.gz` 包着的 EVTX / XLSX / 文本都能进）；
- zip：逐成员递归解析后合并（记录拼接、类型取记录数最多者、confidence 取最低如实反映混合语料），
  单成员失败计失败数并**标注来源文件名**，`__MACOSX` 与隐藏文件静默跳过；
- 坑：**XLSX 本质是 OOXML（ZIP 容器）**，必须先按结构识别为 Excel 再考虑通用解压，
  否则域控导出会被当压缩包拆开（测试抓到后已修）。

**通用 XML**（新 log_type `xml`，识别置信 0.85，排在 EVTX XML 之后避免抢类型）：
- 重复元素 = 记录（沿「唯一子元素」下钻到重复标签层）；叶子取文本、属性取键值、
  深层用 `父.子` 点路径摊平（≤3 层）；
- 字段映射**复用** `_parse_structured_records`（与 JSON/CSV 同一套标准字段推导），
  因此 `SourceAddress` / `Timestamp` 这类标签自动映射到 source_ip / timestamp_iso；
- 无可识别字段的记录计入失败，不静默丢弃。顺带补了 source_ip 别名：
  `ip_address` / `ipaddress` / `source_address` / `sourceaddress`。

新增 `tests/test_parser_archives_xml.py` 7 条（正常 / 损坏成员 / 嵌套 zip 套 gzip / 深度上限 /
EVTX XML 不被抢类型）。`test_whitelist` / `test_domain_controller_export` / `test_rule_quality` /
`test_evtx_standard_fields` 全过。

### 性能调研：字面量倒排索引**否决**（数据说话）

为评估「无索引键规则」的优化空间做了完整量化（11 MB / 60,018 条 / 规则 2371）：

- 85 条无键规则（3.6%）占规则耗时 **5.11s / 8.85s（58%）**——大头确实在这里；
- 但 profile 显示成因**不是包装开销**：`re.search` 仅 1.4s，其余是谓词 matcher 本身的
  逐记录子串扫描——**这就是语义本身的工作量**；
- 试做的「单谓词预过滤」（复用谓词自身 matcher，差分验证事件完全一致）实测
  5.05s vs 5.11s，**无收益已回退**：多数无键规则的最便宜谓词区分度太低
  （如 `result=failure`），候选集依然巨大；
- 逐规则排名：第一名「Relevant Anti-Virus Signature Keywords I」单条 **1375ms**，
  其 `where` 为空、判据全在 `any_of`（大交替正则 × 6 万记录 × url+raw 双字段，纯 intrinsic 成本）。

**真正的两个杠杆，都需要决策，未擅自实施：**
1. **收紧导入规则的类型约束**：45 条无键规则 `log_types=()`（全类型放行），其中多为
   process_creation 类 Windows 规则，在 Web/SSH 记录上扫描纯属浪费且语义上也不该命中
   （Web URL 里出现 mimikatz 不是进程创建）。改 `LOGSOURCE_MAP` 的 exclude 名单 +
   重新导入 + 重跑误报门禁。预计砍掉大部分 5s。
2. **C 多模式匹配器（pyahocorasick）**：把全部字面量建成一个自动机、每记录扫一次。
   纯 Python 的单谓词预过滤已证伪，这是剩余的正路，但引入新依赖需要你点头。

### 导出格式：五套 SIEM 模板（补齐 Zircolite 对标缺口）

新增 `app/services/siem_export.py`，`GET /api/analysis/{id}/report?format=` 扩展五种取值：

| format | 格式 | 说明 |
|---|---|---|
| `splunk` | JSON 数组 | CIM 字段名（`_time` / `src` / `dest` / `user` / `signature` / `sourcetype`） |
| `elastic` | NDJSON | ECS 字段名（`@timestamp` / `event.kind=alert` / `source.ip` / `rule.name`） |
| `opensearch` | bulk NDJSON | `_bulk` 可直接导入，文档字段与 ECS 一致，`_index` 带事件日期 |
| `timesketch` | NDJSON | 三要素 `message` / `datetime` / `timestamp_desc` + `data_type` |
| `sarif` | SARIF 2.1.0 | 规则去重进 `tool.driver.rules`，风险级映射 error / warning / note |

**映射纪律**：只映射事件与证据里真实存在的字段，缺失键直接不产出（不允许幻觉）；
一条事件一条记录，`count` 与证据样本随行。测试：`test_analysis_report_exports_siem_templates`
（五套格式结构断言 + 附件头）。前端导出按钮未加（端点参数即用）。

**工程坑（记一笔）**：同文件的多个 Edit 并行发送会互相覆盖——两个编辑各自基于原内容写回，
后写者冲掉先写者（本会话两次踩中：rules_engine 回退残留 NameError、main.py SIEM 分支丢失）。
同文件编辑必须顺序执行，改完必须 grep 确认落地。

### 性能杠杆 ① 落地：收紧导入规则的类型约束，规则耗时 **10.13s → 3.46s（-66%）**

`LOGSOURCE_MAP` 的 Sysmon 行为类（process_creation / file_event / registry_set /
registry_event / dns_query / network_connection）exclude 名单补上 web / ssh / syslog /
firewall / sqlserver / oracle 共 7 类——这些类型结构上不可能携带进程创建 / 注册表事件；
webserver 类同样补排除（ssh / syslog / firewall / db / windows 全家族）。

- **保守边界**：`xml` 与 `generic` **不排除**——Sysmon 的通用 XML 导出、无法识别格式的
  文本，是关键词规则（扫 raw）的合理兜底场景。
- **验证（与收紧前逐项一致，无 FN）**：门禁 123/123 · TP 111 / FP 0 / FN 0 ·
  可触发 2070 / 疑似缺陷 0 · 体检阻断 0 / 观察 33 · 规则总量 2371 不变。
- **bench（11 MB / 60,018 条）**：规则耗时 min **3.46s**（原 10.13s；n=3 最大 12.35s vs 原
  17.94s），解析 0.87s 与内存 56 MB 不变。按 50 MB 上限外推，规则耗时约 **15s 量级**。
- 6 条 curated web 规则（90-sigma.yaml，手工精选）未重新生成，仍无类型约束——
  合计约 0.5s，属可接受残留；要一起收紧需重跑 curated 导入。
- 内置 6 条全类型聚合规则（Web/SSH 登录聚集等）是**刻意**不限类型，不动。

### 收尾：curated 规则收紧 + validated 标注诚实化 + 前端 SIEM 导出入口

1. **curated 规则（90-sigma.yaml）重新生成**：8 条 webserver/Windows-security 规则全部带上
   类型约束（此前 6 条 web 规则无约束，残留约 0.5s）。规则总量保持 2371。
2. **`import_sigma.py` 的 validated 标注诚实化**：脚本原来一刀切声明 `validated`（注释称
   「7 条都有本地正样本」），但第 8 条（RDP 反向隧道，SigmaHQ `status: test`）语料里从没有
   正样本——旧文件是 7 条时代生成的，重新生成后元数据门禁立即抓住（eval exit=1，
   「声明 validated 但无正样本」）。**门禁是对的**。修法：先如实写 `unverified`，再跑与
   `eval_rules.py` 同源的语料评测，命中正样本的规则才回填 `validated`——
   现在 `validated 7 条、unverified 1 条`。
3. **连带修掉一个跨文件重复**：community 导入时 curated 还是旧 7 条，RDP 隧道规则同时进了
   两个文件 → 体检报 `duplicate_detection` 阻断项。重跑 community 导入（按既有 id 排除后
   2290 → 2289）后阻断归零。**教训：两个生成脚本有先后依赖，先 curated 后 community。**
4. **前端补 SIEM 导出入口**（`App.vue`）：详情页工具栏加「导出 SIEM…」下拉
   （Splunk CIM / Elastic ECS / OpenSearch bulk / Timesketch / SARIF），`vue-tsc` 通过，
   dist 已重新构建。

**最终状态**：门禁 123/123 · TP 111 / FP 0 / FN 0 · 元数据 0 违规 · 阻断 0 / 观察 33 ·
可触发 2070 / 疑似缺陷 0 · bench 规则 **3.52s**（n=3）/ 56 MB · 相关测试 21 passed。

### 补齐 P5-⑦ 的「可回滚」，并修正路线图的两处漏更新

**核实发现 P5-⑥ 其实早已实现**，路线图却一直标着未完成：`POST /api/rules/preview`
（草稿试运行 + TP/FP/FN、不写规则目录）与 `scripts/eval_rules.py`（误报 / 漏报 /
未被覆盖 / 元数据格式四类**非零退出**门禁）都在。已按实际状态补记。

**P5-⑦ 只做了一半**：审计表（`rule_changes`）与 `GET /api/rules/audit` 有，**回滚没有**。本轮补上：

| 文件 | 改动 |
|---|---|
| `app/services/rule_governance.py` | 新增 `rollback(entry_id)`：还原到该记录记下的「变更前」状态，并**追加**一条回滚记录 |
| `app/main.py` | 新增 `POST /api/rules/audit/{entry_id}/rollback` |
| `tests/test_analysis.py` | 新增 2 条：回滚生效且留痕、未知记录返回 404 |

**设计取舍**：回滚**追加新记录**而不是改写旧记录——审计链只增不改才谈得上可追溯；只支持
`enable` / `disable` 两类（`before_value` 是布尔串、语义明确），其它 action 返回 404 而不是猜。

**边界（如实记录）**：这里的「可回滚」覆盖**启停治理**，**不覆盖规则内容变更**——规则正文是
YAML 文件、项目没有版本控制，正文级回滚要先定版本化方案（存快照还是引入 VCS），属需决策项。

**验证**：`tests/test_analysis.py -k rule` **11 passed**（含新增 2 条）。

---

## 2026-10-13

本轮完成「对标后补强」的三项：**威胁情报富化**（新功能）、**MCP 只读接口**（原待定项）、
**大文件验证与内存预检**；并对**真实模型评测**做了首次实跑（结论：被真实 key 阻塞，
同时暴露并修掉一个真实缺陷）。用户随后指定 **Zircolite 为下一优先级参考**，
同日继续交付：**概览看板**、**检测视图**、**左侧分区导航重排**、**ATT&CK 标签映射**、
以及**真实模型评测跑通**（10/11）。

### 外观对齐 Zircolite 4.5.0（设计系统移植）

**只移植设计系统，不换技术栈。** 对比了 Zircolite GUI（Svelte 5 + DuckDB-WASM，全在浏览器）
与本项目（Vue 3 + FastAPI）后保留后者——本产品的核心能力（AI 研判、持久化历史、威胁情报外呼、
取证交付）在纯浏览器 WASM 架构里无法实现。视觉部分按 Zircolite 的 `gui/source/src/app.css`
逐项对齐：

| 维度 | 对齐内容 |
|---|---|
| 色板 | `paper #eef1ef` / `panel #f8faf8` / `ink #16211e` / `ink-2 #4a5955` / `rule #cfd8d4` / `signal #00697a` + 五档 `sev-0..4`（info→critical）+ `sev-unknown`（未被任何等级使用的紫色）；暗色主题同步换成 `paper #0e191c` / `panel #13232a` / `signal #53c2cf` 等 |
| 排版 | 字体栈改为 Atkinson Hyperlegible Next / Mono（本机没有该字体，回退 Inter / JetBrains Mono，注释已注明）；正文 15px / 1.45；字号令牌 `--t-12/13/15/18/22`；数字统一 `tabular-nums` |
| 形状 | 全站圆角收敛到 4px / 3px；**去掉卡片阴影**（Zircolite 靠 1px 边框分层）；胶囊徽章改为方角色块，圆点改方块 |
| 组件 | 指标卡从「独立卡片」改为 **Zircolite tiles 式的拼接网格**（`grid-auto-flow: column` + 共享 1px 分隔线）；五档严重度行、ATT&CK 战术网格同样改为拼接网格；侧栏导航改为 NavRail 形态（40px 行高、无胶囊底、选中态是左侧 3px signal 竖条） |
| 页头 | 去掉半透明毛玻璃，改 `panel` 底 + 1px `rule` 下边线；行高 48px |

验证：`npm run build`（vue-tsc + 构建）通过；色值审计 **53/53 处全部出自 Zircolite 色板或白名单**；
`border-radius` 取值集合收敛为 `0/1/2/3/4px/50%/999px(滚动条)`。

**过程中的三处真实修复**
1. 替换脚本把 `--sev-0..4` 的**令牌定义本身**也改成了 `var(--sev-N)`（自引用死循环），
   审计脚本的「未定义变量」检查把它抓了出来。
2. `--accent` 与 `--surface-2` 被白名单弹窗**引用了但从未定义**（`background: var(--accent)` 实际不生效），
   已改为 `--primary` / `--panel`。
3. `--font-mono` 同样从未定义（项目里的名字是 `--mono`），13 处硬编码 `Consolas` 统一走 `--mono`。

### 新增：导入规则的批量检测效果验证（`scripts/verify_sigma_rules.py`）

回答「导入规则要不要逐条验证」。**不需要，也不应该**——把「规则能不能检出」拆成三个
互不重叠的问题，各自用机器回答，人工只看机器试出问题的那几条。

| 层 | 做法 | 结果 |
|---|---|---|
| 层 1 合成正样本 | 从规则谓词树**反推一条必然满足它的记录**，再用 `evaluate_rule()` 端到端跑一次 | **1992 / 2198 可触发（90.6%）**、**疑似缺陷 0**、无法自动合成 206（正则 / 复杂跨字段约束） |
| 层 2 真实语料回放 | 49 个真实日志 / 16,701 条记录跑全部规则 | 5 条真实命中；1610 条未命中，其中 64 条语料里连它要求的 EventID 都没有，1546 条有同类日志但缺对应恶意内容 |
| 层 3 负样本筛查 | 在「正常流量」内联语料上跑 | **0 条**判定过宽 |

报告：`docs/sigma-rule-verification.md`（含三层口径、结果、原因分布与人工清单）。

**开发过程中修掉的四个真 bug**（都来自「结果对不上」而不是「看起来不对」）
1. `Predicate.matcher` **本身已含取反**（`Rule.covers` 直接拿它当真值），验证器却写成
   `matcher == (not negate)` → 取反条件被赋上「必须不等于」的值，规则必然不命中，被误报成缺陷。
2. 同一字段上多个 `contains` 是 **AND** 语义，候选值必须把各段拼进同一个字符串；
   早期只取一段，导致 392 条规则被误判「条件自相矛盾」。
3. 复核 `covers()` 时计划里没放 `log_type` → 所有带 logsource 的规则都栽在 `logsource_ok`。
4. `where` 为空时 `_solve` 提前返回、不带 `log_type`，any 分支复核失败后又返回了一个
   **「看起来 ok 的空记录」**，把 3 条正常规则误报成缺陷。现在加了「记录为空一律按无法合成处理」的守卫。

新增测试 `tests/test_rule_verification.py`（13 条），把上述坑逐条钉住。

### 新增：威胁情报富化（「查户口」）

**背景**：对标 GitHub 同类项目后最明显的功能差距——本项目查完日志就结束，
不会拿可疑 IP / 域名去公开情报库比对。

| 文件 | 改动 |
|---|---|
| `app/services/threat_intel.py` | **新增**。指标提取 + 三个情报源 + 结果缓存 + 富化主流程 |
| `app/models.py` | 新增 `ThreatIntelSourceResult` / `ThreatIntelFinding` / `ThreatIntelReport` |
| `app/main.py` | 新增 `GET /api/analysis/{id}/threat-intel?refresh=` |
| `frontend/src/App.vue`、`frontend/style.css` | 新增「威胁情报」模块（按需查询 + 结果表 + 强制重查） |
| `tests/test_threat_intel.py` | **新增** 20 条 |
| `.env.example` | 新增 7 项配置 |

**四条硬约束（全部有测试守住）**

1. **默认关闭**（`THREAT_INTEL_ENABLED=false`）：查询会把指标发送到外部服务，
   本地优先的工具必须由用户显式开启；关闭时返回带说明的空报告，**不发任何请求**。
2. **独立展示，不进判定链**：不写入 `events`、不改变风险等级、不进入 AI 上下文。
3. **「未收录」不等于安全**：该声明同时出现在报告 `note`、界面与测试里。
4. **只查公网指标**：内网 IP / 常见厂商域名不外发（复用 IOA 层 2 白名单口径，
   `COMMON_DOMAIN_SUFFIXES` / `NON_PUBLIC_SUFFIXES` / `PRIVATE_NETWORKS` 直接引用，不另立一套）。

**情报源**：ThreatFox（abuse.ch，免 key）、URLhaus（abuse.ch，免 key）、
AbuseIPDB（可选，需 `ABUSEIPDB_API_KEY`，仅 IP，评分 ≥30 视为恶意）。
AbuseIPDB 未配 key 时状态为 `skipped` 并在界面写明原因——**不是「未收录」**，
两者混起来会让用户以为查过了。

**已有工程纪律的沿用**

- 指标提取优先级：事件（按风险降序）→ 实体画像 → 原始记录（目的 IP / DNS 查询），
  上限 `THREAT_INTEL_MAX_INDICATORS`（默认 15），**超限时报告同时给出真实总数**
  （截断处必须给出总数，见 `PROGRESS.md` 上限接口纪律）。
- 查询总时长预算 `THREAT_INTEL_BUDGET_SECONDS`（默认 30s），超预算的来源标记 `skipped` 并写明原因；
  单源异常只影响该源（`status=error` + 可读 detail），不拖垮整份报告。
- 结果按「指标 + 来源」落 `threat_intel_cache` 表，TTL 默认 24 小时；`refresh=true` 强制重查。
  实测第二次查询**零请求**（全部命中缓存）。

**实测与坑**

- 首次实现把 `192.168.1.1` 这类**内网 IP 当域名**放进了待查列表（`_is_queryable_domain`
  只挡了公网 IP 判断）。已改为「任何能解析成 IP 的值都不是域名」，并由测试钉住。
- 预算测试最初用 `THREAT_INTEL_BUDGET_SECONDS=0` 触发，实际被 `_int_setting`
  的「非正值回退默认」拦截（预算变成 30 秒，测试测的是另一件事）。
  改为注入可控时钟，让 `deadline` 必然已过期——**测试的触发条件必须真的能触发**。

### 新增：MCP 只读接口（原「待定」项，行业已验证）

**背景**：2026 年 MCP 已成安全数据接入的事实标准（Sentinel / CrowdStrike / Zscaler 均出官方
MCP server，社区有 misp-mcp / opencti-mcp）。本项目已有一套只读工具层，暴露出去的边际成本很低。

| 文件 | 改动 |
|---|---|
| `backend/scripts/mcp_server.py` | **新增**。13 个只读工具 + stdio 传输 |
| `tests/test_mcp_server.py` | **新增** 3 条（走真实 MCP 协议，非直接调函数） |
| `backend/requirements.txt` | 新增 `mcp==1.9.4`（**必须锁 1.9.x**） |

**工具清单**（全部只读）：`list_analyses` / `analysis_overview` / `analysis_metadata` /
`analysis_statistics` / `query_events` / `query_evidence` / `timeline` /
`query_behavior_deviations` / `query_uncovered_records` / `query_terminal_chains` /
`query_records` / `ai_ledger` / `threat_intel`。

**关键设计**

- **复用而不是重写**：除「分析列表 / 总览 / 台账 / 情报」四个入口外，其余工具全部转调
  `app.services.agent_tools.execute_tool`。MCP 与页面看到的数字同源，
  将来改口径只需改一处（AGENTS.md §30「复用已有模块」）。
- **只读边界写进测试**：工具名单是白名单，且断言任何工具名都不得含
  `delete/upload/write/execute/block/...` 等动作词——**新增工具必须同步改白名单**，
  防止某天悄悄放开一个写操作。
- 每个返回体都带 `summary`，便于外部 AI 客户端直接引用。

**依赖坑（重要）**：`mcp` 2.x 会把 `pydantic` 拉到 ≥2.12、`starlette` 拉到 1.x，
与 `fastapi==0.115.6`（要求 `starlette<0.42`）冲突；`mcp` 1.30 同样要求 `pydantic>=2.12`。
最终锁 **`mcp==1.9.4`**（兼容 pydantic 2.10.6 / starlette 0.41.3）。
`pip` 的解析器不会因为「已安装的 fastapi 不兼容」而回退，**装完必须复核
`pip list` 与 `import app.main`**，否则会留下一个启动即崩的环境。同时清理了
升级/回退过程中产生的 `~cp*` / `~ydantic_core` 无效分发目录。

**FastMCP 两个实现细节**：① 脚本里不能有 `from __future__ import annotations`
（注解变成字符串后 `issubclass(param.annotation, Context)` 直接抛 TypeError）；
② 返回 `list[...]` 会被拆成多个内容块，故统一返回带 `summary` 的对象。

### 新增：大文件验证与上传内存预检

**实测（本机，可用内存 1.5 GB）**

| 样本 | 解析 | 规则 | 峰值内存 | 覆盖率 | 解析失败 | 超保留 |
|---|---|---|---|---|---|---|
| 100 MB（2026-09-30） | 8.19s | 28.20s | 441 MB（4.4×） | 100% | 0 | 0 |
| **200 MB（本轮）** | **17.42s** | **56.87s** | **883 MB（4.4×）** | **100%** | **0** | **0** |

- 峰值稳定为文件大小的 **4.4 倍**、约 857 字节/条，两档均**线性**；
- **500 MB 在本机无法验证**：需要约 2.2 GB 峰值，实测可用 1.5 GB。
  这是硬件约束，不是配置问题——按路线图「超过限制时给出可解释提示」处理。

**改动**：新增 `app/services/memory_guard.py`（`available_bytes()` / `estimate_peak_bytes()` /
`check_upload_memory()`），接入 `/api/logs/upload` 的容量校验。

- 预检式拒绝：`需要 = 文件大小 × 4.4 + 300 MB 余量`，不够则返回 **413 + 可操作提示**
  （写明本次日志多大、按实测需要多少、当前可用多少、建议拆分文件），
  而不是让用户等几分钟后看到进程被杀或机器换页卡死。
- **读不到内存信息时放行**（`available_bytes()` 返回 `None`）：不能因为拿不到系统信息就误拒上传。
- `tests/test_memory_guard.py` **新增** 8 条，含边界（刚好等于峰值时必须拒绝，因为没留余量）
  与「读不到内存 → 放行」。

### 新增：概览看板（仿 Zircolite Overview）

**背景**：用户要求参考 Zircolite（`Zircolite-4.5.0.zip`，Svelte 5 + DuckDB-WASM 的离线检测工具）
重排界面与补齐功能，并保持本项目自身特点（企业级蓝灰白、判定与证据口径）。

| 文件 | 改动 |
|---|---|
| `app/services/dashboard.py` | **新增**。看板数据构建 |
| `app/models.py` | 新增 `SeverityCell` / `TacticCell` / `TopItem` / `AnalysisDashboard`；`TimeBucket` 增加 `levels` |
| `app/services/analytics.py` | `build_timeseries` 增加 `timed_events` 参数 |
| `app/main.py` | 新增 `GET /api/analysis/{id}/dashboard` |
| `frontend/src/App.vue`、`frontend/style.css` | 概览模块顶部新增看板；新增风险过滤联动 |
| `tests/test_dashboard.py` | **新增** 11 条 |

**看板内容（全部由既有 events / records 推导，不新增判定）**

1. 标题：`N 个可疑事件（共 M 条记录，K 条命中规则）`；
2. 五档严重度卡片：每档显示**事件数 + 命中规则数**，点击即在「可疑事件」模块按该等级过滤
   （相同档位再点一次取消；会自动展开被折叠的事件模块）；
3. 中轴双向时间分布：**上方 = 记录数、下方 = 事件按风险分层**（最严重贴近中轴），
   柱高用平方根缩放；
4. ATT&CK 战术网格：14 个战术格（含 0 格），按最忙战术归一化着色；
5. Top 规则 / Top 主机 / Top 来源 IP 三榜。

**两条口径都写进了测试**

- **事件数与记录数不混**：`events_total` 是事件数、`buckets[].count` 是记录数
  （测试断言 10 条记录 + 1 个事件时，卡片显示 1、桶合计为 10）。
- **事件与记录共用同一套桶边界**：否则上下两条轴对不齐；桶边界之外的事件
  **钳到最近的桶而不是丢弃**——丢弃会让「有事件却看不到」变成查不出来的假象。
  事件时间取证据对应记录的 `timestamp_iso`（事件自身的 `first_seen` 是日志原文，
  形如 `12/Sep/2026:09:59:59 +0800`，不一定可解析）；两处都拿不到时**不猜时间**，
  只在 `note` 里如实计数。

**顺手发现的既有小问题（未改，记录在此）**：`_iso_label()` 的 label 只到分钟，
而分桶可能细到秒，于是会出现多个桶显示同一 label（如两个 `09-12 09:17`）。
`AI 洞察` 的时间柱状图也共用该 label，改动会影响现有展示与测试，本轮按外科手术原则未动。

### 修复：真实模型评测暴露的配置报错不可读（11/11 用例同一失败）

**现象**：用 `--real` 实跑评测，11 条用例全部失败在同一句
`'latin-1' codec can't encode characters in position 7-8: ordinal not in range(256)`。

**根因**：`.env` 里的 `AI_API_KEY` 是**未替换的中文占位符**（9 字符、含非 ASCII），
请求头按 latin-1 编码时抛错。报错完全指不到病因——这正是「必须跑真实模型」的价值：
替身路径永远不会碰真实请求头。

**改动**：新增 `_api_key_problem()`，在 `check_ai_config()` 与 `_create_provider()`
两处快速失败，给出可读原因（「API Key 含非 ASCII 字符，常见于 .env 里没替换的中文占位符」）；
`check_ai_config` 同时把该配置判为 `configured=false`，页面不会显示「已配置」。
回归测试见 `tests/test_analysis.py::test_non_ascii_api_key_reports_readable_config_problem`。

**遗留**：~~真实模型评测**未完成**——需要用户填写真实 DeepSeek API Key 后重跑~~ →
**已于同日晚跑通**，见下方「真实模型评测首次跑通」。

### 新增：威胁情报进 AI 上下文 + ATT&CK Navigator 导出 + 规则量扩容（584 → 2272）

**① 威胁情报进 AI 上下文**（`ai.py` + `threat_intel.cached_report`）

- `build_ai_context` 新增 `threat_intel` 与 `threat_intel_note` 两块。
- 🔴 **硬约束：研判过程绝不发起外部请求**——只读 `cached_report()`（缓存里已有的结果）。
  理由：用户在界面点「AI 研判」时并不知道这会向第三方发送 IP，
  本地优先的工具不允许这种隐藏副作用。`cached_report` 有专门测试（patch urlopen 抛错验证）。
- 情报是**第三方数据**，提示里明确 `source=third_party_reputation;not_log_evidence`，
  避免模型把「情报库说这个 IP 恶意」当成「日志证明它恶意」。
- 没查过就写 `queried=none;未查询威胁情报，不得据此推断 IP 声誉`——
  **不能因为「没有情报块」推断「IP 声誉正常」**。

**② ATT&CK Navigator 导出**（`GET /api/analysis/{id}/attack-navigator`）

- 输出 layer v4.5 JSON，可直接在 Navigator 打开；前端「ATT&CK」视图加导出按钮。
- **只导出本次真正命中的技术**：图层回答「这次看到了什么」，不是「我们能检测什么」——
  0 命中的技术上色会让图层读起来像「全都被打过」。
- 颜色按命中事件的最高风险等级（为此给 `AttackTechniqueCell` 补了 `risk_level`），
  comment 里写明风险、事件数与贡献规则。

**③ 规则量扩容：584 → 2272 条**（内置 74 + 精选 7 + 社区导入 2191）

| 环节 | 改动 |
|---|---|
| 候选范围 | 原先只导入 `windows/process_creation` + `windows/builtin`（1517 条候选）→ 现在覆盖 SigmaHQ 全部 17 个 Windows 子目录（**2418 条候选**） |
| 字段覆盖 | EVTX 解析器按**标准格式**落盘：`<System>` 事件头（Channel / Level / Task / Opcode / Keywords / EventRecordID / Provider）+ `<EventData>` 里每个 `<Data Name="…">`；Sigma 字段直连，未登记的字段原样直通 |
| 索引键 | `in_set` 与带变换的 `equals` 现在都能当索引键 |
| 结果 | 转换 2202 → 去重 2202 → 正常流量零命中筛查后保留 **2191**（剔除 11 条） |

**为什么改成「按标准格式解析」而不是「在模型外匹配」**：Sigma 规则大量匹配记录模型里没有的
字段（`OriginalFileName` 512 次、`Details` 265 次、`ParentCommandLine` 71 次…）。
第一版的做法是加一张 `SCOPED_FIELD_MAP` 补丁表，把这些字段映射成 `raw` + `scope:<字段名>`，
指望从原始日志文本里按字段名把值抠出来。**这个方向本身是错的**：

- 变换根本没落盘——`_build_predicates` 里 `transform` 赋值后从未使用、`_predicate_dict`
  也不输出 `transform`，885 条规则退化成未限定的 `raw` 匹配，实际永不命中；
- 即使落盘也取不到值——EVTX 的 `raw` 只由 14 个字段拼成，**不含**这些字段名
  （实测 1048 条真实记录里 0 条）。

正确做法是让字段**真实存在**：解析器按标准 EVTX 结构把 `<EventData>` 里每个
`<Data Name="…">` 原样落进记录（无 `Name` 的合并到 `Data`，认证事件与非认证事件都带上），
Sigma 的字段名与日志里的标准名本就一致，转换时直连即可。`SCOPED_FIELD_MAP` 与 `scope:`
变换已全部删除，`tests/test_evtx_standard_fields.py` 钉住这条链路。

**性能：一次真实的回退与修复**（这部分比结果更值得记）

- 扩量后首次实测：11 MB 日志规则耗时 **2.99s → 19.53s**（6.5×）。
- 定位过程：统计每条规则的候选记录数，发现 **6.9M / 8.46M 次记录访问来自导入规则**，
  其中 **106 条规则完全没有索引键**——它们的守卫是 `status in_set [...]`，
  而 `_index_keys` 只认 `equals` / `exists`。
- 两步修复：① `SYSMON_EVENT_IDS` 补齐 17 个分类的 EventID（原先只有 6 个）
  → 14.63s；② `in_set` 与带变换的 `equals` 纳入索引键（值集合整体作为一个键，
  语义与谓词完全等价）→ **11.94s**，记录访问量 **8.46M → 3.48M**。
- **仍高于扩量前的 2.99s**，原因诚实记录：剩余 40 条导入规则的 `where`
  没有任何可作必要条件的单字段谓词（多为 `keywords` / `any_contains` / 纯取反），
  在当前索引方案下只能全量扫描。下一步的正确做法是**字面量倒排索引**（把
  `any_contains` 的必需子串提成键），不是继续放宽「必要条件」的定义——那会破坏判定正确性。
- 一键回到快档：`RULE_SIGMA_IMPORTED_ENABLED=false`（只跑 74 条内置规则）。

**门禁与报告（全部重新生成）**

- 规则质量：用例 **123/123**、内置覆盖 **74/74**、TP **111** / FP **0** / FN **0**、
  精确率与召回率 100%；未验证导入规则 **2191 条**如实单列；导入规则在攻击样本上
  重复命中 25 次（重复检出，不是误报）。
- ATT&CK 标尺清单扩到 **120 项**（外部参考集原有 27 + 本项目补充 93）：
  新增 75 项来自「该技术有 ≥5 条规则支撑」，技术名与战术取自 **MITRE ATT&CK 官方 CTI 数据**
  的 `kill_chain_phases`（不用规则标签投票——投票给 T1685 的战术是「执行」，官方是「防御规避」）。
  ⚠️ 新加入技术**没有本地正样本**：覆盖报告显示「有规则 120/120、有本地样本 46/120」，
  两个口径保持分开，不合并成一个百分比。

**测试影响（如实记录）**：`test_rule_quality.py` 在启用全部社区规则后明显变慢
（2272 条规则 × 语料），单模块约 3~4 分钟；其余模块不受影响（conftest 默认关闭社区规则）。

### 新增：ATT&CK 两级矩阵 + 搜索语法查询 + 进程树 + 字段 facet（P8 收口）

四项一次交付，均**只做映射/筛选/展示，不改判定**。

| 文件 | 改动 |
|---|---|
| `app/services/attack_matrix.py` | **新增**。战术 × 技术两级矩阵 |
| `app/services/search.py` | **新增**。搜索语法词法、字段别名、匹配与容错 |
| `app/services/facets.py` | **新增**。字段覆盖率与取值 Top |
| `app/main.py` | 新增 `GET /attack-matrix`、`GET /search`、`GET /search-fields`、`GET /facets` |
| `frontend/src/App.vue`、`frontend/style.css` | 新增「ATT&CK」「查询」视图与「进程树」视图；明细页新增字段侧栏；顶部工具栏新增搜索框 |
| `tests/test_attack_matrix.py` / `test_search.py` / `test_facets.py` | **新增** 7 + 11 + 5 条 |

**① ATT&CK 矩阵**：战术列下展开到技术，格内显示事件数与命中规则；可切换「只看命中 / 完整清单」；
不在内置标尺清单里、但本次确实命中的技术同样显示并标「清单外」。

**顺带查出一个真实数据不一致**：内置标尺 `evaluation/attack-benchmark.json` 写的是
「**凭证**访问」（8 项技术），而战术阶段表用「**凭据**访问」——一字之差，
这 8 项技术在按阶段排序的矩阵里**永远不显示**（列被丢弃且不报错），
而 `techniques_hit` 仍把它算作命中，于是出现「说有 1 项命中却一格都看不到」。
三处修复：① `tactics.normalize_tactic()` 加别名归一；② 矩阵对阶段表外的战术
**单独补一列**（`phase_index=99`）而不是丢弃；③ 修正清单数据本身。
新增回归测试 `test_tactic_aliases_normalize_to_official_names` 与
`test_every_mapped_tactic_has_a_phase_slot`。

**② 搜索语法**（仿 Zircolite 顶部搜索框）：`字段:值`、`-字段:值`（排除）、`"多词短语"`、
裸词跨字段全文（含只在 `raw` 里出现的事实）。**刻意不做 SQL 控制台**——
那是数据库客户端的形态，本项目是「对一份日志做研判」的只读工作台。
容错：**认不出的字段名不静默忽略**，而是告警 + 退回「按值全文匹配」
（写 `sourceip:10.0.0.8` 的意图是查这个 IP，不是查字面量）。原生实现过程中发现初版
回退把整串当查询值导致必然查不到，已修正。

**③ 进程树**：由终端证据链的进程节点构建（不新增接口），同一资产内按 PID / 父 PID 连接；
**父进程不在本次日志中时标为根并注明，不凭 PID 大小或时间猜父节点**；
节点数 > 300 时默认只展开根节点，避免一屏几百行。

**④ 字段 facet**：字段覆盖率（分母是**总记录数**，含该字段为空的记录）+ 取值 Top；
`values_total` 给出去重总数，截断时显示「已展示 Top N / 共 M 个取值」；
`raw` 与 `command_line` 刻意不列入（无区分度 / 取值近乎唯一）。
侧栏的 `+` / `−` 能走服务端筛选的走筛选，其余自动转成搜索语法查询。

### 新增：检测视图（按规则归组，仿 Zircolite Detections）

| 文件 | 改动 |
|---|---|
| `app/services/detections.py` | **新增**。按规则归组 + 规则元数据补全 |
| `app/models.py` | 新增 `DetectionVariant` / `DetectionGroup` / `DetectionsReport` |
| `app/main.py` | 新增 `GET /api/analysis/{id}/detections` |
| `frontend/src/App.vue`、`frontend/style.css` | 新增「检测」视图（规则卡片可展开看元数据与命中明细） |
| `tests/test_detections.py` | **新增** 7 条 |

**与「可疑事件」的分工**：可疑事件是「一条事件一张卡」，看现象；检测视图是「一条规则一行」，
看规则命中分布。**只归组，不改判定**——不合并风险等级、不改结论。

**两个口径必须分开写**（测试钉住）：`event_count`（事件条数）与 `trigger_count`（触发次数合计）。
一次聚合事件可能代表几百次触发（实测 `ssh.bruteforce` 两条事件 = 150 次触发），
界面按「N 个事件 · 触发 M 次」两栏显示。

**如实呈现规则可信度**：`source` 为 `builtin`（有本地标注语料）/ `sigma`（仅做过正常流量
零命中筛查）；`validation_status` 直接取规则元数据，内置规则 YAML 目前没声明该字段，
因此显示「规则元数据未声明」——**不替它美化成「已验证」**（补齐真实元数据属路线图 P5）。

### 新增：左侧分区导航与页面重排（仿 Zircolite NavRail）

原先详情页是「顶部横向模块导航 + 全部模块纵向堆叠」，现在改为**左侧分区导航 + 一次只显示一个视图**。

- 新增 `activeView` 状态与 `setActiveView()`（进入视图时自动展开该模块）；各章节由
  `v-show` 折叠改为 `v-if="activeView === 'x'"`。
- **删除已失效的滚动高亮机制**（约 3000 字符）：`updateActiveModule` / `refreshActiveModule` /
  `scrollToModule` / `stickyBottom` / `clickLock*` / `window` 滚动与 resize 监听，
  以及「折叠关联分析」批量开关与对应 CSS（`.module-nav` / `.module-tab*`）。
  单视图切换后这些代码不会再被触发，留着就是死代码（AGENTS 纪律）。
- 视图失效兜底：换一份日志后原视图可能不存在（例如没有实体），自动回到第一个可用视图；
  首次加载一律回到「概览」。
- 窄屏（≤1080px）左栏退化为横向可滚动条。
- 保留模块内折叠开关与 localStorage 持久化；导航切换时自动展开目标视图。

### 新增：ATT&CK 标签映射（让 503 条 Sigma 规则不再落「其他」）

**问题**：内置规则靠 `analytics._TACTICS` 手写映射，而 503 条 Sigma 导入规则只在
`tags` 里带 `attack.<tactic>` 与 `attack.Txxxx`。缺少这层映射时，导入规则的事件在
战术网格与技术矩阵里**全部落「其他」——等于白导入**。

| 文件 | 改动 |
|---|---|
| `app/services/tactics.py` | **新增**。`TACTIC_LABELS` 映射 + `tactic_from_tags()` / `techniques_from_tags()` |
| `app/services/analytics.py` | `_PHASE_ORDER` 补「横向移动」「收集」（否则映射出的战术排到 99 位） |
| `app/services/detections.py`、`app/services/dashboard.py` | 内置映射认不出时回退到规则标签 |
| `tests/test_tactics.py` | **新增** 5 条（含「映射出的战术必须在阶段表里有位置」） |

**口径**：`attack.stealth` 归到「防御规避」——ATT&CK 19.x 把它从 defense-evasion 拆出，
但本项目既有的 T1562.001 等映射都写作「防御规避」，两套词会让同一件事分成两格。

**实测**：IIS 演示日志里那条 Sigma 规则从「其他 / 可疑行为」变为 **「发现 / T1083」**。

### 真实模型评测首次跑通（10/11，暴露 1 处真实校准差异）

用户填入真实 DeepSeek Key 后执行 `scripts/eval_ai.py --real --write`：

- **用例 10/11 通过**；准确率 **91%**（TP 6 / FP 1 / TN 4 / FN 0）、漏报率 **0%**、
  误报率 **20%**（1/5 条正常用例被判为可疑）；报告已落 `docs/ai-quality-report.md`。
- **唯一失败是 `truncated-mid-line`**：模型给出 `medium`，用例标注可接受 `info/low`。
  该用例是「最后一行被截断、URL 不完整」，数据集口径是「不能凭残缺串猜意图」；
  模型没有崩溃、没有编造证据（引用覆盖率 100%），而是**保守地判为可疑**——
  属真实的模型校准差异，**不是崩溃也不是幻觉**。
- 结论：「真实模型跑一次」的价值在一小时内出现两次——先是暴露不可读的配置报错，
  再是暴露一处误报倾向。**确定性替身路径这两件事都发现不了。**
- 待定：是否调整该用例标注（承认「截断输入判可疑」是可接受行为）还是调整 Prompt
  （要求残缺证据一律不下可疑结论）。**先记录，不擅自改判据**。

### 顺手清理

- `backend/.venv` 中 pip 升级遗留的 `~cp` / `~cp-*.dist-info` / `~-p` / `~ydantic_core`
  无效分发目录（会让每次 pip 操作都打印 `Ignoring invalid distribution` 警告）。

### 新增：规则元数据补齐与格式门禁（P5-①）

**背景**：`Rule` / `RuleDefinition` / `/api/rules` / 前端展示**四层管道早就通了**
（`RuleDefinition` 一直有 `author` / `version` / `license` / `references` / `validation_status`，
前端规则面板也一直在渲染「作者 / 版本」与验证状态），**唯独 YAML 里是空的**——
实测全仓库 `grep license:` 零命中。属于「接通最后一公里」，改动面小、收益立刻可见。

| 文件 | 改动 |
|---|---|
| `app/services/rules_engine.py` | `build_rule` 新增 `defaults` 参数；`load_rules` 读文档级 `metadata` 块 |
| `app/services/rule_metadata.py` | **新增**。格式门禁 + 声明一致性检查 |
| `app/services/sigma_import.py` | 新增 `SIGMA_METADATA`；`render_rules_file` / `write_rules` 支持输出 `metadata` 块 |
| `rules/*.yaml`（10 个内置 + 2 个 Sigma） | 补文档级 `metadata` |
| `scripts/import_sigma.py` / `import_sigma_community.py` | 重新导入时同步生成 `metadata`，避免被覆盖 |
| `scripts/eval_rules.py` | 门禁并入，违规非零退出 |
| `tests/test_rule_metadata.py` | **新增** 10 条 |
| `tests/test_rule_quality.py` | 新增 1 条声明一致性用例（复用既有 `report` fixture） |
| `frontend/src/App.vue` | 修正验证状态文案 + 展示许可证 |

**关键设计：文档级继承，而不是逐条重复。** 内置 74 条的作者/许可相同，
Sigma 2198 条同源同许可，逐条重复只会让 `95-sigma-community.yaml`
（**已 3.85 MB / 130,083 行**）再膨胀一遍，而且「改一处要改一千处」。
取值优先级 **规则级 → 文档级 → 内置默认**，例外规则仍可单独覆盖（有测试钉住）。

**实测结果**

```
规则总数: 2272（builtin 74 + sigma 2198）
license:  proprietary 74 / DRL-1.1 2198      ← 0 条缺失
author:   AI-LogInsight 74 / SigmaHQ contributors 2198
validation_status: validated 81 / unverified 2191
scripts/eval_rules.py → 规则元数据门禁：通过（0 项违规），退出码 0
```

`validated 81` = 内置 74 + 精选 Sigma 7，与语料覆盖**完全一致**——
`evaluation/corpus` 里恰好引用 7 条 `sigma.*` 规则，且都在 `90-sigma.yaml` 里。

**门禁不只是格式检查，还有一条「声明必须有证据」。** 除四类格式检查
（`author` 非空 / `license` 在允许集合 / `validation_status` 在允许集合 /
`references` 必须为 http(s)）外，还要求 **`validated` ⟺ 语料里有正样本**。
理由与本项目 ATT&CK 报告一致：**「有标签」和「已验证」是两件事**，
不允许把「已验证」当成随手可写的标签。反向验证：故意写非法许可证 →
门禁失败、退出码 **1**、逐条列出违规规则；恢复后回到 **0**。

**明确不做（避免「为了做而做」）**

- **P5-② 规则类型分类**：74 条内置规则全是 YAML 检测规则，而 IOA「行为偏离」走
  `behavior_baseline.py`、**不在 YAML 里**。现在加 `rule_type` 会让 2272/2272 全是
  `detection`——等于没分。需先定「IOA 偏离是否纳入规则类型体系」，本轮不猜。

**顺带修正一处会误导用户的文案**：前端把 `unverified` 显示为「规则元数据未声明」。
这次改动后 `unverified` 已是**显式声明**（意为「无本地正样本」），
旧文案会让用户以为元数据没填，已改为「未验证（无本地正样本）」/「已验证（有本地正样本）」。

### 新增：Sigma 逐条 author / references（原「本机无 SigmaHQ 检出」的阻塞项已解）

**阻塞点的真实解法**：不需要 clone 整个仓库，直接取**指定版本**的归档即可——
`https://codeload.github.com/SigmaHQ/sigma/zip/b4ba1f2`（**短 SHA 也支持**，
与生成文件头部记录的版本号 `b4ba1f2` 完全一致，因此重跑导入**不会改变规则集**）。
12.7 MB / 2 秒下完（本机有本地代理），解压后 2418 个 Windows 规则文件。

| 文件 | 改动 |
|---|---|
| `app/services/sigma_import.py` | `convert_rule` 带上 `author` / `references`；新增 `sigma_references()` |
| `scripts/import_sigma_community.py` | 报告新增两行元数据统计；**修正 `DEFAULT_DIRS` 默认值**（见下） |
| `rules/95-sigma-community.yaml` | 重跑生成：1608/1608 带 `author`、1564/1608 带 `references` |
| `docs/sigma-import-report.md` | 重跑生成，含元数据统计行 |

**`references` 只收 http(s) 链接，且不静默丢弃**：SigmaHQ 的 Windows 规则里有
**107 条**参考是 `Internal Research` 这类非链接文本。字段语义是「参考链接」，
写进去会撞上门禁，因此不收——但导入报告里**明确报出条数**（44 条规则因此完全没有
`references`）。「不静默丢弃」与项目既有纪律一致。

**过程中发现并修掉一个真实缺陷（会造成静默少导入 447 条）**：
`import_sigma_community.py` 的 `DEFAULT_DIRS` 只写了 2 个子目录
（`windows/process_creation`、`windows/builtin`），而 PROGRESS / CHANGELOG 里给出的
复现命令**没有带 `--dirs`**——照文档重跑，候选规则会从 2417 悄悄掉到 1517、
保留数从 1608 掉到 **1161**，**且不报任何错**。已把默认值改为 SigmaHQ
`rules/windows/` 下的全部 17 个子目录，并复验：重跑后候选 2418 → 保留 **1608**，
规则 id 集合与改动前**逐条一致**（新增 0 / 丢失 0）。

**验证结果**

```
导入漏斗：候选 2418 → 排除已落盘 1 → 转换 1617 → 保留 1608（当时与改动前逐条一致）
规则集：新增 0 / 丢失 0
元数据：author 1608/1608 · references 1564/1608
scripts/eval_rules.py → 用例 123/123、内置覆盖 74/74、TP 111 / FP 0 / FN 0、
                        规则元数据门禁通过，退出码 0
```

**关于接口体积（先误判、后核实）**：`/api/rules` 响应由 996 KB 涨到 **1346 KB（+35%）**，
增量主要来自 `references`。但**核实后发现前端根本没有调用这个接口**——
`App.vue` 里只有 `/api/rules/preview`，规则元数据实际是从 **detections** 接口下发的
（`app/services/detections.py` 逐字段读取 `Rule`），而 detections 只为**真正命中的规则**建组。
因此实际影响很小：`/api/rules` 的 350 KB 只落在 API 消费方（当前无内置消费方），
detections 的增量取决于命中规则条数（典型分析只有个位数分组）。
`references` 目前前端只声明未渲染，要不要渲染留作后续决策。

### 新增：规则库体检（P5-④）

**背景**：导入时做过一次去重，但那只管「这一次导入的候选之间」；规则库是长期演进的——
后来手工加的规则、改过的 `suppresses`、新一批导入，都没有统一关口。本项补上全库体检。

| 文件 | 改动 |
|---|---|
| `app/services/rule_health.py` | **新增**。六类阻断项 + 一类观察项 |
| `scripts/rule_health.py` | **新增**。有阻断项时非零退出，`--write` 出报告 |
| `tests/test_rule_health.py` | **新增** 15 条 |
| `docs/rule-health-report.md` | **新增**（生成物） |

**六类阻断项，每类都对应一种「安静地出错」**

| 检查 | 为什么是错的 |
|---|---|
| `dangling_reference` | `suppresses` / `upgrade_rule` 指向不存在的 id——多半是改 id 或打错字，压制/升级**静默失效** |
| `self_suppress` | 规则压制自己——该规则永远不产出事件 |
| `suppress_cycle` | A 压制 B 且 B 压制 A——谁产出取决于遍历顺序，结果不稳定 |
| `asymmetric_upgrade` | A 声明 `upgrade_rule: B`，B 却没声明 `suppresses: A`——升级链断了一半 |
| `duplicate_detection` | 判据与聚合完全相同、且互相无压制/升级关系——同一条记录产出两个事件 |
| `ungrouped_aggregate` | 有聚合但 `group_by` 为空——整个时间窗并成一条，丢掉来源 IP / 主机区分 |

**`event.type` 冲突只记观察项，不阻断**：20 组冲突多由 `slug()` 截断造成
（如 `Meterpreter or Cobalt Strike Getsystem Service Installation - Security` 与
`- System` 截断后同型），而 `slug()` 同时是环境变量名的组成部分、不能随便加长；
且 `analytics._tactic` 优先按 `rule_id` 映射，类型冲突不改变判定。

**开发时踩的坑（也是本项最重要的设计决定）**：最初只拿 `where` 当判据签名，
结果把 **5 组刻意设计的 `.success` 压制对误报成「重复规则」**——
`ssh.bruteforce` 与 `ssh.bruteforce.success` 共享 `where`，靠聚合里的 `follow_up` 区分，
并互相声明了 `suppresses` / `upgrade_rule`。现签名**含聚合（含 `follow_up`）**，
且把「互相压制或升级」视为已解决。有测试专门钉住这 5 组不被误报。

**实测与反向验证**

```
scripts/rule_health.py → 2272 条规则：阻断项 0、观察项 33（event.type 冲突），退出码 0
反向验证：把 ssh.bruteforce.success.suppresses 指向打错的 id
        → 退出码 1，并【同时】抓出连带的 asymmetric_upgrade（升级链静默失效）
        → 恢复后回到 0
```

**为什么把「出厂规则零阻断项」钉进 `pytest`**：本项目没有 CI，`pytest` 就是唯一门禁机制
（同 P2-⑥ 的口径）——「定期体检」若只留一个要人手记得跑的脚本，等于没有。

### 修正：按标准 EVTX 格式解析事件数据，删掉「模型外字段」补丁

**上一版的方向错了。** ③ 里那张 `SCOPED_FIELD_MAP` 补丁表把记录模型里没有的字段映射成
`raw` + `scope:<字段名>`，指望从原始日志文本里把值抠出来。两个致命问题：

1. **变换根本没落盘**——`sigma_import._build_predicates` 里 `target_field, transform = mapped`
   的 `transform` 赋值后**从未使用**，所有谓词都走 `_field()` 硬编码的 `transform="none"`；
   `_predicate_dict` 也**不输出** `transform` 键。生成的 `95-sigma-community.yaml` 里
   `transform:` 出现 **0 次**，而 `field: raw` 有 2468 处。
   后果：885/1618 条可转换规则（1205 处字段引用）退化成未限定的 `raw` 匹配，**永不命中**。
2. **即使落盘也取不到值**——`evtx.py` 的 `raw` 只由 14 个 `EVENT_DATA_FIELDS` +
   EventID/Date/Provider/Computer 拼成，**不含** `OriginalFileName` / `ParentCommandLine` /
   `Details`（实测 1048 条真实记录里 **0 条**含这些字段名）。

**门禁为什么没抓到**：`verify_sigma_rules.py` 层 1 按谓词树反推正样本，对 `transform=none`
的 raw 谓词会直接合成 `raw = <取值>`，于是「永不命中」的规则反被判成「可端到端触发」——
88.5% 这个数字被这类规则抬高了；层 3（正常流量零命中）同样抓不到，永不命中的规则天然零命中。

**改法：让字段真实存在，而不是在模型外近似匹配。**

| 文件 | 改动 |
|---|---|
| `app/services/evtx.py` | `_system_fields` 补齐标准事件头（`channel` / `provider` / `level` / `task` / `opcode` / `keywords` / `event_record_id`）；`_event_data` 把 `<EventData>` 里**每个** `<Data Name="…">` 按标准名原样落进记录（只保留有值的；无 `Name` 的合并到 `Data`），认证事件与非认证事件都带上 |
| `app/services/sigma_import.py` | **删除 `SCOPED_FIELD_MAP`**；未登记的字段**原样直通**；修好 `transform` 传递（`_field` 带上变换、`_predicate_dict` 输出 `transform`、多字段谓词写 `field: [...]`）；新增 `provider_name → provider` |
| `app/services/rules_engine.py` | 删除 `_scoped_value` / `_scope_pattern` / `_SCOPED_FORMS` 与 `scope:` 变换分支 |
| `scripts/verify_sigma_rules.py` | 删除 scope 合成分支；清掉重复定义的 `_PLAIN_TRANSFORMS` |
| `scripts/import_sigma_community.py` | 给语料记录补 `log_type`（见下） |
| `tests/test_evtx_standard_fields.py` | **新增** 10 条 |
| `tests/test_scoped_fields.py`、`backend/_cleanup.py` | **删除** |
| `rules/90-sigma.yaml`、`rules/95-sigma-community.yaml` | 重跑生成（精选 7 条 id 集合不变，社区 2191 条） |
| `docs/sigma-import-report.md`、`sigma-rule-verification.md`、`rule-quality-report.md`、`rule-health-report.md`、`attack-coverage-report.md` | 重跑生成 |
| `README.md`、`PROGRESS.md`、`docs/IMPROVEMENT_ROADMAP.md` | 规则量与「字段限定匹配」的表述按本条改写 |

**顺带修掉一个会让误报筛查空过的缺陷**：导入脚本直接调 `evaluate_rule`，记录上没有
`log_type`，而 `Rule.logsource_ok` 会拿它过滤——带日志类型限制的规则在筛查里**一律不匹配**，
「正常流量零命中」成了空过。补上后 11 条社区规则因命中正常流量被剔除（原先 9 条），
且剔除的都是真实误报：net.exe 侦察、PowerShell 派生、wevtutil 查询、wmic 查询、
certutil 计算哈希。

**实测（漏斗与规则量）**

```
候选 2418 → 排除已落盘 1 → 转换 2202 → 去重 2202 → 误报裁剪后保留 2191（剔除 11）
规则总量：1689 → 2272（内置 74 + 精选 7 + 社区导入 2191）
跳过原因：「字段无法映射」归零；「logsource 无法映射」401 → 480（原先被字段映射挡在前面）
端到端：OriginalFileName: evil.exe 对 <Data Name="OriginalFileName">evil.exe</Data> 命中
```

**生成文件里的直接证据**（`95-sigma-community.yaml`，3.85 MB → 4.67 MB）：

| 统计项 | 改动前 | 改动后 |
|---|---:|---:|
| `field: raw` 谓词 | 2468 | **1** |
| `field: OriginalFileName` | 0 | **747** |
| `field: Details` | 0 | **843** |
| `field: ParentCommandLine` | 0 | **425** |
| `transform:` 键 | 0 | **100** |

「判据落在哪个字段上」从「全都落在 `raw`」变成「落在真实标准字段上」，这是这次改动的实质。

**成本（如实记录）**：EVTX 的 `raw` 现在渲染全部标准字段，实测三份真实样本的平均长度
分别由 191 → **618**（安全，3.2×）、107 → **164**（系统，1.5×）、102 → **261**
（应用程序，2.6×）字符。AI 侧有 `AI_RAW_TEXT_LIMIT = 640` 截断兜底，单条证据的计费上限
不变，但多数证据会顶到上限附近，实际上下文体积上升。取舍：证据里必须能看到命中的字段，
否则「命中但看不出为什么命中」——这是取证工具不能省的部分。

**遗留（同类问题，未做）**：`logsource 无法映射` 480 条被 `LOGSOURCE_MAP` 的服务白名单挡住，
而 EVTX 解析器本身能读任意通道。正确做法是给这些 `service` 映射到 `channel` 守卫
（`channel` 现在已落进记录），而不是简单放开白名单——放开会让规则跑到全部 EVTX 记录上。

---

## 2026-09-30

### 新增：证据价值评分与上下文压缩（P4 ①②③④⑤，②③ 部分完成）

**背景**：路线图 P4。动手前先实测现状，发现真实起点与文档描述不同：

- 证据选择原先只有**一个维度**——`risk_level` 静态查表（critical/high 5 条、medium 3、low 2、info 1）；
- **档位机制只在「事件证据数 > 档位」时才起作用**。实测样本日志（1~5 条证据）丢弃率全是 0%，
  真正会丢的是聚合类事件：敏感路径探测 30 次 → 1 条 medium 事件 10 条证据 → **只下发 3 条，丢 70%**；
- `build_event` 里 `records[:10]` 把事件证据上限固定在 10 条，所以档位的最大丢弃幅度是 50%~90%；
- **真正的证据遗漏风险不在深度截断，而在事件抽样**：高风险事件的基准档位就是满额，
  永远不会被深度截断；它们只会在事件抽样这一层被整条丢掉，连同全部证据一起消失。

**改动**

| 文件 | 改动 |
|---|---|
| `app/services/evidence_value.py` | **新增**。五分量价值评分（风险 / 交叉印证 / 规则来源 / 时间新颖性 / 关联度），不 import 项目内任何东西 |
| `app/services/ai.py` | `_event_value_facts` / `_chain_endpoint_keys` / `_evidence_depth` / `_high_risk_evidence_recall` / `_keep_top_value` / `_records_time_range`；`_event_context` 改为接收深度；`_fit_context_budget` 改按价值削减；两个 note 重写 |
| `tests/test_evidence_value.py` | **新增** 30 条 |

**五个分量的依据**（全部确定性、全部来自项目已有数据）

| 分量 | 依据 | 说明 |
|---|---|---|
| `risk` | 事件 `risk_level` | 主信号（AGENTS.md §8） |
| `confidence` | 同一归组实体上**不同规则**的命中数 | `Event` 结构里**没有** `confidence`，不伪造一个；这是**代理指标**，字段名与说明里都写明 |
| `reliability` | 规则 `source`：builtin 1.0 / sigma 0.6 | 内置规则有本地标注语料，510 条 Sigma 是未验证的导入规则 |
| `novelty` | 事件在同实体时间轴上的位置 | 复用「与本批次相比首次出现」这一已有口径 |
| `correlation` | 跨来源文件数 + 同实体事件数 | 见下方「修正」 |

**硬约束：评分不参与任何研判判定**——不改变 `events` / `risk_level` / `confidence` / `behaviors`。
评分只决定「下发几条证据」。已用测试守住：一旦它能影响结论，就成了「为了省钱而改判」。

**修正三处自己引入的错误**（都由实测暴露，不是推测）

1. **关联度恒等于 1.0**。最初写成「该实体活动量 / 最活跃实体活动量」，只有一份日志一个实体时
   自身就是峰值，等于给每个事件白送满分——而退化场景恰好是最常见的小日志。
   改为绝对口径 `entity_correlation(跨文件数, 同实体事件数)`（各自减 1 后除以 4 封顶）。
2. **「关键节点」覆盖率接近 100%**。单阶段链的 `stages[0] == stages[-1]`，若也算端点则
   每个孤立事件都是关键节点，标记完全失去区分能力。现只认 **≥2 个阶段**的链。
3. **端点拿到超过高风险事件的预算**。无差别给满额时，一条 `low` 端点拿到 5 条，
   超过 `high` 非端点事件的 4 条——与「风险是主信号」冲突且是纯成本上涨。
   「硬保留」的准确含义是**不被降级**（`max(depth, base)`），不是拿到全局满额。

**压缩前后的证据召回率与自动降级**

`_high_risk_evidence_recall()` 给出高风险事件的证据下发比，低于 `EVIDENCE_RECALL_FLOOR = 0.9`
时**一次性**自动降级到更完整的档位（把被抽样丢掉的高风险事件补回来）。
降级受 `EVENT_SAMPLE_HARD_MAX = 200` 约束——没有这个上限，降级逻辑本身就成了绕过预算守卫的后门；
补回后仍超限时不降级，但会如实写出 `high_risk_dropped=N`。

实测：100 条 high / 共 200 条事件 → 降级前召回 **280/400 = 0.70** → 补回后选中 80 → **110 条**，
召回 **1.00**，说明里出现 `evidence_tier=full;reason=hr_recall_low`。

**预算削减改为按价值保留**：原先按列表位置砍尾巴，砍掉哪条取决于分层抽样顺序、**与价值无关**，
一次削减可能正好砍掉唯一的 critical 事件。现按 `(是否链端点, value_total)` 排序保留，
并**恢复原顺序**（上下文必须对同一份日志逐字稳定，否则 prompt cache 前缀失效）。

**去掉一处会「对模型谎报」的设计**：`events_note` 原先硬编码
`evidence_depth=critical/high:5,medium:3,low:2,info:1`，与 `_EVENT_EVIDENCE_DEPTH` 是两份事实。
先尝试「从实现生成图例」，但发现**逐档图例对模型不可操作**（它改不了深度）却要每轮付费发送，
最终改为只声明 `evidence_cap=N`——彻底消除不同步的可能。另补 `time_range=`（取**全量**记录，
样本的时间跨度天然更窄；无时间戳写 `unknown`，不猜）。

**验证证据**

- `tests/test_evidence_value.py` 30 条通过；全量 `pytest` → **517 passed**（388s，改前 487）
- **用 P3 的门禁检查 P4 的改动**：`tokens 750→750（+0%）`，`context_bytes 26515→27145`（+2.4%，
  在 10% 容差内），准确率 100%→100% → 门禁通过。**亚阈值的变化被 `token_composition` 如实报出**，
  这正是 P3 那一行的价值。
- 生产库 `data/loginsight.db` mtime 未变（自检全部带 `LOGINSIGHT_DB_PATH` 指向 `%TEMP%`）

**P4 未完成项（2 处，均为可选优化而非缺陷）**

1. **互补证据**：同一事件内优先选实体互不相同的证据。现有机制是事件内按 `raw` 去重
   + 两块记录样本互斥，已消除重复，但未按「互补性」排序。
2. **显式的「信息增益」度量**：普通记录的现有做法是按实体/状态码/路径等维度分层轮流取，
   已消除重复与偏斜，但没有计算「这条记录相对已选集合带来多少新信息」。

### 新增：Token 成本与质量联合指标 + 发布门禁（P3 ④⑤⑥）

**背景**：路线图 P3 的 ①②③（记录 token / 逐事件归属 / 证据覆盖率）上一轮已实现。
本轮补齐 ④⑤⑥——把指标**用起来**：算质量比率、建回归门禁、出联合报告。
核心约束来自路线图原文：**禁止只以 Token 下降作为优化成功标准**。

**改动**

| 文件 | 改动 |
|---|---|
| `app/services/ai_eval.py` | `EvalReport` 加 `confusion` / `accuracy` / `false_positive_rate` / `false_negative_rate`；`CaseOutcome` 加 `metrics`；`RunResult` 委托质量指标并加 `estimated_cost`；新增 `GATED_METRICS` / `metric_row()` / `compare_gate_metrics()` / `check_token_regression()` / `render_verdict()` / `load_artifact()`；`render_markdown` 与 `render_comparison` 增质量与成本列；`build_artifact` 增 `gate_metrics` |
| `scripts/eval_ai.py` | 新增 `--baseline FILE`；门禁结论写进报告正文（不只是 stdout） |
| `tests/test_ai_eval_gate.py` | 新增 29 条 |

**顺带修掉一处自相矛盾**：`ai_eval.py` 开头就声明「可疑与否看 `risk_level`，
不看行为条数」，而 `evaluate()` 里写的是 `suspicious_actual=bool(judgement.get("behaviors"))`。
归档里因此存着一份与门禁结论互相矛盾的记录。已改为按 `risk_level` 推导——
下界由数据集标注反推（负样本允许 `info/low` 并禁止 `high/critical`，正样本期望
`medium/high/critical`，故 `medium` 即可疑下界），新增 `SUSPICIOUS_LEVELS` 常量说明依据。

**四条联合判定规则**（前两条门禁失败）

| 情形 | 判定 | 理由 |
|---|---|---|
| Token 涨超容差 + 质量未提升 | **失败** | 多花钱没换来质量 |
| Token 降 + 质量下降 | **失败** | 省下的 token 是拿准确率换的 |
| Token 降 + 质量持平或提升 | 通过 | 真优化 |
| Token 涨 + 质量提升 | 通过，**记为观察项** | 值不值这个价钱是人的决定，门禁不代为判定成功 |

准确率涨但**误报率变差不算质量提升**（对安全产品是净损失，delta 被压到 0 从而否决豁免）。

**门禁不依赖具体机制**：比较 `tokens_total` / `tokens_first_round` / `context_bytes` /
`evidence_sent` / `accuracy` / `false_positive_rate`。五类上下文整形手段（字段白名单、
分层采样、去重、证据预算、摘要指针）生效时必然落在其中某一列上，因此 **P4 实现这些机制时
不必再改门禁**。基线来自归档产物的 `summary.gate_metrics`，按同名 label（模型 + Prompt）
匹配，换了组合只提示跳过、**不静默当通过**。

**三条「不可评估 ≠ 通过」的口径**（与前几轮同一条原则）

1. 没有正常用例时误报率返回 `None`，**不返回 0**——返回 0 会显示成「误报率完美」，
   而真相是根本没测；
2. 判据崩溃时 `risk_level` 为空，**不计为「正确」**——否则一次崩溃会在准确率上
   伪装成一次成功的保守判断；
3. 两边都没账单时门禁记为**不可评估**，不计为通过也不计为失败。

**刻意不放进 `pytest` 断言**：确定性替身下质量恒为 1.0，任何合法的 Prompt 改动都会
只涨 token 不涨质量，自动断言会让门禁变成「禁止改 Prompt」。因此它是**发布门禁**（CLI，
人工触发）。但用 `test_gated_metric_names_match_the_metrics_payload` 守住了真正的静默
失效风险——指标模块改字段名而门禁读不到时，必须报错，而不是悄悄退化成「无法比较」。

**验证证据**

- `tests/test_ai_eval_gate.py` 29 条通过；全量 `pytest` 通过；
- 端到端：`--smoke --artifacts` 产出含 `confusion: {tp:2, fp:0, tn:3, fn:0}`、
  `accuracy: 1.0`、`gate_metrics.context_bytes: 26515` 的产物；
- **反向验证门禁会响**：把基线 `tokens_total` 改成 300（本次 750，+150%，质量持平）→
  门禁失败、退出码 1，报告写明「超过容差 10%，但质量未提升」。

**遗留**：门禁的基线需人工归档（当前未纳入版本库），「与上次发布比」仍依赖人工执行。

### 新增：多模型 / 多 Prompt 对比与评测产物（P2 ③）

**背景**：路线图 ③ 要求「支持同一评测集的多模型和多 Prompt 对比，保存 JSON、证据引用、
耗时和 Token 评估产物」。**本轮不调用真实模型**——② 的真实评测需用户授权，
所以这里只建能力并用确定性替身验证骨架。

**改动**

| 文件 | 改动 |
|---|---|
| `app/services/ai_eval.py` | `CaseOutcome` 加 `duration_ms` / `usage` / `evidence_refs` / `dropped_evidence_ids`；新增 `RunResult`、`render_comparison()`、`build_artifact()`、`write_artifact()` |
| `scripts/eval_ai.py` | `--model` / `--prompt`（均可重复，笛卡尔积成多个运行）、`--artifacts DIR`；多运行时打印对比表 + 逐轮明细 |
| `tests/test_ai_eval_compare.py` | 新增 23 条 |

**对比表有两张，第二张才是重点**

1. 运行对比：通过数 / 门禁 / 平均置信度 / 平均行为数 / 引用覆盖率 / 总 tokens / 计费用例 / 总耗时；
2. **逐用例风险等级矩阵**，标出「一致 / 分歧」。

「同一份日志上两个模型给出不同风险等级」比「通过率都是满分」信息量大得多——
后者可能只是用例太容易。矩阵让分歧无处藏身。

**两条口径（写进注释并用测试钉死）**

1. **缺账单显示 `n/a` 而不是 0**。服务端没回传用量，与「用量为零」是两件事。
   填 0 会让成本对比得出**反向结论**——报告说 A 比 B 便宜，其实只是 A 没测到。
   产物 JSON 里对应写 `null`，不写 0。
2. **引用覆盖率只在可评估用例上求平均**。不可评估（无行为）的用例不参与、也不当 0，
   否则「什么都没输出」会把平均值拉低成假象。这与 P2 ④ 的「不可评估 ≠ 通过」是同一条原则。

**耗时只计判据调用**，不含解析与规则分析——后者与模型无关，混进来会让不同模型的耗时不可比，
而评测的意义就是比模型，口径一混结论就废。

**Prompt 变体真的换掉了 Prompt**

`patch.object(ai_service, "SYSTEM_PROMPT", ...)` 有效，因为该全局是**调用时**读取的
（`_request_content` 里 `system_prompt = SYSTEM_PROMPT + reminder`）。
有一条测试证明换的是 Prompt 本身，而不只是对比表上的两个标签。

**诚实的边界（已写进 CLI 输出与路线图）**

用确定性替身做多运行对比**没有区分度**——替身对每个运行返回同一份结论。
CLI 在这种用法下会显式打印提示，避免有人把「两个模型都是 5/5」当成真实结论。
要看真实差异必须加 `--real`，而 `--real` 需用户授权。

**修掉自己引入的一个小问题**：产物里 `mean_confidence` 出现浮点毛刺
（`0.44000000000000006`）。产物是要归档比对的，读起来不该像有精度信息，已四舍五入到 4 位。
同时把 `duration_ms` 的取整从 1 位改到 2 位——替身太快时 1 位小数会把真实测量塌成 `0.0`，
看起来像「没测」。

**验证**

- `tests/test_ai_eval_compare.py` **23 passed**；`tests/test_ai_eval.py` 30 passed（无回归）
- 全量套件 **431 passed**（408 → 431）
- CLI 实测：单运行与原来一致；多运行（2 模型 × 2 Prompt = 4 运行）对比表与风险矩阵正确，
  `--artifacts` 产物含 `evidence_refs` / `duration_ms` / `usage`
- **反向验证**：重构 `main()` 后重验门禁退出码——故意声明不可能满足的期望 → **1**，正常 → **0**

**遗留**

- ② 真实模型评测仍未做（需用户授权）。③ 的对比骨架在真实模型下尚未跑过，
  因此「对比表能不能正确反映真实分歧」目前只有替身与构造数据两种验证。
- 对比只覆盖风险等级矩阵，没有做「同一用例两个模型给出的行为描述差异」的文本对比。

---

### 修复：模型输出形状异常时崩溃或静默丢数据（P2 ⑦ 压力场景）

**背景**：P2 ⑦ 要求覆盖「多轮工具调用 / 长上下文证据遗漏 / 模型引用不存在字段 /
过度自信 / 多语言日志」。我没有直接写断言，而是先用一个探测脚本把真实行为打出来
（期望值必须来自实测）。探测结果暴露出 **6 个真实缺陷**，全部属于同一主题：
**代码本意是容错，但有路径漏了**。

**改动**

| 文件 | 改动 |
|---|---|
| `app/services/ai.py` | 新增 `_coerce_confidence()`；`_build_structured_verdict` 构造前归一化风险等级、字符串字段只接受 `str`；`_build_behavior` 的 `evidence` 走 `_as_list`、置信度走 `_coerce_confidence`；`_normalize_evidence_ids` 接受裸字符串 |
| `tests/test_ai_stress.py` | 新增 42 条，覆盖 5 个子项 + 上述 6 个缺陷 |
| `tests/test_ai_grounding.py` | 新增 1 条词边界守卫，并写明账号回退的缺陷背景 |

**6 个缺陷**

| # | 缺陷 | 后果 | 修法 |
|---|---|---|---|
| 1 | `risk_level` 为大写 `"HIGH"` / 数字 `5` / 数组 `["high"]` | **抛 ValidationError / TypeError**，整轮 AI 研判失败 | 构造前归一化 |
| 2 | 非字符串塞进 `str` 字段（`"involved_account": 0`） | 同上，崩溃 | 只接受 `str`，否则视为未提供 |
| 3 | `confidence: NaN` | 被放大成 **1.0（最高置信度）** | NaN → 0.0 |
| 4 | `evidence: "10.0.0.1"` | 被**逐字符拆开**成 `['1','0','.','0',...]` | 走 `_as_list` |
| 5 | 行为置信度 `"high"` | **整条行为被静默丢弃** | 保留行为，置信度回退 0.0 |
| 6 | `evidence_ids: "e-1"` | 静默丢失，`dropped` 诊断也统计不到 | 按单项处理 |

**缺陷 1 的根因值得单独记一笔**：`_build_structured_verdict` 里本来就有

```python
if verdict.risk_level not in {"critical", "high", "medium", "low", "info"}:
    verdict.risk_level = "info"
```

但 `StructuredVerdict.risk_level` 是 pydantic `Literal`，**非法值在构造时就已经抛错**，
这段归一化**永远执行不到**。它看起来像兜底，实际是死代码 —— 比没有更糟，
因为它会让人以为这个场景已经处理过了。这类「看起来有防护、实际不可能触发」的代码
在评审时最容易被放过。

**缺陷 3 为什么可达**：`json.loads` 默认接受非标准的 `NaN` / `Infinity` 字面量，
而 `min(1.0, nan)` 返回 `1.0`。一个无意义的值因此变成了「最高置信度」，
和「不允许过度自信」正好相反。

**验证**

- 探测脚本逐项确认修复前后行为（`NaN → 1.0` 变为 `NaN → 0.0`，`evidence` 不再被拆开，
  行为不再被丢弃，非法风险等级降级为 `info` 而非崩溃）；
- `tests/test_ai_stress.py` **42 passed**；AI 相关 6 个文件 **261 passed**；
- 全量套件 **408 passed**（352 → 408）；
- 评测门禁 `scripts/eval_ai.py --smoke` **5/5 通过**，退出码 0。

**遗留**

- `"behaviors": [{}]` 会生成一条占位行为（置信度 0、无分析），未改，已用测试钉住现状。
  它会计入「行为条数」，而召回下界按条数判定，改动前需先确认评测口径。
- **syslog 消息体依赖英文关键词**：德语 / 中文 sshd 日志落到 `generic`、0 条记录。
  这是真实能力边界，已如实写进测试（`test_syslog_body_recognition_depends_on_english_keywords`），
  不假装支持。Web 日志则与语言无关，实测德语 UA 与 `/../../etc/passwd` 均正常解析。

---

### 修复：`_check_grounding` 从未被反向验证，一验就发现账号误报

**背景**：`_check_grounding` 是防幻觉的核心（校验 AI 结论里的 IP / 记录编号 / 账号 /
目标资产是否在日志中真实存在），但在这个文件出现之前，测试里只有
`assert judgement["unsupported_claims"] == []` —— 那是「**没抓到东西**」的断言。

**一个从未证明能报警的报警器，等于没有报警器，而且更危险**：它让人以为有防护。
所以补 `tests/test_ai_grounding.py`（14 条），逐类构造编造内容验证**每一类都被抓到**：
编造 IP（结论里 / 行为分析里）、编造记录编号、编造账号、编造目标资产、编造攻击源 IP，
以及子串陷阱（日志有 `192.168.200.51`，结论说 `192.168.200.5` 必须判编造——
用 `in` 判断会放过去）。

**一验就抓到缺陷**：`test_real_account_in_verdict_is_not_reported` 失败 ——
日志里明明有 `admin`，却被判成「引用了日志中不存在的账号」。

**根因**：`_parse_web_line` 把 nginx combined 的 `username` **写死为 `None`**
（`remote_user` 从不提取），而 `_check_grounding` 的账号分支**只查结构化字段**，
不像 IP 和目标资产那样回退查日志原文。三条路径里漏了一条。

**修法**：账号分支补 `appears_in_log()` 回退，与 IP / 目标资产一致。
代码里本来就写着这条原则——「把日志事实报成幻觉，和对正确结论的误报是同一类问题」——
只是账号分支漏了。

**为什么没改解析器**：提取 nginx `remote_user` 是**扩能力**，不是修 bug。
`correlation.py` 按 `username` 做账户维度关联、`analyzer.py` 输出 `top_users` 统计，
改动会**改变关联结果与风险等级**并波及界面。按外科手术原则只修溯源检查，
解析器的事另行决策。

**验证**：`tests/test_ai_grounding.py` **14 passed**。新增一条词边界守卫
（`adm` 不能被 `admin` 吞掉），因为回退若用子串包含，任何真账号的前缀都会被放行，
回退就形同虚设。

---

### 新增：AI 评测最小回归集分层（P2 ⑥）

**背景**：P2 ⑤ 的门禁只能手动跑脚本。路线图 ⑥ 要求「Prompt 或 AI 代码变更时自动执行
最小回归集；扩大样本集时执行完整评测」。

**改动**

| 文件 | 改动 |
|---|---|
| `evaluation/ai-cases/*.yaml` | 5 条用例加 `smoke: true` 标记 |
| `app/services/ai_eval.py` | `AiCase.smoke` 字段；`load_cases(smoke_only=...)` |
| `scripts/eval_ai.py` | `--smoke` 只跑最小回归集；报告头新增「用例范围」条件 |
| `tests/test_ai_eval.py` | 新增 6 条，最小回归集随 `pytest` 自动执行 |

**关键决定：自动执行挂在 pytest，而不是脚本**

项目**没有 CI 配置**（无 `.github/workflows`），`pytest` 是唯一门禁机制。
因此「自动执行」只能是「作为测试套件的一部分运行」——写成测试，而不是指望有人记得手动跑脚本。

**最小回归集选哪些**

5 条，各对应一类核心失败模式，漏掉任何一类对应的退化都会溜过去：

| 用例 | 拦截的失败模式 |
|---|---|
| `normal-health-check` | 误报（把正常行为报成可疑） |
| `obvious-sensitive-path` | 漏报 |
| `insufficient-evidence` | 无证据时编造结论 |
| `correlated-failures-then-success` | 多事件关联失败 |
| `truncated-mid-line` | 边界/截断处理错误 |

排除两条 3000 行规模用例（体量大，属完整评测）。

**三道守卫（防止分层悄悄失效）**

分层失效的方式是「变慢」而不是「报错」，没人会注意到，所以必须有断言兜住：

1. 最小集必须**严格小于**完整集；
2. 最小集必须**排除**规模用例；
3. 最小集条数**不得超 8**——防止有人把全部用例都标上 `smoke: true`；
4. 另有一条一致性断言：同一批用例在最小集与完整集下结论必须一致，
   否则「smoke 过了」不能作为「完整集也会过」的证据。

**验证证据**

```bash
cd backend && .venv\Scripts\python.exe -m pytest tests\test_ai_eval.py -q   # 30 passed
cd backend && .venv\Scripts\python.exe scripts\eval_ai.py --smoke           # 5/5，退出码 0
cd backend && .venv\Scripts\python.exe scripts\eval_ai.py                   # 11/11，退出码 0
```

**实测耗时（不夸大）**：最小集 **4.3s** / 完整集 **6.7s**。差距不大——Python 启动本身
就占约 3 秒。分层的价值在「样本集增长后有稳定快速通道」，**不是现在省这几秒**。

**遗留**：项目无 CI，`pytest` 需人工触发，因此严格说不是「无人值守自动执行」。
引入 CI 属新增基础设施，本轮未做。

**顺带查了一处耗时异常（结论：与本轮改动无关）**

一致性断言原本重复跑了一整轮完整集（含两遍 3000 行规模用例），单条测试耗时 8s。
改为缓存完整集报告后，测试文件从 **19.7s 降到 13.0s**——这部分是本轮实际修掉的浪费。

另外注意到全量套件耗时在两次运行间从 **2m21s 变成 4m51s**。查证过程与结论：

| 检查 | 结果 |
|---|---|
| 本轮新增测试文件的耗时 | **13s**（占套件 4%） |
| AI 相关三个测试文件合计 | 95 个测试 **28.7s**，最慢单条 5.9s |
| 对 `_validate_response` 的改动量级 | 每个 behavior 一次 `list.append`，O(1) |
| 机器内存 | 15.69 GB 总量，**可用仅 3.43 GB**，占用 78%（本次会话早前低至 1.0~2.4 GB） |

**没有证据表明是本轮改动导致**。已停掉挂了 1h14m 的预览服务后复测，耗时并未改善，
因此「后台服务占资源」也不是主因。**未能给出确凿的根因**——缺少同条件下的前后对照测量，
最可能是内存压力与文件缓存波动（本机可用内存在 1.0~3.4 GB 间浮动）。
如实记录，不编造解释。

---

### 新增：AI 研判评测与发布门禁（P2 ①②④⑤，本轮只做 ①④⑤）

**背景**：路线图 P2 要求「AI 改动有安全网」。此前只有 `tests/test_ai_regression.py` 里
5 个内联用例，且断言的是「管线不篡改模型返回值」——**没有任何东西在判断模型判得对不对**。

**改动**

| 文件 | 改动 |
|---|---|
| `evaluation/ai-cases/baseline.yaml` | 新建。核心 5 类场景（正常 / 明显异常 / 证据不足 / 多事件关联 / 误报） |
| `evaluation/ai-cases/edge.yaml` | 新建。边界 4 条（无时间戳 / 缺状态码 / 截断 / 截断但已越阈值） |
| `evaluation/ai-cases/scale.yaml` | 新建。规模 2 条（3000 条里藏 1 条异常、3000 条全正常），用 `generator.kind=repeat` 展开 |
| `app/services/ai_eval.py` | 新建。`load_cases` / `build_case_context` / `check_judgement` / `evaluate` / `render_markdown` |
| `scripts/eval_ai.py` | 新建。门禁 CLI，镜像 `eval_rules.py`：打印报告、`--write` 落 `docs/`、有缺口非零退出 |
| `app/services/ai.py` | `_normalize_evidence_ids` / `_build_behavior` / `_validate_response` 增加**只读诊断出口** `dropped_evidence_ids` |
| `tests/test_ai_eval.py` | 新建。24 条用例，重点在反向验证 |
| `docs/ai-quality-report.md` | 新建。由 `--write` 生成，报告头写明评测条件 |

**标注口径**（参照 `DiogoRibeiro7/ai-incident-analysis-agent`，实测后确定）

该项目的 benchmark 是**混合标注**而非单一严格度：`incident_expected` 布尔、
`expected_root_cause` 精确单值、`allowed_root_causes` **集合**（30 个场景里只有 3 个用，
全是「歧义 / 矛盾 / 不相关同时发生」这类） 、`expected_min/max_incidents` **区间**。
关键洞察：**歧义是数据集的属性，不是门禁的宽容**——只在证据本身真有分歧时才放宽，
不为了好过门禁而全局松绑。本项目据此映射为 `suspicious` / `risk_levels` / `min_behaviors` /
`forbid_risk_levels` / `evidence_keywords`。

**为此修掉一个真实缺陷**

`_normalize_evidence_ids` 对「模型引用了不存在的证据编号」是**静默丢弃**的。
运行时宽容是对的，但代价是这件事**完全不可观测**——模型编 3 个假证据 ID，行为照样通过，
没人知道。引用覆盖率因此无法统计。现新增 `judgement["dropped_evidence_ids"]`：
只计数、不改判定、不进 `AnalysisResult`（`_apply_ai_judgement` 是显式取键，已确认不泄漏）。

**被真实模型输出纠正的一次设计错误（值得记）**

检查器初版把「输出了行为」等同于「判定为可疑」，并在正常用例上要求 `max_behaviors: 0`。
用真实模型一跑就假失败：模型对单条正常健康检查正确给出 `risk_level=info` / `confidence=0.35`，
同时附一条 `behavior_deviation`（「低频来源地址访问健康检查路径」，分析里明写
「属统计性偏离而非攻击特征」）。**这正是本项目 P1-16 设计的行为偏离**——低置信度提示、
不改变风险等级。结论：可疑与否一律看 `risk_level`，不看行为条数；上界检查整个去掉。
这个教训已固化成回归测试 `test_low_confidence_deviation_on_benign_log_is_not_a_false_alarm`。

**验证证据**

```bash
cd backend && .venv\Scripts\python.exe -m pytest tests/test_ai_eval.py -q   # 24 passed
cd backend && .venv\Scripts\python.exe -m pytest -q                        # 346 passed（改前 322）
cd backend && .venv\Scripts\python.exe scripts\eval_ai.py                  # 11/11，退出码 0
```

**反向验证**（门禁必须证明它会失败，否则只是摆设）：

```bash
# 临时塞一条不可能满足的用例（正常日志却要求判 critical + 至少 3 条行为）
# → 报告「门禁：失败」，列出 suspicious_match / risk_level_acceptable / behavior_count
# → 脚本真实退出码 = 1
# 删除该用例后 → 11/11，退出码 = 0
```

另验证：11 条用例在 **Sigma 社区规则开/关两种环境**下结果一致（`RULE_SIGMA_IMPORTED_ENABLED`
默认 true，测试环境为 false），用例对规则集不敏感。

**遗留与需明说**

1. **本轮只做 ①④⑤**（用户明确）。②③⑥⑦ 未做。
2. **`--real` 的真实模型评测未完成验证**。过程中有一次**未经授权**的 `--real` 调用——
   key 在通用的 `AI_API_KEY` 而非我先前检查的 `DEEPSEEK_API_KEY`，我误判为「未配置」。
   该次调用产生了真实 API 费用，并暴露了上面那个检查器缺陷；但检查器已修正，
   那次结果作废，**最终版检查器尚未对真实模型验证过**。
3. **`docs/ai-quality-report.md` 是确定性替身的报告，不是真实模型评测**。报告头已显式写明。
   替身通过只说明「检查器与管线自洽」，**不代表模型判得准**。
4. 样本集 11 条对 9 类场景是「每类至少一条」，**不是统计意义上的充分样本**；
   结论不能外推为准确率。

---

### 新增：实体调查接入前端（P1 欠账收口）

**背景**：实体调查接口交付后一直只能 curl 调——`frontend/src/App.vue` 里 `/entities/` 命中数为 0，
「实体关联」模块展示的仍是 `AnalysisResult.entities` 的聚合画像，没有进入完整调查视图的入口。
上一轮修完匹配与截断后接口口径已经可靠，这轮把它接到界面上。

**改动**

| 文件 | 改动 |
|---|---|
| `frontend/src/App.vue` | 抽出 `TimelineEntry` 类型（原先内联在 `Result` 里，现由 `Result` 与 `EntityInvestigation` 共用）；新增 `EntityInvestigation` 类型；新增实体调查弹层（关联事件 / 时间线 / 原始记录分页 + 精确匹配口径说明）；「实体关联」表新增「调查」列 |
| `frontend/style.css` | 新增 `.entity-modal` / `.entity-note` / `.entity-events` / `.entity-timeline` / `.entity-page` 与 `.ledger-block h3 small` |

**设计决定**

1. **入口放在「实体关联」表里，不挂在事件或明细行上**。实体画像本来就是「这个实体的汇总」，
   从汇总点进明细是最自然的路径；挂在事件行上会让同一个实体在多个事件里重复出现入口。
2. **明确写出口径**。弹层里直接写明「实体值按精确匹配，不做模糊包含：查 10.0.0.8 不会带出 10.0.0.80」——
   上一轮刚修掉的就是这个坑，界面不写清楚，用户仍会按子串语义理解条数。
3. **截断必须说清**。`events` / `timeline` 被截断时显示「已展示 N / 共 M 条」，与事件列表、攻击链的既有口径一致。
4. **时间线为空时解释原因**，不显示空白：时间线由事件与事件证据构成，实体未命中规则时必然为空。
5. **翻页保留旧内容**，只有换实体才清空弹层，避免翻页时闪白。

**验证证据**

```bash
cd frontend && npx vue-tsc --noEmit -p tsconfig.json     # 无错误（含模板类型检查）
cd frontend && npx vite build --outDir dist-verify        # 构建通过，产物含弹层模板标识
```

端到端联调（临时库，不写 `data/loginsight.db`）：起后端（8000）+ 前端 dev server（5173），
用演示日志 `structured/auth-events-demo.csv`、`iis/iis-access.log` 各造一条分析，
**全部经前端 5173 代理**请求（不是直连 8000，确保代理链路也通）：

| 请求 | 结果 |
|---|---|
| `GET /api/health` | `{"status":"ok"}` |
| `GET /api/analysis/{csv}/entities/source_ip/203.0.113.90` | `records 21/21`、`events 1/1`、`timeline 5/5` |
| `GET /api/analysis/{csv}/entities/account/admin` | `records 21/21`、`events 1/1`、`timeline 5/5` |
| `GET /api/analysis/{iis}/entities/destination_ip/10.0.0.5` | `records 3/3`、`events 2/2`、`timeline 2/2` |
| `GET .../entities/source_ip/203.0.113.9`（前缀陷阱） | `0/0`、`0/0`、`0/0` —— 精确匹配生效，未吞 `203.0.113.90` |

字段逐项核对：模板读取的 `event.summary` / `event.name` / `event.rule_id` / `event.count`、
`entry.title` / `entry.kind` / `entry.timestamp`、`record.record_id` / `record.result` / `record.raw`
**均在真实响应中存在且有值**（`event.summary` 实测为
`203.0.113.90 在 5 分钟内出现 20 次认证失败，涉及 1 个账户，随后出现 1 次成功登录。`），
不存在渲染成空白的字段。三种 `kind` 在 `ENTITY_LABELS` 中都有中文文案。

同时确认 dev server 服务的是**改后**组件：经 5173 取 `/src/App.vue` 模块（750,973 字节），
`entity-modal`、`实体调查`、`openEntityInvestigation`、`已展示`、`不做模糊包含`、`人工确认` 均命中。

人工确认链路一并端到端走通（同一代理）：初始 `pending`/空历史 → POST `needs_review` →
POST 改判 `confirmed` → 最终 `history=2`，**改判前的 `needs_review` 记录仍在**（追加式留痕成立）；
`reviewer` 传空串返回 422。

**未验证（需明说）**

**渲染效果仍未经肉眼确认**。本机未安装 `agent-browser`，也没有可复用的 Chromium；
装一次约 500 MB，对一次截图不成比例（且本机可用内存只有 1～2 GB），因此未擅自安装。
因此上面确认的是「数据链路完整 + 组件是最新的 + 字段不缺失」，
**样式、布局、翻页按钮的实际观感仍需人在浏览器里看一眼**——已把服务留在运行态供点击。

**其他未接入前端的接口**（本轮未动，仍是欠账）：案件包导出、证据 manifest、规则审计。

---

### 修复：实体调查的子串匹配与未截断返回

**问题**（本轮熟悉项目时发现，两条都影响结论可信度而非体验）：

1. `investigate_entity` 用 `expected in record[field].lower()` 做**子串包含**匹配，
   于是查 `10.0.0.8` 会连带返回 `10.0.0.80` 的 5 条记录、查账号 `root` 会连带返回 `rootuser`。
   实体调查是**身份查询**，不是搜索：多出来的记录等于凭空造出关联，而报告读者无从分辨。
   同一函数里 timeline 又用精确比较 `item.source_ip == value`，两处口径还不一致。
2. `events` 与 `timeline` 未设上限、全量返回。一个高频来源 IP 会一次拉回整份关联事件与时间线，
   与 P0「极高基数 IP」场景直接冲突；且没有真实总数，界面无法说明「已展示 N / 共 M」。

**改动**

| 文件 | 改动 |
|---|---|
| `backend/app/main.py` | 实体匹配改为**精确匹配（忽略大小写）**；timeline 的 `source_ip` 比较同样改为精确且仅在 IP 类实体下启用（此前拿账号值去比 IP 是无意义的巧合匹配）；去掉一处与 `item.record_id in record_ids` 完全重复的判断；新增 `event_limit`（默认 50，上限 200）与 `timeline_limit`（默认 100，上限 500），事件按风险从高到低截断 |
| `backend/app/models.py` | `EntityInvestigation` 新增 `events_total` / `timeline_total`，并写明匹配口径与「已展示 N / 共 M」的要求 |
| `backend/tests/test_entity_investigation.py` | 新增，8 条用例 |

**设计决定**

1. **精确匹配，不提供 `contains` 开关**。需要模糊查找的场景已由日志明细的关键词筛选覆盖，
   两者语义不同（一个问「这个实体干了什么」，一个问「哪些记录包含这段文字」），
   在实体视图里加模糊模式只会重新引入同一类虚假关联。
2. **上限沿用既有约定**：`ge=1`，不允许 0——与 `/api/analysis/{id}` 的 `event_limit` 一致，
   避免通过接口重新拉回几十 MB 响应。
3. **截断前按风险排序**：留下的是最严重的事件，而不是最先产出的事件，与事件列表、攻击链的既有口径一致。

**验证证据**

```bash
cd backend && .venv\Scripts\python.exe -m pytest tests/test_entity_investigation.py -q   # 8 passed
cd backend && .venv\Scripts\python.exe -m pytest -q                                      # 322 passed（改前 314）
```

**反向验证**（把匹配临时改回子串后重跑，确认测试真能抓住回归）：

```
4 failed, 4 passed
FAILED test_ip_match_is_exact_not_substring
FAILED test_account_match_is_exact_not_substring
FAILED test_entity_match_ignores_case
FAILED test_similar_ips_do_not_share_events_or_timeline
```

覆盖点：IP 精确匹配（总数 5 而非 10）、账号精确匹配（`root` 不含 `rootuser`）、忽略大小写、
不存在的实体返回空结果且不推断、非法实体类型 400、空值 400、分析不存在 404、
两个相似 IP 的事件与时间线互不污染、事件截断后总数不变且最严重的在前、时间线截断后总数不变。

**已知限制（未做）**

1. **接口未接入前端**。实体调查目前只能用 curl 调，前端「实体关联」模块展示的仍是
   `AnalysisResult.entities` 的聚合画像，没有跳转到完整调查视图的入口。
2. **日志明细的 `source_ip` / `destination_ip` 筛选仍用子串包含**（`database.get_record_page`）。
   那是**搜索筛选**语义，与身份查询不同，按外科手术原则本轮未动；如果后续要统一口径需单独评估。

### 新增：AI 结论人工确认与导出分层（P1 证据链收口）

**背景**：`docs/IMPROVEMENT_ROADMAP.md` 的 P1 只剩两项未完成——AI 结论的人工确认状态，
以及导出里区分「原始事实 / 规则命中 / AI 推断 / 人工确认」。这两项合起来才成立：
只加状态而不改导出，报告里 AI 推断仍然长得像规则结论。

**改动文件**

| 文件 | 改动 |
|---|---|
| `backend/app/models.py` | 新增 `ReviewStatus`、`ReviewEntry`、`ReviewUpdate`、`HumanReview` |
| `backend/app/services/review.py` | 新增。`ReviewRepository` + `analysis_reviews` 表（追加式）+ `REVIEW_LABELS` |
| `backend/app/main.py` | 新增 `GET/POST /api/analysis/{id}/review`；报告与案件包注入确认状态；删除分析时清理确认记录 |
| `backend/app/services/report.py` | 新增 `build_provenance()`；JSON 报告加 `provenance` + `human_review`；HTML 报告新增 AI 推断区块、规则命中标注与人工确认区块 |
| `backend/tests/test_human_review.py` | 新增，10 条用例 |
| `frontend/src/App.vue` | AI 研判模块新增人工确认区块（四态选择 + 确认人 + 备注 + 历史） |
| `frontend/style.css` | 新增 `.human-review` 系列样式，跟随明暗主题变量 |

**设计决定**

1. **追加式留痕，不做覆盖式更新**。每次确认插一行，当前状态取最新一行。
   「谁在什么时候把结论从确认改成了否定」本身就是要留证的研判过程，覆盖掉就没了。
   代价是历史无上限增长——本项目按次分析、不做长期留存，暂不设上限。
2. **「未确认」不落库**。`history` 为空即未确认，不用一条假记录表示「没人看过」，
   避免界面和报告把「有人点过未确认」和「还没人看」混为一谈。
3. **确认人必填**。没有名字的确认无法追溯，等于没确认。
4. **provenance 只给定位与计数，不复制数据**。四层各自指向 `events[].evidence_items[]`、
   `events[]`、`ai_behaviors[]`、`human_review`，报告体积不因分层而翻倍。
5. **报告口径改动**：HTML 报告的「可疑事件」标题改为「规则命中事件」并加说明；
   事件确实来自确定性规则（每条带 `rule_id`），原措辞容易被读成「已确认的攻击」。

**验证证据**

```bash
cd backend && .venv\Scripts\python.exe -m pytest tests/test_human_review.py -q   # 10 passed
cd backend && .venv\Scripts\python.exe -m pytest -q                              # 314 passed（改前 304）
cd frontend && npx vue-tsc --noEmit -p tsconfig.json                             # 无错误
```

覆盖点：未确认默认态、四种状态流转、历史累积不丢改判前记录、确认人空白拒绝（400）与空串拒绝（422）、
非法状态 422、分析不存在 404、JSON 四层 provenance 与计数、确认后 `human_confirmation` 计数变化、
HTML 未确认与已确认两种文案、案件包内报告带确认信息、删除分析后确认留痕不成为孤儿。

**已知限制（未做，需明说）**

1. **确认粒度是「整条分析的 AI 结论」，不是逐条行为**。前端入口在 AI 研判模块内，
   因此只跑了规则、没跑 AI 的分析目前没有确认入口（`hasAi` 为假时该模块整体隐藏）。
   若要逐条 `ai_behaviors` 确认，需要新的数据结构，不在本轮范围内。
2. **`actor` 沿用「用户自己填」**，没有登录态（与规则审计一致，`actor` 恒为 `console` 是同类问题）。
3. **确认状态不进证据 manifest**，只进 `report.json` / `report.html`；
   案件包的 `package_integrity` 仍只覆盖原始证据与两份报告。

**顺带核对（未改动）**

- `PROGRESS.md` 记录的测试数已过期（写 295，实测改前已是 304），本轮一并修正。
- 发现但**未处理**的既有问题（避免顺手扩大改动范围）：
  ① `investigate_entity` 的实体匹配用子串包含（查 `10.0.0.8` 会命中 `10.0.0.80`），且 timeline 过滤混用精确比较；
  ② 实体调查的 `events` / `timeline` 未分页；
  ③ 上传与案件包全量驻留内存（`upload_log` 读全文件、`case-package` 组包在内存）；
  ④ manifest 的 `record_ids` / `evidence_ids` 随记录数线性膨胀。
  ②③④ 会在 P0 大文件真实验证时直接暴露，建议在 P0 开工前先处理 ③。

---

## 2026-09-24

### 文档：README / AGENTS 去重（P2-08）

两份文档同源于早期 V1.0 规范，但编号已各自漂移（README §12 = 风险等级，AGENTS §12 = AI 输出格式），
内容也各自增补，形成了同源重复。

#### 先量化，不凭感觉删

用脚本把两份文档切成章节、逐对算文本相似度，定位**真重复**。结论是重复集中在 **5 组**（≥0.50），
并非「大面积重复」：

| 相似度 | AGENTS 章节 | README 章节 |
|---|---|---|
| 0.89 | #23 数据隐私 | #19 敏感数据脱敏 |
| 0.76 | #6 工具调用原则 | #9 Agent Tools |
| 0.67 | #12 AI 输出格式 | #11 Agent 输出 |
| 0.56 | #9 可疑行为判断 | #13 重要原则：不要过度判断 |
| 0.52 | #13 behaviors | #11 Agent 输出 |
| 0.50 | #25 前端原则 | #16 推荐技术栈 > Frontend |

#### 去重原则

**约束与判定口径留 `AGENTS.md`，产品定义（字段表 / JSON schema / 技术栈 / 工具清单）留 `README.md`**，
两侧用 `§N` 指针连接，不再互相抄写。这样 AGENTS 变精简（它每会话注入，直接省 token），
README 仍是完整的产品文档，且无信息丢失。

#### 改动明细

| 位置 | 处理 |
|---|---|
| `AGENTS.md` #6 | 删除 6.1–6.5 五个工具的用途罗列（约 80 行），保留「预取哪些、按需追加哪些、全部只读」的约束 + 指向 README §9 |
| `AGENTS.md` #12 / #13 | 删除完整 JSON schema 与 behaviors 示例，保留「必须结构化 JSON」「behaviors 五个必填字段」「evidence 不得编造」+ 指向 README §11 |
| `AGENTS.md` #23 | 删除字段清单与示例，保留「AI 请求前必须脱敏、`[REDACTED]` 替换」+ 指向 README §19 |
| `AGENTS.md` #25 / #26 | 删除前后端技术栈清单，保留「前端不得直接调用 DeepSeek API」「模块职责清晰、不要把所有代码写进 `main.py`」+ 指向 README §16 / §21 |
| `README.md` #9 | 删除 5 个过时工具段，改为「工具速查」表 |
| `README.md` #13 | 精简为原则陈述 + 指向 AGENTS §9 / §11 |

#### 顺带修掉一处过时内容

两份文档的工具清单都只有最初的 5 个工具（`log_metadata` / `log_statistics` / `query_events` /
`query_evidence` / `timeline`），**缺 `query_records`、`query_terminal_chains`、
`query_behavior_deviations`、`query_uncovered_records`**。新的 README「工具速查」表
已按 `app/services/agent_tools.py` 实际注册的 **9 个工具名**核对过。

#### 结果

| 指标 | 去重前 | 去重后 |
|---|---|---|
| `AGENTS.md` 行数 | 1362 | **1186**（−176，−13%） |
| `README.md` 行数 | 2017 | 1946（−71） |
| 相似度 ≥0.50 的重复组 | 5 | **0** |
| 相似度 ≥0.40 的重复组 | 22 | 4 |

完整性核对：`AGENTS.md` 的 **36 个编号小节一个不少**、全部约束条款（只读 / 不执行处置 / 不允许幻觉 /
必须脱敏 / 必须结构化 JSON / 不得直连 DeepSeek / 不要把代码写进 `main.py` 等）逐条点名确认仍在；
所有 `§N` 指针均指向存在的小节。

### 修复：`db.destructive_query` 把日常 DELETE 判成高危 + 三处「疑似缺口」的核查结论

#### 修复：DELETE 误报（真实精确率问题）

`db.destructive_query`（high）原先把 `delete from` 直接列进词表，于是应用日常的
`DELETE FROM sessions WHERE expired_at < NOW()` 会被判成 **high 级破坏性操作**。实测确认：
两条带 WHERE 的 DELETE → 产出 1 条 high 事件、次数 2。

在真实 MySQL general log 里 DELETE 是高频业务语句，这会让精确率直接崩掉——而精确率正是
「初步检测准确率」的一半。

修法：把 DELETE 拆出来单独判定，**只有不带 WHERE（清空整表）才算破坏性**：

```yaml
- - field: url
    op: regex
    value: '\bdelete\s+from\b(?!.*\bwhere\b)'
```

DROP / TRUNCATE / SHUTDOWN 仍走原词表（出现即告警）。验证三种语句的判定差异：

| 语句 | 修复前 | 修复后 |
|---|---|---|
| `DELETE FROM sessions WHERE expired_at < NOW()` | high 事件 | **无事件** |
| `DELETE FROM audit_log`（无 WHERE） | high 事件 | **high 事件** |
| `DROP TABLE users` | high 事件 | high 事件 |

补语料 2 个（1 正 1 负，负样本专门覆盖「带 WHERE 的日常删行」），用例 121 → 123、TP 110 → 111。

#### 核查了三处「疑似缺口」，结论都是不可做

按「规则数最少 = 最该补」的思路找了三个候选，逐项验证后**都不成立**。记录在此以免重复评估：

| 疑似缺口 | 核查结论 |
|---|---|
| **网络类只有 1 条规则** | ① 实测 WAF 日志里的注入 URL **已被** `web.sql_injection` / `web.path_traversal` 接住（Web 规则用的是 `exclude_log_types` 黑名单，本就作用于 `firewall_waf`），并非只靠 `firewall.port_scan` 一条；② `PROGRESS.md` 已明确「深度 WAF 分析 暂缓，优先 Windows/Sysmon 应急响应」。**这不是缺口，是既定优先级。** |
| **`db.sql_injection` / `db.destructive_query` / `db.data_exfiltration` 未覆盖 sqlserver / oracle** | 加进去**完全无效**：这三条匹配 `field: url`，而 `_parse_sqlserver_lines` / `_parse_oracle_lines` 的 `url` **恒为 `None`**（只解析认证成功/失败与 ORA- 错误码，不提取查询文本）。现有窄范围其实是**正确的**——只包含真正能拿到查询文本的类型。**进一步核实：改解析器也没用**——SQL Server errorlog 样本只有 `Login failed/succeeded for user`，Oracle alert.log 样本只有 `ORA-01017`，**格式本身不含查询语句**。要支持得先引入 SQL Server Audit / Oracle Unified Audit 等新日志格式，属新增日志类型（`AGENTS.md` §33），不是补规则能解决的。 |
| **Redis 无命令级检测**（`FLUSHALL` / `CONFIG SET dir` / `MODULE LOAD`） | 数据源本身不支持：redis-server 默认日志**不记录命令**，样本里只有「Ready to accept connections」和「Invalid password for user」。要做只能依赖 `MONITOR`、Redis 6+ ACL 日志或代理，属另一条数据链路。 |

**教训**：规则数少不等于有缺口。判据字段是否真被填充，必须落到解析器实现上核实——
三处里有两处都是「字段根本没提取」，只看规则会误判成可以补。

#### 顺带发现（未改动）

`db.sql_injection` 词表里的 `waitfor delay` 是 **SQL Server 专有**的延时注入特征，
但该规则的 `log_types` 只含 mysql/postgresql/mongodb——这个值在当前范围内**永远不会命中**，
属无效词条。未改动（会影响词表语义），仅记录。

#### 验证

`scripts/eval_rules.py` → **123 / 123 用例 · 74 / 74 内置规则 · TP 111 · FP 0 · FN 0**，precision/recall 100%。

### 新增：内置检测规则扩容 18 条 + ATT&CK 基准清单扩充（P3-06）

目标：提高**未做 AI 研判时**的初步检测准确率。做法是先量化「哪里真的没规则」，再逐条补，而不是批量灌 YAML —— 只堆规则会让精确率掉。

#### 先量化缺口

| 分类 | 原条数 | 分类 | 原条数 |
|---|---:|---|---:|
| Sysmon/终端 | 15 | 数据库 | 7 |
| Web | 15 | 应用层 | 3 |
| 认证 | 7 | **网络（firewall）** | **1** |
| Windows 事件 | 6 | 域控导出 | 2 |

最关键的发现：**整个「影响（Impact）」战术是 0 条规则**——没有任何勒索加密、数据破坏、服务停摆的检测。另有 9 类高价值技术完全空白：LSASS 转储、SAM/NTDS 导出、清空事件日志、创建本地账户、账户操纵、破坏恢复、注册表 Run 键自启动、certutil 解码、UAC 绕过。

可行性先逐项确认：`command_line` / `process_image` / `parent_image` / `target_filename` / `registry_key` / `service_name` 均由解析器填充（`registry_key` 来自 EVTX 的 `TargetObject`，它**没有**出现在 `parser.py` 里，是追到 `evtx.py` 才确认可用的，差点误判为不可用）。

#### 新增的 18 条规则

| 战术 | 规则 | 等级 |
|---|---|---|
| 影响 | `windows.inhibit_recovery`（T1490 破坏恢复）、`windows.ransomware_extension`（T1486）、`windows.security_service_stop`（T1489）、`windows.data_destruction`（T1485） | high / high / medium / medium |
| 凭证访问 | `windows.lsass_memory_dump`（T1003.001）、`windows.sam_registry_dump`（T1003.002 + T1003.003）、`windows.credential_hunting`（T1552.001） | critical / critical / medium |
| 防御规避 | `windows.eventlog_cleared`（T1070.001）、`windows.defender_exclusion_added`（T1562.001）、`windows.certutil_decode`（T1140）、`windows.uac_bypass`（T1548.002）、`windows.hidden_file_attrib`（T1564.001） | high / high / medium / medium / low |
| 账户与持久化 | `windows.create_local_account`（T1136.001）、`windows.account_manipulation`（T1098）、`windows.registry_run_key`（T1547.001） | high / high / medium |
| 发现 | `windows.network_connection_discovery`（T1049）、`windows.file_directory_discovery`（T1083）、`windows.account_discovery`（T1087） | low / low / low |

规则总数 **566 → 584**，内置 **56 → 74**。

#### 三条防噪设计（否则会变成误报源）

1. **发现类三条要求时间窗内重复出现**（`count_gte: 3` / 300 秒）：单次 `netstat`、`dir /s` 在运维中很常见，只有短时间内反复枚举才构成发现阶段信号。
2. **发现类的判据刻意避开 `windows.discovery_command` 已覆盖的进程清单**（`net.exe` / `net1.exe` / `nltest.exe` / `whoami.exe` 等），否则同一行为会被两条规则重复检出。
3. **需要「组合条件」才告警的地方不用单条件**：`hidden_file_attrib` 要求 `+h` 与 `+s` 同时出现（单独 `+h` 是正常整理文件）；`script_interpreter_encoded` 早已确立的同类做法。

`ransomware_extension` 的词表也刻意收窄，只收与勒索家族强绑定的后缀（`.lockbit` / `.conti` / `.ryuk` 等），**不收 `.enc`、`.crypto`** 这类正常加密工具也会用的通用后缀。

#### ATT&CK 基准清单扩充：口径问题比数量重要

新加的技术（T1490、T1003.001 等）**不在**外部参考集 EVTX-to-MITRE-Attack 的 27 项里。如果只把清单从 27 扩到 45 再报一个「45/45 覆盖」，就等于把**自选清单冒充外部标尺**——这正是项目一贯反对的假覆盖。

因此给每项技术加了 `origin` 字段（`external` = 外部参考集原有 / `project` = 本项目补充），报告按两个来源**分开统计**，不合并成一个百分比：

```text
技术覆盖 45 / 45、本地正样本验证 45 / 45
  其中 外部参考集原有 27 / 27、本项目补充 18 / 18
```

`AttackCoverageReport` 新增 `external_technique_count` / `external_covered_count` / `project_technique_count` / `project_covered_count`；报告表格增加「来源」列；`render_markdown` 里写死的「清单只有 27 项」改为按实际数量动态输出。

#### 验证证据

| 项目 | 结果 |
| --- | --- |
| `scripts/eval_rules.py` | **121 / 121 用例 · 74 / 74 内置规则 · TP 110 · FP 0 · FN 0**，精确率与召回率 100%（原 85/85 · 56/56 · TP 92） |
| 新增语料 | 18 正 + 18 负，共 36 个用例（语料用例是数据，不进 pytest 计数） |
| `pytest -q` | **295 passed**（新增 1 个 ATT&CK 双口径回归测试） |
| `GET /api/rules/attack-coverage` | 45/45，两个来源分开统计 |
| 前端 | 无需改动（规则编号与类型选项动态渲染） |

#### 过程中修掉的 4 个问题

1. **`cipher /w:C:` 漏检**：正则写 `/w(\s|$)`，但 `cipher /w:C:\...` 后面是**冒号**不是空格 → 正样本 FN。改为 `/w(\s|:|$)`。
2. **正样本的 `Image` 放在临时目录**：`windows.ransomware_extension` 的正样本原本用 `...\AppData\Local\Temp\svhost.exe`，会**误触** `windows.suspicious_executable_in_temp` → 改到桌面路径。
3. **负样本撞上 Sigma 规则（两次）**：用「procdump 转储非 lsass 进程」做负样本，会命中导入规则 `sigma.2e65275c`「Procdump Execution」——**任何** procdump 调用都会命中它；改用 `Get-Process lsass` 又命中 `sigma.b2815d0d`「PowerShell Get-Process LSASS」。最终改用 `tasklist /fi "imagename eq lsass.exe"`（观察 ≠ 转储），既守住「提到 lsass 不等于转储 lsass」的边界，又不与既有规则冲突。
4. **`forbid` 字段其实没被评测器使用**：判定逻辑是「凡不在 `expect` 里的内置规则命中即算 FP」（负样本则任何内置规则命中都算 FP）。这条是在读 `rule_quality.py` 时发现的——意味着新规则若误触已有语料的日志会直接让门禁失败，因此每条判据都必须足够窄。

#### 一处偏离原定计划

原计划第三条凭证访问规则做「浏览器凭据」，实际改为 **T1552.001 凭据文件搜索**（`findstr /si password`）：浏览器凭据已被既有 `windows.credential_file_access`（T1555）覆盖，再加一条只会造成重复检出。

#### 边界

- 规则是**后端能力**，前端无需改动；`GET /api/rules` 自动暴露新规则与启停状态。
- 三条发现类规则依赖时间窗聚合，单次执行不告警。

### 新增：高信号检测规则扩展

在现有声明式 YAML 规则引擎上新增 4 条规则，并为每条规则补充正/负评估样本：

- `ssh.password_spray`：同一来源在 10 分钟内对至少 5 个账户发起 8 次失败认证；
- `auth.password_spray`：JSON/CSV 等结构化认证日志的同源多账户失败；
- `web.cloud_metadata_access`：请求云元数据服务地址或路径，提示 SSRF 后续取凭证风险；
- `windows.scheduled_task_persistence`：Sysmon 进程创建中使用 `schtasks /Create` 或 PowerShell 注册计划任务。

本轮规则库从 **562 条增至 566 条**，内置规则从 **52 条增至 56 条**。规则门禁结果为 **85/85 用例、56/56 内置规则、TP 92、FP 0、FN 0**；后端测试保持 **294 passed**。

### 改进：压缩 AI 研判提示语与上下文说明

把发给 DeepSeek / OpenAI-compatible Provider 的 System Prompt 从长说明改成短协议，保留只读边界、不得编造、规则未命中不等于正常、样本不得代替总体、证据 ID 引用、固定 JSON 输出和 structured 11 键约束。固定提示从约 2.9 KB 降到 **1.68 KB**。

同时把 `events_note` 与 `records_sample_note` 从大段自然语言改为机器可读短标记，保留总数、样本口径、证据深度、补查工具和「规则未命中不等于正常」等关键信息，减少每轮随上下文重复发送的说明文本。

验证：

- `pytest tests/test_ai_limits.py -q` → **60 passed**

### 新增：时间维度行为偏离（P1-16）

在既有 5 类 IOA 空间偏离之外，补上 3 类**时间维度**的低置信度信号：非工作时段活动（23:00–06:00）、同源高频突发、周期性心跳。

两条防噪是硬要求，否则会把正常运维打成异常：

- **突发必须有比较基线**：单来源批量任务天然「高频」，只有显著高于同批次其它来源才算偏离；
- **心跳只认高度规整的间隔**：连续间隔不规整时不出信号，避免把固定采集任务当成心跳式外联。

三者仍只进 `behavior_deviations`，**不进 `events`、不改变风险等级**（与既有 IOA 口径一致）。

**验证**：`tests/test_behavior_deviations.py` 新增 5 个用例（`test_off_hours_activity_is_reported_but_does_not_raise_risk`、`test_working_hours_activity_is_not_flagged`、`test_burst_activity_requires_a_comparison_baseline`、`test_periodic_heartbeat_only_for_regular_intervals`、`test_time_deviations_are_silent_on_existing_scenarios`）；最后一条专门验证**既有场景不因本次新增而产生偏离**，是防回归的关键一项。设计见 `docs/ioa-behavior-baseline.md` §7。

### 新增：规则预览与质量门禁（P2-06）

`POST /api/rules/preview`：提交规则草稿做校验与试运行，返回 `TP` / `FP` / `FN` 与命中事件。

- 草稿三种写法任选：`yaml_text` 全文，或 `rule` / `rules` 的 JSON 对象；
- 带 `sample_log` 时真正解析并跑一遍新规则，可传 `expected_rule_ids` 算 FN；
- **不写入规则目录**（`test_rule_preview_runs_draft_without_writing_rule_file` 直接断言规则文件数不变），因此失败也无需回滚。

### 新增：规则变更审计与接口启停（P2-07）

两条接口，落在新增的 `app/services/rule_governance.py`：

- `PATCH /api/rules/{rule_id}/enabled?enabled=false` —— 启停写入 `rule_overrides` 表，并记一条变更到 `rule_changes`；规则不存在返回 404；
- `GET /api/rules/audit?limit=100`（1–500）—— 返回 `action` / `rule_id` / `before` / `after` / `actor` / `created_at`，最新在前。

**与 `.env` 的关系**：`apply_rule_overrides()` 作用在 `build_rule()` **之后**，所以接口覆盖优先级高于 `RULE_*_ENABLED`；规则对象每次请求重建，接口改动**立即生效，无需重启**（改 `.env` 才需要重启）。

**已知边界**：`actor` 由服务端写入、默认 `console`，尚未接入登录态 —— 审计记的是「做了什么」，不是「谁登录做的」。

**验证**：`test_rule_enable_override_is_audited`（改状态 → 覆盖生效 → 审计可查）。

### 新增：AI 研判审查台账（P3-03）

每次 AI 研判落一条可追溯台账，落在新增的 `app/services/ai_ledger.py`：

- `GET /api/analysis/{id}/ai/ledger` 返回 `AiLedger`；
- `GET /api/analysis/{id}/ai/ledger/export?format=json|html|csv` 导出。

台账内容：`provider` / `model`、`tool_trace`（每次工具调用与返回摘要）、结论引用的 `evidence_ids`、被溯源校验拦下的 `unsupported_claims`、`usage`、`duration_ms` 与结束 `status`。持久化到 SQLite，服务重启后仍可查；库里没有时对已完成分析按结果现场重建。

**验证**：`test_ai_ledger_is_persisted_and_exportable` 断言 `analysis_id`、`status`、`evidence_ids == ["record-1"]`、`usage["prompt_tokens"]`、被拦下的无效引用，以及三种导出格式均可用。

### 文档同步（本轮）

新增的 4 项能力（`rules/preview`、`rules/{id}/enabled`、`rules/audit`、`ai/ledger`）**均为后端接口，前端未接入**，`README.md` 已在接口清单与 §6.5.5 中标注该事实。

同时修掉三处文档与代码不一致：

| 位置 | 原文 | 问题 |
|---|---|---|
| `README.md`（规则启停段） | 「当前版本不支持通过接口修改规则」 | 与 P2-07 已实现的 `PATCH /api/rules/{id}/enabled` **直接矛盾**，属错误陈述，不只是缺文档 |
| `README.md` §6.5.3 | 「规则覆盖 63 / 63」 | 陈旧，实际为内置 56 / 56 |
| `docs/ioa-behavior-baseline.md` §1 | 「现有 46 条规则」 | 陈旧，实际内置 56 条（另 510 条 Sigma 导入） |
| `README.md` §12 风险等级 | 与 `AGENTS.md` §10 **措辞不一致** | 两文档对同一枚举给出不同定义（例如 High：README 写「高度疑似攻击或高风险异常行为」，AGENTS 写「存在明显的高风险攻击行为特征」并附「大量认证失败 + 成功登录」示例）。代码里只有枚举值、两套措辞都未落地，属纯文档分歧；已统一到 `AGENTS.md` 口径并注明以其为准 |

> 风险等级分歧是 **P2-08（README / AGENTS 去重）** 暴露出来的第一个具体案例。两份文档同源于早期 V1.0 规范但编号已各自漂移（README §12 = 风险等级，AGENTS §12 = AI 输出格式），除风险等级外，置信度、证据要求、误报处理、UI 原则等段落同样存在同源重复。完整去重涉及删改两份大文档，本轮**只修了有实际语义分歧的风险等级**，范围外的重复留待 P2-08 单独处理。

---

## 2026-09-23

### 改进：AI 研判 Token 成本优化（P0 / P1 / P2，实测累计降幅 83%~85%）

上一轮已经把「工具轮次 10→4、自动预取 8→4、样本与事件证据去重」做完，但只是削了外围。这一轮是**按成本结构做手术**：先量化每轮请求由什么构成，再逐项打掉放大项。设计文档见 `docs/ai-token-cost.md`，可复测脚本 `backend/scripts/bench_ai_context.py`。

#### 成本模型（先量化，再动手）

Chat Completions 是**无状态**协议：第 N 轮必须重发 `system + 全部历史消息`，所以 N 轮工具调用的累计输入 ≈ **首轮 × (N+1)**。实测三大真实日志：

| 日志 | 记录数 | 首轮上下文 | 优化前累计输入（4 轮） |
|---|---|---|---|
| `access.log` | 6591 | 242 KB | 约 1.67 MB |
| `安全.evtx` | 4132 | 340 KB | 约 1.76 MB |
| 域控登录 XLSX | 12510 / 3955 事件 | 648 KB | 约 4.45 MB |

结论：**多轮重发是唯一的乘法级杠杆**，其余都是线性优化。

#### P0-3 修复 `tool_results` 绕过预算校验 + 去重

发现并修复一个真实缺陷：`request_ai_judgement()` 里 `context["tool_results"] = tool_outputs` 挂在 `_fit_context_budget()` **之后**，等于自动工具结果绕过了 2 MB 硬上限。改为先建上下文 → 执行自动工具 → 并入 `tool_results` → 最后统一过预算，并把 `tool_results` 加入削减/丢弃序列。

同时去重：自动预取的 `log_metadata` / `log_statistics` / `query_events` / `timeline` 与上下文已有的 `metadata` / `statistics` / `events` / `timeline` 块**同源重复**。新增 `_auto_tool_pointer()`，把这四个工具的返回替换为 `{summary, data_in, note, 计数锚点}` 指针，完整内容留给模型按需用工具查。**实测 9733 → 1121 字节（−88%）。**

#### P0-1 工具结果取回后裁剪历史上下文

新增 `_shrink_history_context()`：当首条 user 消息（即完整上下文）超过 `_HISTORY_SHRINK_THRESHOLD = 20_000` 字节时，从**第二轮起**替换为 `_history_context_placeholder()` 生成的摘要 JSON（`total_records` / `local_risk_level` / `coverage` / `events_total` / `query_hint`）——事实锚点保留，原始明细交给模型按需查询。函数幂等，重复调用不会继续缩小。

端到端实测：第 1 轮 243,477 字节 → 第 2/3 轮仅 5,326 / 7,679 字节。

#### P0-2 动态工具轮次与早停

新增 `_ACTIVE_EVENT_COUNT`（在 `request_ai_judgement()` 中按 `len(result.events)` 设置）。`_effective_tool_rounds()` 分档：

- **无事件（干净日志）→ 1 轮**（`CLEAN_LOG_TOOL_ROUNDS`）：没有可疑事件时追加查询的边际收益极低，不值得再付一轮全量重发；
- 有事件 → 默认 4 轮；≥2 万条记录 → 自动翻倍到 8；
- `AI_MAX_TOOL_ROUNDS` 显式配置时**始终优先**。

`complete_with_tools()` 增加 `if not calls: return` 早停，模型不再调工具时立刻收尾。

#### P1-4 记录样本字段白名单瘦身

`sanitizer.py` 新增 `record_sample_fields(log_type)` 与 `slim_records(records, log_type)`：按日志类型给出保留字段白名单，单趟完成「白名单裁剪 + 脱敏」。剔除派生字段 `timestamp_iso` / `correlation_basis`（均可从原始时间戳复算），未知字段**保留**以免丢证据。原 `sanitize_records()` 保留为向后兼容入口。

#### P1-5 事件块按风险分层瘦身

`_event_context()` 新增 `_EVENT_EVIDENCE_DEPTH = {critical: 5, high: 5, medium: 3, low: 2, info: 1}`，按风险等级决定每条事件携带多少条证据明细，并新增 `evidence_count` 字段让模型知道总数（明细可查、总数可视）。避免低风险事件也带着满额证据刷上下文。

#### P1-6 按风险分档选择上下文深度（轻量模式）

新增 `LIGHT_SAMPLE_LIMIT = 60` 与 `_is_light_context(result)`：**无事件且覆盖度完整**（`coverage.limitation` 为空、`parse_failures == 0`、`retention_drops == 0`）时判定为轻量场景，记录样本配额从 200/500 降到 60，并在 `records_sample_note` 追加口径说明。覆盖不完整时**绝不启用**轻量模式——那种情况下样本本身就是主要证据。实测干净日志：46,636 字节上下文、0 事件、60 条样本。

#### P2-7 精简 System Prompt 并为 prompt caching 做准备

- System Prompt 从 **3563 → 2895 字节（−19%）**，逐条锁定所有硬约束不丢（只读边界、不得编造、规则未命中不等于正常、不得用样本条数代替总体、11 个结构化字段、只返回 JSON）。
- 新增 `_CONTEXT_KEY_ORDER` 与 `_order_context_for_cache()`：把**稳定字段排在前面、易变字段排在后面**。DeepSeek 的 prompt cache 按前缀命中，稳定前缀可复用（命中价格约 1/10）。
- 同时删去 prompt 里**重复罗列的工具名清单**：9 个工具名已由每次请求的 `tools` 定义下发，写进 prompt 等于每轮多付一份重复文本，改为「工具清单见本次请求的 tools 定义」。

#### P2-8 接入 prompt caching（按服务端分流）

结构排序只是准备，请求还得带上服务端认得的信号。两类服务端语义不同，因此按 base_url 分流（`_needs_explicit_cache_marker()`）：

| 服务端 | 缓存方式 | 处理 |
|---|---|---|
| Anthropic / OpenRouter | 必须**显式**标记 | `_cacheable()` 在 system prompt 上打 `cache_control: {"type":"ephemeral"}` |
| DeepSeek / OpenAI | **自动**前缀缓存 | 不传额外字段，只靠稳定前缀排序；加字段反而可能被严格网关拒收 |

由 `_post()` 统一处理，且**只对 `role == "system"` 的消息转换**——user 上下文是易变内容（第二轮起还会被摘要占位替换），打标记会让缓存前缀每轮失效。开关：`AI_PROMPT_CACHE=false` 可完全关闭退回纯字符串 content。


#### 预算函数加固

`_fit_context_budget()`：说明区预留由固定 420 改为 `max(512, min(budget // 20, 4096))`（大日志给说明区更多空间）；`tool_results` 加入丢弃序列（排在 `terminal_chains` 之后）；删块后仍越界时把 `context_budget_note` 收缩成短串再抛错，避免「为了写说明而超预算」。

#### P2-9 用量与缓存命中的可观测性

前八项都在**减少请求体积**，「发得少」不等于「花得少」——账单由服务端计费口径决定，缓存命中量是唯一能直接验证 P2-8 是否生效的信号。新增 `_usage_tokens()` 把各家不统一的字段归一化：

| 服务端 | 命中数字段 |
|---|---|
| DeepSeek | `prompt_cache_hit_tokens` / `prompt_cache_miss_tokens` |
| OpenAI | `prompt_tokens_details.cached_tokens` |
| Anthropic | `cache_read_input_tokens` / `cache_creation_input_tokens` |

统一口径：`prompt_tokens` / `completion_tokens` / `cache_hit_tokens` / `cache_miss_tokens` / `cache_write_tokens` / `cache_hit_ratio`。`_merge_usage()` 再汇总各轮为一份总账（含整体命中率与轮数），以 `{"tool": "usage", "usage": {...}}` 追加进 `ai_tool_trace`。两条刻意约束：**缺失就省略、不编造 0**（把「未上报」显示成「命中 0%」会误导判断）；**降级路径也记账**（`complete()` 与 Anthropic 单次调用同样写 `last_usage`，否则「模型未走工具」时成本成盲区）。

前端「AI 研判」模块把用量从工具调用轨迹里**拆开单独展示**，且不计入「N 次工具调用」——否则会虚增次数并多出一行空条目。

#### P2-10 工具返回结果裁剪（`query_terminal_chains`，−76%）

前九项都在管**上下文**，但有一条路径不经过上下文预算：**模型按需调用的工具返回**。实测发现这里藏着最大的一块——终端类日志上 `query_terminal_chains` 单次返回 **71.8 KB**，一条链就顶掉整轮上下文的三分之一。

两个原因：① 节点带 23 个字段，其中绝大多数对该节点类型恒为 `null`（`file_activity` 不会有 `destination_ip`），原实现用 `**node` 全量展开，一半以上体积花在 `null` 上；② `timestamp` 与 `timestamp_iso` 是同一时刻的两种写法，重复下发。

修法（新增 `_chain_nodes()` + `CHAIN_NODE_FIELDS` + `MAX_CHAIN_NODES = 40`）：只保留白名单字段、**丢弃 null/空串**、丢弃重复的 `timestamp_iso`、单链节点上限 40 并回传 `node_limit_per_chain`。

顺手修掉一个**语义缺陷**：按 `kind` 过滤节点时 `record_count` 仍在报整链计数，与返回内容不符；现改为按实际返回节点数计，摘要里点明「仅 X 节点」。

| 场景 | 裁剪前 | 裁剪后 | 降幅 |
|---|---|---|---|
| 含 100 节点终端链 | 71,645 B | 17,445 B | **−76%** |
| 含 100 节点终端链（另一份） | 73,145 B | 17,445 B | **−76%** |
| IIS 3 条小链 | 2,685 B | 1,900 B | −29% |

**证据完整性未损失**：实测 40/40 节点均保留 `evidence_id`，输出中 `null` 字面量归零。`bench_ai_context.py` 增加「工具返回体积」分节，让这条路径今后可复测。

#### P2-11 两块记录样本互斥（去重，−21%~−47%）

拆解首轮上下文构成后发现**记录样本占 70%**，且两块之间存在近乎完全的重叠：`records_sample` 占 49%、`uncovered_records_sample` 占 21%。

原实现刻意允许重叠（注释写「两者会有重叠，这是刻意的」），理由是二者语义不同。但实测**重叠率 96%~97%**——规则覆盖少时，「从全体抽样」与「从未覆盖池抽样」几乎命中同一批记录，两块合计约 **47.5% 的体积是纯重复**。

**关键判断**：重叠的意图是保留**两种视角**，不是把同一批原文发两遍。视角靠 `records_sample_note` 里的计数表达（命中规则 N 条 / 未覆盖 M 条），明细则各出一份。因此让 `uncovered_records_sample` 抽样时排除已进入 `records_sample` 的记录。

| 日志 | 并集（前） | 并集（后） | 体积（前） | 体积（后） | 降幅 |
|---|---|---|---|---|---|
| access.log | 213 | **213** | 148,345 B | 117,738 B | **−21%** |
| 1.log（306 条） | 207 | **207** | 175,776 B | 92,482 B | **−47%** |
| windows-event-kv.log | 207 | **207** | 181,701 B | 95,587 B | **−47%** |

**并集完全不变**——去重的只是重复字节，模型能看到的记录种类一条没少。note 也如实改为「两块互不重复」，避免模型误以为可以相加。

顺带修掉 `_history_context_placeholder()` 里一处两语句挤在同一行的排版缺陷（本次改动引入）。

#### P2-12 `query_records` 按查询字段投影下发（−47%）

`query_records` 的下发字段此前是固定的 21 项白名单，与模型的查询条件无关。模型问「`username=root` 的记录有哪些」时，每条仍带回 `command_line`、`registry_key`、`query_name`、`process_image` 以及整条 `raw` 原文——既计费又与问题无关。

**先测后改**（合成 3000 条 sshd 日志，`limit=20` 满额返回）：

| 查询条件 | 改动前 | 改动后 | 降幅 |
|---|---|---|---|
| 不带 `field`（看全貌） | 6781 B | 6781 B | 0（刻意不动） |
| `field=source_ip` | 6780 B | 3587 B | **−47%** |
| `field=username` | 6732 B | 3546 B | **−47%** |
| `field=raw` | 6827 B | 5254 B | −23% |

三条约束保证不伤质量：

1. 未指定 `field`、或 `field` 不在白名单内 → **原样返回完整白名单**，行为完全不变；
2. `evidence_id` / `record_id` / `timestamp`（`RECORD_QUERY_ALWAYS`）**恒保留**——否则模型无法把结论挂到真实证据上，这是本次改动唯一真正危险的地方；
3. `raw` 与解析明细**互斥**：查 `raw` 只给正文，查解析字段不给正文（同一件事的两种粒度，不宜重复计费）。

`total_matched` 与 `limit` 无关——裁剪只影响下发体积，不影响命中口径。

另在 System Prompt 补一句「查到条数上限后从结果里看分布」，避免模型拿到 20 条就当成全集；字节数基本不变。

#### P2-13 修复「轮次用尽时把最后一条 tool 结果挤出末尾」

做 P2-12 时被现有测试暴露出的一个**真实缺陷，与成本无关但影响结论质量**。

`complete_with_tools()` 在轮次用尽后无条件追加收尾提示「请直接输出最终 JSON 结论，不要再调用工具」。而当模型每轮都调工具、直到轮次用尽才停下时，`messages` 末尾恰好是**刚回填的 `tool` 结果**——追加后 `messages[-1]` 变成这条 user 消息，模型读到的是「别再调工具了」而不是「你刚查到的证据」，**最后一轮工具调用等于白花**。

实测（1 轮预算、模型调 `query_events`）：

| | 修复前 | 修复后 |
|---|---|---|
| 终局请求末尾 role | `user` | **`tool`** |
| 模型实际能看到的 | 「不要再调用工具」 | 刚取回的事件证据 |

修法：新增 `_has_open_tool_round()`，仅当消息**不**停在「刚回填完工具结果、模型尚未表态」时才追加提示；收尾文案改为「请基于已获取的证据输出最终 JSON 结论」。

回归测试 `test_exhausted_tool_round_does_not_bury_the_last_tool_result` 已做**反向验证**——移除守卫后该测试会失败，确认它真的守得住。

#### 评估后决定不做：按模型自适应预算

原计划把固定的 `AI_CONTEXT_MAX_BYTES`（2 MB）改为按模型上下文上限自适应。**实测后放弃**：该预算在真实数据里从不构成瓶颈——典型日志占 0.3%~1.3%、access.log 占 11%、实测最大的域控 XLSX 也只占 **31%**。它的真实职责是**防跑飞**（源自一次真实的 HTTP 400 拒绝），改成自适应只会增加配置面与失败模式，去解决一个不发生的问题；若顺手调紧默认值，反而可能拒掉合法日志而省不下成本。依据记录在 `docs/ai-token-cost.md` §3.12，并已整理进 §7「评估后决定不做的项」以免重复评估。

#### 测试与验证

`tests/test_ai_limits.py` 从 30 → **59 个测试**；`tests/test_analysis.py` 新增 3 个终端证据链裁剪测试 + 5 个 `query_records` 字段投影测试 + 2 个收尾提示测试；新增 `tests/test_ai_usage_history.py` **7 个用例**。累计新增 48 个用例。其中 `test_record_samples_are_mutually_exclusive` 与 `test_record_sample_union_is_not_shrunk_by_dedup` 是样本去重的**质量双保险**——前者锁「两块不重复」，后者锁「并集不缩水」，两条同时成立才说明去重是安全的。

- AI 上下文定向测试：`pytest tests/test_ai_limits.py -q` → **59 passed**
- 完整后端测试：`pytest -q` → **290 passed, 3 warnings**（原 242 + 新增 48）
- 规则评测门禁：`eval_rules.py` → **78/78 用例 · TP 88 · FP 0 · FN 0**
- 前端类型检查：`npx vue-tsc --noEmit -p tsconfig.json` → 通过
- 前端构建：`npx vite build` → 通过
- 基准复测：`python scripts/bench_ai_context.py` → 首轮降幅 **30%~58%**（原 30%~36%）、多轮累计 **85%~88%**（原 83%~85%）

| 日志 | 首轮降幅（前） | 首轮降幅（现） | 累计降幅（前） | 累计降幅（现） |
|---|---|---|---|---|
| access.log | 33% | **43%** | 83% | **85%** |
| 安全.evtx | 36% | **58%** | 84% | **88%** |
| 域控 XLSX | 30% | 30% | 85% | 85% |

| 场景 | 优化前累计 | 优化后累计 | 降幅 |
|---|---|---|---|
| 域控登录 XLSX | 4.45 MB | 691 KB | −85% |
| `access.log` | 1.67 MB | 289 KB | −83% |
| `安全.evtx` | 1.76 MB | 294 KB | −84% |

#### P2-14 修复「工具轮次失败降级时丢失轨迹与用量」

做 P2-15 时先查数据，发现生产库 **49 条已完成分析、0 条带用量记录**——而用量展示早已上线。顺线索查出第二个真实缺陷。

根因在 `_request_content()` 的降级分支：`except Exception: pass` 把 `complete_with_tools` 已累积的 trace 一并丢弃。而它是**边执行边累积**的——第 3 轮失败时前 2 轮的调用与用量都已真实发生并计费。后果两层：前端轨迹空白；**用量那条 `tool == "usage"` 也在 trace 里**，被一起丢掉，这才是 0/49 的直接原因。

修法三处：`complete_with_tools()` 把 `trace` 挂到 `self.last_trace` 且**每轮都更新 `self.last_usage`**（原先只在自然收敛时写，中途失败就等于没记录）；新增 `_recover_trace()` 取回并补 usage 记录；降级分支改为返回取回的结果。另给 `AnthropicProvider` 补 `last_trace`，避免上层统一取用时 `AttributeError`。

**反向验证**：临时还原为 `pass`，`test_tool_round_failure_keeps_completed_trace_and_usage` 会失败（`assert 'log_metadata' in []`），确认测试守得住缺陷。

#### P2-15 用量展示的历史趋势（`GET /api/ai/usage-history`）

最后一项待办落地。数据源是 `analyses.result_json` 里的 `ai_tool_trace`。

**不反序列化整份结果**（单条可达数百 KB，取 30 条即十几 MB 解析开销），改用 SQLite 的 `json_each` / `json_extract` 在库内直接定位 `tool == "usage"` 那一条。

**两条口径坚持**：

1. **缺失就是 `null`，绝不填 0**——用 0 填充会把趋势图画成误导性的低谷；接口同时返回 `with_usage` / `total_points`，前端如实注明「近 N 次中 M 次有账单，均值只按 M 次算」。
2. **前端缺失点不画柱**，显式标注「无记录」，与「消耗很低」区分开。

前端在日志列表页新增「AI 研判用量趋势」柱状图（最近 12 次，柱高取相对序列最大值的比例），可切换**输入 tokens** / **缓存命中率**两种视图。

**过程中修掉一个自己写出的 bug**：柱高比例分母写死 `Math.max(1, ...)`。对 token 计数正确，但命中率是 0~1 比例——分母兜底成 1 后所有命中率柱都被压到不足 1% 高度、看起来全空。改为按模式选分母下限（`cacheMode ? 0.01 : 1`）后恢复。

#### 遗留

- 已完成或已否决项的依据：字段级裁剪 §3.13、收尾提示修正 §3.14、记录样本增量发送 §3.15（否决）、
  降级丢轨迹修复 §3.16、用量历史趋势 §3.17、按模型自适应预算 §3.12（否决）。
- **`docs/ai-token-cost.md` §6 当前无待办项**——原四项待办已全部完成或经实测否决并留证。

---

## 2026-09-23

### 改进：降低 AI 研判 Token 消耗

- 撤销会增加上下文体积的完整 `rule_hit_summary` 方案，规则详情改为模型需要时按 `rule_id` 查询，避免 500+ Sigma 规则摘要本身变成新的 Token 负担。
- 默认工具轮次从 10 降至 4；大日志仍按规模自动放宽到 8，且 `AI_MAX_TOOL_ROUNDS` 显式配置优先。
- 自动预取从 8 个工具收敛为 4 个：元数据、统计、少量事件和时间线；行为偏离、未覆盖记录、终端证据链等改由模型按需调用。
- `records_sample` 会排除已经出现在事件证据中的记录，减少同一条原始日志在事件和样本中重复发送。
- 固定 System Prompt 保持不变；它不是主要 Token 消耗来源，动态日志原文和多轮工具消息才是主要成本。

验证：

- AI 上下文定向测试：**30 passed**
- 完整后端测试：**242 passed，3 warnings**（FastAPI / Starlette 既有弃用提示）

---

## 2026-09-23

### 修复：`unverified_rules` 未写入质量报告

- `backend/app/services/rule_quality.py` 的 Markdown 渲染现在增加「未验证的导入规则清单」章节，逐条输出 `unverified_rules` 中的规则 ID。
- 同时增加「重复检出明细」章节，避免只显示数量而无法定位具体 Sigma 规则。
- `backend/scripts/eval_rules.py` 在 Windows 控制台强制使用 UTF-8 输出，避免 GBK 无法编码警告符号导致 `--write` 在报告写入前失败。
- 新增测试，确认报告包含章节并包含全部未验证规则 ID。

验证：

- `tests/test_rule_quality.py`：**6 passed**
- 生成报告：`docs/rule-quality-report.md`
- 报告核验：未验证规则清单 **503 条**，重复检出明细章节存在。

---

## 2026-09-22

### 新增：SigmaHQ 社区规则批量导入（P3-02，7 条 → 510 条）

目标是把检测规则量从「几十」拉到「几百」，前提是**不破零误报门禁**。做法是导入而不是重写，且每一步都留痕。

#### 导入器扩展（`app/services/sigma_import.py`）

- **字段映射补全**：新增 Windows / Sysmon 字段（Image→`process_image`、CommandLine→`command_line`、ParentImage→`parent_image`、TargetFilename / TargetObject / QueryName / Hashes / LogonType 等）。只映射**本项目真正解析进来的字段**——ParentCommandLine / OriginalFileName / IntegrityLevel 这类没解析的字段一律不映射，让规则按「字段无法映射」跳过，而不是转换出一条永远不命中的假规则。
- **日志源补全**：新增 `process_creation` / `file_event` / `registry_set` / `registry_event` / `dns_query` / `network_connection` 与 Windows `security/system/application` 通道。
- **通配符**：普通取值里的 `*x*` / `x*` / `*x` 按 Sigma 语义转 contains / startswith / endswith；混合形态或中间通配（`a*b`）**整条跳过**（要展开成 OR，超出 where/any 能表达的范围，宁缺勿乱）。
- **必要条件（guards）**：给终端类规则自动补 `status == Sysmon EventID`（如进程创建 = 1、文件 = 11、DNS = 22）和「字段必须存在」。这两条都是 Sigma 分类**隐含成立**的条件，补上后不改变判定结果，但让规则索引有了高区分度键——**没有这一步，500 条导入规则会退化成「每条记录跑全部规则」，实测规则耗时从 2.2s 飙到 48s**。补上后回落到 **3.7s**。

#### 批量导入脚本（`scripts/import_sigma_community.py`）+ 落地文件

漏斗（1512 候选 → 503 落地，每步都写进 `docs/sigma-import-report.md`）：

| 阶段 | 数量 |
|---|---|
| SigmaHQ 候选（process_creation + builtin，commit `16eb58704e94`） | 1512 |
| 转换成功 | 504 |
| 去重（同 uuid / 标题 / 判据签名；并排除与 90-sigma.yaml 精选重复的） | 504 |
| 误报裁剪（在本地**正常流量**用例上必须零命中） | **503** |

跳过 1007 条的 Top 原因：字段无法映射（948，如 `Description`）、logsource 无法映射（30，如 `applocker`）、修饰符不支持（28，如 `windash`）。

#### 门禁口径调整（这是「不破零误报门禁」的关键）

- **内置规则**：仍然每条必须有本地正样本。
- **导入的社区规则**：做不到逐条配样本，验收口径改为「在正常流量用例上零命中」；未验证的导入规则在质量报告里**单独列出**（`unverified_rules`，当前 503 条），不混进「已覆盖」。
- **误报定义收窄到「正常流量被当成异常」**：社区规则在攻击样本上重复命中属「重复检出」（`duplicate_hits`，当前 4 次），计数但不判失败——否则没人敢导入任何规则。
- `RuleQualityReport` 新增 `builtin_rule_count` / `imported_rule_count` / `unverified_rule_count` / `duplicate_hit_count` 等字段。

验证：`pytest` **242 passed**；门禁 **78/78 用例 · 内置 52/52 · TP 88 · FP 0 · FN 0**；大日志基准规则耗时 **2.2s → 3.7s**（562 条规则、60k 记录）。测试环境默认关闭社区规则（`conftest` 设 `RULE_SIGMA_IMPORTED_ENABLED=false`），门禁测试单独启用，否则套件会从 ~6 秒拖到 ~4 分钟。

遗留：503 条社区规则**没有本地正样本**，只在正常流量样本上做过零命中筛查，真实环境仍可能误报（报告已明说，可用全局开关一键关闭）；`evaluate()` 在 562 条规则下跑一遍约 20 秒，门禁比之前慢，属可接受范围。

### 新增：ATT&CK 覆盖尺子 + 补齐两个执行类缺口（P3-01）

对标公开样本集后要回答的问题只有一个：**我们到底覆盖了哪些攻击手法、哪些完全没有证据支持**。先做尺子，再补规则——顺序不能反，否则补出来的规则会被错误的覆盖率误导。

#### 尺子：外部样本只作标尺，不打包

- 新增 `app/services/attack_coverage.py` + `evaluation/attack-benchmark.json`（27 项优先技术）+ `scripts/attack_coverage.py` + `GET /api/rules/attack-coverage`，报告写到 `docs/attack-coverage-report.md`。
- **270 是外部参考集（EVTX-to-MITRE-Attack，>270 个第三方 EVTX 样本）的规模，没有打包进仓库，产品也不解析它**：第三方样本有许可与恶意样本处置风险，且会把仓库撑大。这里只引用「其中出现过哪些技术」当标尺。
- 报告刻意分三个口径，避免把「有标签」当成「已验证」：

| 口径 | 含义 | 当前 |
|---|---|---|
| 有规则 covered | 存在映射到该技术的规则 | 27 / 27 |
| 有本地正样本 | 标注语料里真的有用例命中过这条规则 | 27 / 27 |
| 外部参考样本 | 第三方样本规模，只作标尺，未打包 | >270 |

- 另加两条防误读：**「有规则但缺本地正样本」单独列出**；清单全部覆盖时报告会自动加一句「27 项不等于 ATT&CK 全量（Enterprise 200+），下一步价值在扩充清单」。

#### 顺带修掉三处不可信的数据（这几处比缺规则更容易误导人）

1. 逐技术的 `reference_samples` 全是「1」，是把「出现在参考集中」写成了「样本数」——**编的数字比没有数字更糟**，已删除该字段。
2. `T1070.004` 名称写成「File and Directory Discovery: File and Directory Deletion」（把 T1083 的名字接在 T1070.004 上），已改为正确的 **Indicator Removal: File Deletion**。
3. 攻击链用例数报 0，是因为计数口径只认 `scenario: attack_chain` 标记。现在分两个数：**整份真实日志用例 4** 与**攻击链场景 family 2**，与 `PROGRESS.md` 的历史表述对齐。
4. **收紧一处过度映射**：`web.404_scan` 原本映射 T1046「网络服务扫描」，但它的实际语义是 Web 目录/文件枚举（属 Active Scanning / Discovery，不是服务扫描）；T1046 由 `firewall.port_scan` 覆盖即可，去掉后覆盖仍为 27/27。另外把映射口径写进 `RULE_TECHNIQUES` 的注释（「宁缺勿宽」，并记录 `windows.suspicious_executable_in_temp` 刻意不映射 T1204 的原因）。
   - ⚠️ 同时标注了一处**未擅自改动**的宽松映射：`db.privilege_escalation` → T1068「利用漏洞提权」，但该规则判据其实是 GRANT / CREATE USER / SET GLOBAL 这类**权限变更语句**（更贴近 T1098）。改它会立刻变成真缺口（当前没有规则覆盖「漏洞利用提权」），因此把选择权留给负责人，没有偷偷调低覆盖率。

#### 补齐清单里最后两个缺口

| 新规则 | 技术 | 级别 | 判据与误报边界 |
|---|---|---|---|
| `windows.script_interpreter_encoded` | T1059.001 PowerShell | high | ① 编码命令（`-EncodedCommand` / `-enc ` / `FromBase64String`）；② 「隐藏窗口 + 不加载配置文件 / 绕过执行策略」**同时出现**。**刻意不匹配** `-File`、明文 `-Command` 与 `IEX + 下载`：前者是正常运维写法，后者在 Chocolatey 等软件分发脚本里同样常见，误报不可接受 |
| `windows.command_shell_suspicious_parent` | T1059.003 Windows Command Shell | medium | cmd.exe 由文档编辑器 / 压缩工具 / 脚本宿主 / mshta 启动。**刻意不匹配** explorer、终端服务、计划任务启动的 cmd（那是正常运维） |

- 为第二条新增渲染占位符 `{parent}`（`rules_engine` 的两处 `context` 同步加），摘要里能直接给出父进程名，而不是让用户自己去翻原文。
- 三处同补：`analytics._TACTICS`（否则杀伤链显示「其他」）、`analyzer._build_recommendations`（否则只有兜底建议）、`.env.example`（两个规则开关）。
- 语料新增 3 个用例：编码命令正样本、Word 启动 cmd 正样本、**解释器正常用法负样本**（明文 `-File` + `-ExecutionPolicy Bypass`、explorer 启动的 cmd 必须 0 事件）——把「组合判据」的边界钉死。

验证：`pytest` **242 passed**；门禁 **78/78 用例 · 59/59 规则 · TP 88 · FP 0 · FN 0**；覆盖报告 27/27 有规则、27/27 有本地正样本。文档同步：`PROGRESS.md`（能力表 / 规则清单 / 验证命令 / P3-01 状态与交付记录）、`README.md`（规则数 59、覆盖报告能力、评估结果 78/59/TP 88）。

遗留：这份清单只有 27 项，**满覆盖不等于检测能力到顶**。下一步是扩充清单本身（新技术的样本与规则一起加），以及 P3-02 的 Sigma 规则量扩容。

### 完成：AI 上下文硬上限、任务恢复与第二轮内存优化

- `AI_CONTEXT_MAX_BYTES` 现在是真正的最终发送边界：上下文缩减、追加预算说明、移除低优先级块后会再次计算序列化字节数；仍超限时直接返回可行动错误，不发送超过预算的请求。
- AI 任务在服务启动时扫描 SQLite 中遗留的 `running` 任务，恢复为 `recovering` 阶段并重新启动同一个 `task_id + analysis_id`。不存在对应分析记录时标记为失败；重复执行恢复不会重复启动。恢复是从头重跑，不承诺模型 token 级断点续跑。
- `build_ai_context()` 不再先复制并脱敏全部日志记录，只对分层采样结果和未覆盖样本复制脱敏，保留原始记录用于规则、工具查询和证据校验。
- 新增上下文硬上限、无法容纳最小上下文、任务单次恢复、缺失分析失败和重复恢复保护测试。

验证：

- 定向测试：**37 passed**
- 后端完整测试：**240 passed，3 warnings**（FastAPI `on_event` 与依赖项弃用提示）
- 大日志基准：11.1 MB / 60,018 条，峰值内存 **49 MB**，解析 2.72 秒，规则匹配 4.59 秒，覆盖率 100%。

---

## 2026-09-22

### 改进：事件与攻击链改为增量分页

- `/api/analysis/{id}` 新增 `event_offset`，前端加载更多事件时只请求下一页，不再重复传输已经展示的事件。
- `/api/analysis/{id}/insights` 新增 `chain_offset`，攻击链加载更多同样只返回下一页。
- 保留 `events_total` / `attack_chains_total`，风险排序和每页硬上限不变；报告导出仍读取完整存储数据。
- 新增分页回归测试，覆盖事件和攻击链的连续页不重复。

验证：分页定向测试 **14 passed**；完整后端 `pytest` **237 passed**；前端 `vue-tsc -b` 通过。

---

## 2026-09-22

### 收紧大响应与 AI 上下文边界

- 普通分析详情接口默认返回 200 个事件，硬上限 1000；攻击链接口默认返回 20 条，硬上限 100 条。`event_limit=0` / `chain_limit=0` 不再允许，避免通过普通接口重新拉取完整大响应；报告导出仍保持全量。
- AI 上下文新增 `AI_CONTEXT_MAX_BYTES`，默认 2,000,000 字节。构建上下文后若超预算，会按事件、记录样本和未覆盖记录样本逐步缩减，并写入 `context_budget_note`。
- 新增边界回归测试，覆盖无限制参数拒绝和上下文超预算自动缩减。

验证：后端 `pytest` **235 passed**；前端 `vue-tsc` 通过，`vite build` 在受控环境因 `esbuild spawn EPERM` 未完成。

---

## 2026-09-22

### 修正：大日志下 AI 研判 400、历史详情卡在「正在加载」（同一根因：事件没有上限）

用户反馈两个现象。实测后确认**同源**：事件列表全量进上下文、也全量进 HTTP 响应。

#### 现象一：AI 研判返回「AI 服务返回 HTTP 400」

实测复现并拿到服务端原话：

```
HTTP 400
This model's maximum context length is 1048576 tokens.
However, you requested 7981061 tokens (in the messages)
```

域控导出（12510 条记录 / 3955 个事件）的 AI 上下文达 **14.52 MB ≈ 798 万 tokens**，其中 `events` 占 13.80 MB（95%）——每个事件还整份带上 `evidence_items[].raw` 与 `timeline`。

修复（两层）：

1. **上下文瘦身（根因）**：新增 `_sample_event_indexes()`，按 **规则 / 风险等级 / 类型 / 来源** 四个维度分层抽取事件（上限 80），并限制每个事件的证据条数（5）、时间线条数（5）、`evidence` 条数（8）；`risk_scores` 上限 50。新增 `events_note` 写明**总数与采样口径**，并指引模型用 `query_events` / `query_evidence` 补查。上下文 **14.52 MB → 0.57 MB（798 万 → 20 万 tokens）**。
2. **错误可读化**：`_open()` 现在读取错误响应体，`_classify_http_error()` 把服务端 message 带出来；并按关键词识别 **`context_too_long`（输入上下文超出模型上限）**，提示改为「减少一次性分析的日志量（分批上传）或改用上下文更大的模型」，不再一律甩「请检查密钥」。其余类别也各给对应建议（`NON_RETRYABLE_ADVICE`）。

真实复测：同一份域控导出 **35 秒完成，风险 high / 置信度 0.88**，结论给出非工作时段 3282 条、`anonymous logon` 71 次、高频来源 IP 排名等细节。

#### 现象二：点历史记录一直显示「正在加载分析结果…」

不是卡死，是**载荷过大**：`/api/analysis/{id}` 对大记录返回 **20~37 MB**（最多 7536 个事件，每事件含证据原文与时间线），前端要解析这份 JSON 并一次性渲染全部事件卡。

修复：

- 详情接口新增 `event_limit`（默认 200，`0` = 不裁剪），响应按上限裁剪 `events`；新增 `AnalysisResult.events_total` 保存**真实总数**，避免界面谎报「只有 200 个事件」。老记录没有该字段时按裁剪前的长度补齐。
- **只裁 HTTP 响应、不改存储**：HTML/JSON 报告直接读存储，导出仍是完整清单（新增测试锁住这条）。
- AI 任务载荷里的 `result` 同样裁剪，保证前端赋值后行为一致。
- 前端：事件计数改用 `events_total`；被裁剪时显示「按风险从高到低展示前 N 条」+「加载更多事件」按钮（每次 +200）。

实测：

| 记录 | 改前 | 改后 |
|---|---|---|
| 域控 10.0.0.11（3955 事件） | 20.05 MB / 1.25 s | **1.80 MB / 0.43 s** |
| 2 个日志文件（7536 事件） | 37.32 MB / 2.34 s | **1.83 MB / 0.76 s** |
| `event_limit=0`（导出） | — | 仍为全量 |

#### 顺带修掉一处溯源误报

复测里证据校验报「结论引用了日志中不存在的 IP：10.0.0.11」，但那**正是目标主机**（域控导出把资产写成 IP）。`_build_grounding_index` 只把 `source_ip` / `destination_ip` 计入已知 IP，漏了 `target_asset`。已修：资产值若形如 IP 即计入已知 IP；编造 IP 仍会被抓。

验证：`pytest` **225 passed**（新增 `tests/test_analysis_payload.py` 4 条、事件采样与 400 分类 3 条、溯源 1 条）；门禁 **75/75 · 57/57 · TP 86 · FP 0 · FN 0**；前端 `npm run build` 通过。

### 修正：AI 洞察的攻击链无上限（2000 条链 / 2.33 MB）+ 洞察状态残留

用户指着导航里的「AI 洞察 **2047**」反馈：记录太多，既吃内存也吃 token。查下来是两件事，其中一件比反馈的更严重。

#### 现象一：2047 是**上一条记录**的数字（状态残留，正确性问题）

那张截图是「只有 1 条记录的 auth.log」，但卡片上写着 2047。逐条核对后确认：2047 = 域控导出那条记录的「48 个时间段 + 1999 条攻击链」。

根因：`upload()` / `analyzeDemoLogs()` 只设了 `result` 就切到详情页，**既不重置 `insights` 也不重新拉取**（只有从历史列表点进去的 `openAnalysis()` 会拉）。于是新记录顶着上一条记录的柱状图、攻击链与计数，分页上限也沿用上一条记录的值。

修法：新增 `enterAnalysisDetail(analysis)` 作为进入详情的唯一路径（重置 `eventLimit`/`chainLimit`/`insights` 后统一拉取记录与洞察），三条入口（上传 / 演示 / 历史）都走它。

#### 现象二：攻击链数量 = 来源 IP 数，且没有上限

| 记录 | 记录数 | 攻击链 | `/insights` 载荷 |
|---|---|---|---|
| 域控 10.0.0.10 导出 | 11091 | 1999 | **2.33 MB** |
| 2 个日志文件 | 23601 | 2214 | 2.61 MB |

前端会为每条链渲染一张卡片（链内还有若干阶段卡），2000 条链就是上万 DOM 节点——和之前 7536 个事件把页面压住是同一类问题。

修法（与事件列表同一套口径）：

- `build_attack_chains(events, entities, max_chains=0)`：排序键改为 **风险 → 阶段数 → 触发次数合计 → 起始时间**，再按 `max_chains` 截断。服务层默认 0（不截断），由 HTTP 层决定上限。
  - 「阶段数」优先于「次数」是有意的：阶段多说明行为链更完整，最值得先看。真实数据里排第一的是 3 阶段的一个内网地址，其后才是单地址 2.5 万次的另一来源。
- `/insights` 新增 `chain_limit`（默认 20，`0` = 全量）；`Insights.attack_chains_total` 存真实条数，界面显示「共 N 条 · 按风险从高到低展示前 M 条」+「加载更多攻击链」（每次 +20）。
- 实测：**2.35 MB → 33 KB（-98.6%）**；`?chain_limit=0` 仍可拿全量。

#### token：洞察数据从来不进 AI 上下文（附带做了一处去重瘦身）

先说结论：`timeseries` / `attack_chains` 不在 `AnalysisResult` 里，`build_ai_context()` 也从不引用它们——**「洞察 2047 条」的 token 成本是 0**，之前的 400 是事件列表造成的，与洞察无关。

顺带查了 AI 上下文（实测域控 0.75 MB / 大日志 1.06 MB，各字段都已限条），发现一处纯浪费：**`event.evidence` 与 `evidence_items[].raw` 是同一批原文**（构造事件时 `evidence` 就是取 `raw` 填的），同一段文本进上下文两遍——80 个事件里 306 条 evidence 有 **293 条逐字重复**。现在 `_event_context` 只保留 items 窗口之外、未重复出现的原文，并在 `events_note` 里说明「items 才是权威证据全集」。

- 域控：上下文 **747 KB → 663 KB（-11%）**，events 块 468 → 365 KB（-22%），原文一条不少。
- 测试锁死「两个列表无交集」且「合起来等于限条内的全部原文」。

验证：`pytest` **234 passed**（新增 `tests/test_insights_payload.py` 4 条 + 事件上下文去重 1 条）；门禁 **75/75 · 57/57 · TP 86 · FP 0 · FN 0**；前端 `npm run build` 通过；后端已重启，真实接口复测：洞察 33 KB / 20 条链 / total 1999，详情 1.96 MB，小记录洞察 708 字节。

遗留：无。

### 修正：事件列表改为「按风险从高到低」

上一条的遗留：`event_limit` 是「从头截取」，于是截断时最先看到的批次不代表最严重的批次。现已按风险排序。

- 新增 `models.sort_events_by_risk()`：**风险等级降序，同级按触发次数降序**（同一规则反复触发通常比偶发一次更值得先看）。用的是稳定排序，等级与次数都相同时保持原有检测顺序，不制造随机抖动。
- **落库前排一次**（`analyzer` 构造 `AnalysisResult` 时）：详情、HTML/JSON 报告、导出共用同一顺序。定级、异常评分、杀伤链串联都在排序之前完成，判定结果不受影响。
- **读取时再排一次**（`_trim_events`、`export_report`）：历史记录落库时是检测产出顺序，不做这一步点开旧记录仍是老顺序。
- 前端文案同步：被裁剪时说明「按风险从高到低展示前 N 条」，并恢复展示最高等级——排序后已加载部分必然包含最高等级，之前「不再声明最高等级」的限制可以撤掉。

真实入库数据核对：

| 记录 | 事件构成 | 排序前前 3 条 | 排序后前 3 条 |
|---|---|---|---|
| 域控 10.0.0.10 导出 | 3581（high 2000 / medium 1581） | 15167 次 · 26 次 · 34 次 | 15167 次 · 9458 次 · 5075 次 |
| 2 个日志文件 | 7536（high 4116 / medium 3420） | 前 200 条已全是 high，但次数乱序 | 前 200 条是 high 里触发最多的 200 条 |

等级混杂才是主要收益：规则是按文件顺序逐条评估的，medium 规则排在前面时（如 `30-web-access.yaml` 的敏感路径探测在敏感文件成功读取之前），截断会先塞满 medium。新增测试就用「高风险写在日志最后一行」的日志锁住这条：`?event_limit=1` 返回的必须是那个 high。

验证：`pytest` **229 passed**（新增 4 条：列表按风险排序、截断保留最严重的一条、老记录读取时补排、同级按次数排序且幂等）；门禁 **75/75 · 57/57 · TP 86 · FP 0 · FN 0**；前端 `npm run build` 通过。

遗留：无。

---

## 2026-09-22

### AI 链路：错误分类重试 + 实时输出 + 任务状态持久化（P2-01 / P2-02 / P2-03）

#### P2-01 错误分类与重试

原先所有失败都压成两句笼统提示，且从不重试。现在按「能不能自己好」分类：

| 类别 | 触发 | 处理 |
|---|---|---|
| 鉴权失败 | 401 / 403 | 不重试，提示去查模型 / 密钥 / 接口地址 |
| 请求被拒绝 / 接口不存在 | 400 / 404 / 405 / 422 | 不重试 |
| 调用被限流 | 429 | 重试，优先按服务端 `Retry-After` 退避 |
| AI 服务端故障 | 其它 4xx / 5xx | 重试，指数退避（1s → 2s，上限 30s） |
| 网络不可达 | `URLError` | 重试 |
| 响应格式异常 | 响应体不是合法 JSON / 不是对象 | 重试（网关偶尔返回 HTML 错误页） |
| 响应超时 | `TimeoutError` | **不重试** —— 单次上限已是数百秒，自动重试会让等待变成 15~30 分钟，与实际收益不成比例，交给用户决定 |

- 重试次数 `AI_MAX_RETRIES`（默认 2，即最多 3 次尝试）。提示文案会说明「已自动重试 N 次仍失败」，用户能区分「该等」与「该改配置」。
- **模型输出不是 JSON** 这一类格式错误单独处理：复用同一份上下文再要一次，并重申「只输出 JSON 对象」。两次都失败才上报，且给出可行动的说明而不是 json 的原始报错（`Expecting value: line 1 column 1`）。

#### P2-02 实时输出

- 传输层抽出 `_open`，一次请求与流式请求共用同一套超时口径与错误分类。
- 新增 `_stream_message`：解析 SSE 分片，**工具调用参数在流里是分片到达的**，按 `index` 累积后拼回完整 `tool_calls`，因此 `complete_with_tools` 完全不必区分两种取回方式。
- `request_ai_judgement(..., delta_cb=...)` 把增量文本回调给任务；前端在进度条下方展示「模型实时输出」。
- **与结论解耦（产品要求）**：增量文本只用于展示。最终结论始终来自完整文本经 `_extract_json` → `_validate_response` → 证据校验后的结果，因此流式中断既不改动规则结果也不改动结论；流式请求失败会自动退回一次性请求，研判照样完成。测试里专门锁了两条：流里的残片不会被当成结论、流式失败仍出结论。
- 增量文本只保留最新 4000 字符，且最多每 2 秒落盘一次（展示用，不必逐块写库）。

#### P2-03 任务状态持久化

- 新表 `ai_tasks`（与 `analyses` 同库另表），`GET /api/ai/tasks/{id}` 先查内存、未命中回落数据库，因此**服务重启后与多 worker 部署下都能查到进度与结果**。
- 内存 `updated_at` 是 epoch 秒（TTL 清理用），落盘统一转 ISO，保证 `updated_at < cutoff` 同口径比较。
- 数据库侧按同样的 TTL（30 分钟）清理已结束任务，**运行中的任务永不删除**；清理刻意在锁外执行，避免持锁做 I/O 阻塞进度查询。
- 落盘失败不抛出：一次写锁冲突不该让几分钟的研判白跑。

验证：

- `pytest` **217 passed**（新增 `tests/test_ai_streaming.py` 5 条、`tests/test_ai_task_persistence.py` 6 条，以及 P2-01 的 7 条错误分类用例）。
- 因新增可选回调参数，更新了 8 处测试桩签名（`complete` / `_post` / `fake_ai` / `failing_ai`）与 1 处文案断言——属接口变更，非回归。
- **真实 Provider 端到端**（DeepSeek `deepseek-chat`，`windows-event-kv.log` 306 条）：上传 → 3 条规则事件 medium → 启动 AI 任务 → **实时文本 867 → 3711 → 4000 字符（流式生效，且达到保留上限）** → 27 秒完成 → 结论 medium / 置信度 0.7、给出 3 项行为分析（含规则未直接给出的 `SeBackupPrivilege` / `ServerManager` 细节）→ 工具调用 8 次（均为自动工具）→ **证据校验 0 条无效断言** → 任务状态可从存储读回。

遗留：

- 流式用的是「任务字段 + 600ms 轮询」而不是 SSE：现有进度机制本就是轮询，这样不必新增一套连接管理。若要真正的 SSE 推送需单独排期。
- 本次真实的 8 次工具调用**全部来自自动工具**，模型没有主动调用 `query_records`。说明「让模型自己挑工具去查」这条路径尚未在真实样本上被验证，需要更多样本观察。
- Anthropic 协议未实现流式（是另一套 `content_block_delta` 协议），走单次调用。

---

## 2026-09-22

### 大日志性能收尾：规则匹配索引化 + 记录内存瘦身（P1-17 / P1-18）

11 MB / 6 万条的实测变化：

| | 改前 | 改后 |
|---|---|---|
| 解析耗时 | 0.75 s | 0.85 s |
| 规则匹配耗时 | 9.5 s | **2.2 s**（目标 < 2 s，最优 1.9 s） |
| 峰值内存 | 90 MB | **49 MB**（-46%，约 820 字节/条） |

#### P1-17 规则匹配

cProfile 显示热点是「每条记录 × 每条规则 × 每个谓词」的函数调用链（实测 174 万次 `_match_field`、163 万次 `matches`）。

- **谓词预编译成闭包**：`Predicate` 新增 `matcher`，在 `__post_init__` 里把「读字段 → 判空 → 大小写归一 → 比较」固化成单个闭包；`Rule.covers` 直接调用 `matcher`，省掉 `matches` / `_match_field` / `FieldSpec.read` 三层调用。
- **字段读取器闭包**：`_field_reader` 把变换与默认值判断固化，无变换字段退化为一次 `dict.get`。
- 早前已落地并保留：归一化常量预计算、多值匹配合并为单次正则扫描、按日志类型与必要条件（`equals` 优先于 `exists`）挑选候选规则。

**一处必须记住的边界**：带 `follow_up` 的规则**不能**按索引裁剪记录——`follow_up` 是在完整记录集里检索「失败之后的成功」，那类后续记录本身不满足主 `where`，裁剪会静默丢失关联（当时被门禁打出 8 项失败才发现）。

#### P1-18 记录内存

诊断出的浪费不在「记录表示」，而是**同一份数据被复制了三遍**：解析产出、组装（`{**record, source_file, log_type}`）、编号（`{**record, record_id, evidence_id}`）各一份完整字典，而 `main.py` 还把分析器已经做过的组装又做了一遍。

- 新增 `analyzer.collect_records()`：就地补 `source_file` / `log_type`，不再复制；`main.py` 改用它。
- `assign_record_ids()` 改为就地排序 + 就地写编号，返回传入的那个列表。
- 新增值去重（`parser._share` / `reset_value_pool`）：把 `source_ip` / `user_agent` / `url` / `status` / `timestamp` 等结构性字段的重复取值换成共享对象。**必须在构造记录那一行调用**——事后统一去重不影响峰值内存。用 `threading.local` 隔离并发，每次解析前重置避免跨分析滞留；单字段取值种类超过 4096 时自动停用该字段的去重，防止「全唯一的 URL」让去重表本身变成新负担。
- 保留 `raw` / `command_line` 等近乎唯一的正文不去重。

验证：

- `pytest` **199 passed**（新增 `tests/test_record_memory.py` 4 条：重复值共享对象、高基数字段停止去重、去重表不跨解析滞留、组装与编号就地改）。
- 规则门禁 **75/75 用例 · 57/57 规则 · TP 86 · FP 0 · FN 0**（判定行为零变化）。
- 真实样本抽查字段与结论未变：`windows-event-kv.log` 306 条 / 3 事件 medium；`syslog-app-security.log` 276 条 / 5 事件 medium；`nginx-sensitive-file-probe.log` 21 条 / 3 事件 high。
- 基准脚本 `_build_records` 改为走产品真实路径（`collect_records` + `assign_record_ids`），避免「基准测的是一套、线上跑的是另一套」。

遗留：

- 解析阶段因值去重每条记录多 20 次 `dict.get`（+0.1 s / 6 万条），换来 26 MB 峰值下降；若日后解析成为瓶颈，可只对已确认低基数的字段启用。
- 峰值仍随记录数线性增长，50 MB 上传上限下约 0.25 GB；若要进一步压缩需改记录表示（如列式存储），属结构性改动，未做。

---

## 2026-09-21

### AI 研判泛化能力：分层采样 + 规则降权 + 放宽时限 + 按条件查记录

用户指出：AI 研判不应只依赖规则，否则「没规则就检不出」，发挥不出大模型泛化能力；研判应以准确性为先，不设固定时长。

核查出两处硬限制，正好解释了「没规则就没结论」：

- `build_ai_context` 里 `records_sample = safe_records[:30]`、`uncovered_records_sample = [...][:30]` —— **固定只给模型 30 条**，且是**按文件顺序取前 30 条**。1.2 万条日志 → 模型只看到 0.24%，且很可能全来自同一来源、同一类结果。
- 模型的判断锚点是 `events`（规则产出）；规则未命中时，它拿到的是「空事件 + 30 条无代表性样本」。

改动：

1. **分层采样**（`_stratified_sample` / `_round_robin`）：按来源 / 目标 / 账号 / 状态码 / 动作 / 路径 / 进程 / 文件 / 域名 **9 个维度**分别分组，组间轮流取；上限 200 条，≥2 万条记录时 500 条。实测 12510 条域控记录 → 200 条样本覆盖 **92 个来源 + 两类登录类型**（旧实现只覆盖 1 个来源）。
2. **显式采样口径**：新增 `records_sample_note`，写明总数、命中/未命中分布与样本上限，避免模型把「样本 200 条」当成「日志只有 200 条」。
3. **prompt 重新定位**：写明「规则只是线索、**规则未命中不等于正常**、要基于原始记录独立判断（谁在何时对什么做了什么、结果如何）、关注异常时段/批量枚举/横向移动/数据外带/持久化与防御规避、涉及数量必须以元数据总数为准、需要更多记录时调用 `query_records`」。
4. **时限放宽 + 自适应**：默认 300 秒 / 10 轮（原 180 / 6）；**未显式配置时按规模自适应**，≥2 万条记录自动翻倍为 600 秒 / 20 轮；显式配置始终优先（`_effective_timeout` / `_effective_tool_rounds`）。
5. **新增 `query_records` 工具**（第 9 个）：按 `field` + `contains`/`equals` + `log_type` 筛选原始记录，不填 `field` 时按整条原始内容匹配；让模型主动「去看」它怀疑的部分，而不是凭样本推测全集。

验证：`pytest` **195 passed**（+4：分层采样覆盖面、采样上限随规模变化、超时与轮次自适应、`query_records` 筛选）；用真实域控导出验证上下文构造（12510 条 → 200 条分层样本，覆盖 92 个来源）；`.env.example` 同步默认值与「留空自动翻倍」说明。

遗留：**模型实际输出效果尚未验证** —— 分层采样解决「给没给材料」，prompt 解决「怎么问」，最终效果取决于模型本身。需要用同一批文件（这三份域控导出 + 之前的 `1.log`）在改动前后各跑一次 AI 研判做对比，并观察误报是否上升。

---

## 2026-09-21

### 修正：XLSX 类型识别不校验表头，把其它报表按登录列表硬解

用户反馈两份「域控异常登录列表」检测不到。实测两份**都能检测到**（11091 条 / 3581 事件 / high；12510 条 / 3955 事件 / high），真正失败的是同目录的 `安全事件总览列表`：**36451 条全部未纳入检测**。

两个根因：

1. `parse_upload` 里只要 `_is_xlsx(content)` 成立就无条件返回 `log_type="windows_auth_export"`，并且**硬写 `confidence=0.97`** —— 完全没校验表头。
2. `_parse_windows_auth_export` 的表头判定是「匹配 ≥5 个已知列」。同一安全平台的「安全事件总览」能对上 9 列（首次发现时间 / 最近发现时间 / 风险等级 / 影响资产 / 资产状态 / 发生次数 / 处置状态 / 处置方式 / 事件ID），**只缺「源IP」与「登录用户」** —— 表头判定通过，随后每一行都因 `source_ip` 为空失败，产生 3.6 万条「假失败」，而失败原因指向行、掩盖了真正的问题（表头不对）。

修复：

- 新增 `AUTH_EXPORT_REQUIRED_HEADERS = {首次发现时间, 源IP, 影响资产}`：表头必须**同时包含必需列**才认定为异常登录列表。宁可判「不支持的表格」，也不要逐行报假失败。
- 表头不匹配时 `log_type="unsupported_xlsx"`、`confidence=0.2`（不再谎报 0.97）；失败原因改为**指向表头且只保留 1 条**。
- 踩坑：`recognized` 初版写成 `bool(records)`，把「表头正确但数据行为空」误判为不支持（测试立刻打红）。正确判据是**表头是否识别成功**，与是否解析出记录无关；为此让解析函数多返回一个布尔值。
- 前端 `LOG_TYPE_TONES` 补 `windows_auth_export` 与 `unsupported_xlsx` 配色。

验证：`pytest` **191 passed**；三份文件复测（两份正常、总览表给出明确的表头级提示）；前端 `npm run build` 通过。

遗留：`安全事件总览列表` 这类**资产维度**的报表当前不支持。它与异常登录列表的关键差异是没有「源IP / 登录用户」，事件主体是资产——若要支持需定义新的类型与规则（按资产聚合，而非按来源 IP）。

---

## 2026-09-21

### 降噪与误报控制：用户白名单 + 全规则聚合（P1-15 / P1-14 / P1-12 / P1-13）

按用户指定顺序落地的第一批。

#### P1-15 事件聚合降噪

核查发现降噪其实已由规则级 `aggregate` 承担，50 条内置规则里 **47 条已有聚合，仅 3 条没有**（`web.sensitive_path`、`web.path_traversal`、`db.privileged_login`）——这三条会逐条产事件。

- 给这三条补上 `aggregate`（`web.*` 按 `source_ip` 分组、`db.privileged_login` 按 `source_ip + username` 分组，均 `bucket: true`），并去掉原有的 `evidence: single` 改用窗口证据，文案补 `{count}`。
- 实测：同一 IP 1 分钟内 10 次敏感路径请求 → **10 条记录合并为 1 个事件，count=10、证据 10 条**。

#### P1-14 Sigma 聚合语义

Sigma 规则是「逐条匹配」语义，导入时不带聚合 → 同一来源反复命中会逐条刷事件（实测同一份日志刷出 2 条 count=1 的事件）。

- `sigma_import.convert_rule` 统一给导入规则补轻量聚合兜底：`aggregate: {group_by: [source_ip], bucket: true}`；分组键取 `source_ip` 是因为事件文案本就写的是「来源 {ip}」，两者必须一致。
- 重新生成 `rules/90-sigma.yaml`（7 条规则全部带上聚合）。实测同一份日志：**2 条 count=1 → 1 条 count=2**。
- 说明：Sigma 的 `condition | count() by ... > N` 管道聚合表达式属可选扩展，现有 9 条样例中未出现，**未实现**（按「至简原则」不为未出现的场景写抽象层）；带该语法的规则会在导入时按转换失败明确跳过，不会静默产出错误规则。

#### P1-12 用户白名单

支持 7 个维度：IP/网段、账号、User-Agent、域名、进程、路径、端口。

- **前提修复**：`user_agent` 此前整个项目都不保留（Sigma 只能匹配 `raw`）。新增 `WEB_TRAILING_QUOTED` 与 `_web_user_agent()`，按 combined 格式约定取行尾引号字段作为 UA，`LogRecord` 新增 `user_agent` 字段。
- 新模块 `app/services/whitelist.py`：条目表 + 变更审计表 + 匹配器 `WhitelistMatcher`。各维度语义**集中定义**以免口径漂移：`ip` 支持 CIDR；`path` 前缀匹配（`/health` 覆盖子路径但**不覆盖 `/healthz`**）；`domain` 后缀匹配（`example.com` 覆盖子域但不覆盖 `notexample.com`）；`process` 路径尾部匹配；`username` **精确匹配**（放 `admin` 不应连 `administrator` 一起放过）；`user_agent` 包含匹配。
- 生效方式：命中白名单的记录**不参与规则匹配**（因此不告警），但**原始记录仍保留在明细里**，并打上 `whitelisted_by` 标记；覆盖度新增 `whitelisted_records` 独立计数。**刻意不放进 `limitation`**——三态判定里「无事件 + limitation 非空 = 无法确认」，塞进去会把「用户主动跳过」误判成「没看清」。
- 踩坑：标记最初只写在 `analyze_parsed_logs` 的本地副本上，而调用方（`main.py`）会**另行组装 records** 入库，导致明细里标记丢失（实测 0 条）。改为在记录组装**之前**写回 `parsed_logs` 的原始记录，并补测试锁住。
- 白名单读取失败时**退回「没有白名单」**——宁可多报，也不能因为白名单读不到而漏报。

#### P1-13 白名单审计

- 变更审计表记录每次 add / enable / disable / remove（含操作时间与备注），**删除条目只删条目、审计历史保留**。
- 接口：`GET /api/whitelist`（条目 + 维度标签 + 变更历史）、`POST`（新增，非法维度 400）、`PATCH /{id}?enabled=`（启停，不存在 404）、`DELETE /{id}`（删除，不存在 404）。
- 前端：侧栏新增「白名单」入口，弹窗内可新增、启停、删除，并展示变更历史；分析结果的覆盖度与日志明细都会显示「命中白名单已跳过」与「被哪条白名单放过」。

验证：

- 后端 `pytest`：**186 passed**（新增 `tests/test_whitelist.py`：17 组匹配语义参数化用例 + 放过但仍留证据 + 停用条目无效 + 标记写回 + API CRUD 与审计）。
- 规则门禁：**75/75 用例 · 57/57 规则 · TP 86 · FP 0 · FN 0**。
- 真实接口端到端：同一份日志 **3 事件 → 加白名单后 1 事件**（203.0.113.7 的 2 条被跳过），明细仍保留 3 条，审计历史完整。
- 前端 `npm run build`（vue-tsc + vite）通过。

遗留：

- 白名单是「整条记录命中即跳过所有规则」，未做「按字段维度精准抑制」（例如只放过该 IP 的扫描类告警、仍保留它的爆破告警）。
- 单用户场景，`actor` 字段固定为 `console`，多用户需接入身份后才有意义。

---

## 2026-09-21

### 新增规则：关键防护服务被停止（防御规避）

Windows 服务控制管理器记录关键安全防护服务被停止（7036 且 `State=Stopped`），是攻击者削弱防御（T1562.001）的典型动作，勒索软件投递前也常先停掉防病毒。

改动：

- 解析器新增 `SERVICE_NAME_KEYS` / `SERVICE_STATE_KEYS`；Windows 事件键值解析器与 syslog 内层消息都补上 `service_name` / `service_state` 映射（此前 7036 的 `Service=` / `State=` 被直接丢弃）。
- `models.LogRecord` 新增这两个字段；前端明细表按「服务：<名称>（<状态>）」展示。
- `EVALUABLE_FIELDS` 纳入这两个字段 —— 此前 39 条 7036 因"没有任何规则消费其字段"被计入不可判定，现在有规则消费，判据随之成立（该日志可判定记录 267 → **306 / 306**）。
- `rules_engine` 渲染上下文新增 `{service}` / `{state}` 占位符，否则事件文案说不出"是哪个服务被停"。
- 新规则 `windows.protection_service_stopped`（level: **high**）：`status=7036` + `service_state=stopped` + `service_name` 命中防护组件名单（Defender 系列、防火墙、安全中心、事件日志、Sysmon，含中英文显示名）；按 `[target_asset, service_name]` 聚合，避免同名服务刷屏。
- 三处同补：`analytics._TACTICS`（防御规避 / T1562.001）、`analyzer._build_recommendations`、`.env.example` 开关。

**判据边界（防误报的关键）**：必须**同时**满足「防护类服务」+「Stopped」。以下都不得告警，已分别锁进单元测试与语料：

- 同一个服务处于 **Running**（该场景日志里 Defender 的 9 条状态事件全是 Running）。
- **非防护服务被停止** —— `Windows Search` / `Print Spooler` / `Windows Update` / `Windows Time` 在企业里被停属运维常态。
- **刻意没把 `Windows Update` 写进名单**：停更新确实是攻击手法，但企业用 WSUS / 组策略管控更新的场景太多，误报率不可接受。

验证：

- 后端 `pytest`：**164 passed**（+1）。新增词表边界用例：10 个防护服务名（含中文显示名）都能命中，6 类正常情况都不告警。
- 规则门禁：**72/72 用例 · 55/55 规则 · TP 84 · FP 0 · FN 0**（新增 1 正样本 + 1 负样本）。
- 真实接口上传验证：`WIN-DC-02` 停掉 Defender 防病毒与防火墙 → **2 条 high**；同一份日志里 `Windows Search` 被停**不报**；风险等级 high，战术显示「防御规避 / T1562.001」。

遗留：

- 名单是**代码内词表**（与 IOA 白名单同样的取舍），不做成配置项。若要适配客户自有安全产品（如各家 EDR 的客户端服务），需要另开配置入口。
- 仅覆盖 7036（服务状态变化）。7045 是"新增服务"，没有"停止"语义，不在本规则范围。

---

## 2026-09-21

### 修正：键值解析丢失行为字段，使覆盖度虚低并误触发结论降级

用户上传上一条同一份日志后看到「检测覆盖不足：176/306 条记录不含可用于判定的行为字段，现有规则没有判据」。核查后确认**根因是解析器丢字段，不是规则缺失**。

- `_parse_windows_event_lines` 只映射 `SourceAddress` / `Account` / `Status` / `Result`，**没有映射 `Process` / `PID` / `ServiceFile`** —— 这三个键其实已被 `_firewall_fields()` 提取出来，却在组装记录时被丢弃。`syslog` 内层键值消息（`_syslog_message_record`）存在完全相同的缺口。
- 176 条不可判定的构成：**139 条带 `Process="xxx.exe"`**（事件 ID 5002/5001/3100/2001/2002/1001/1000，多为安全产品、监控与备份 Agent 事件）、**1 条 `7045` 带 `ServiceFile`**、**39 条 `7036`**（只有 `Service=` 与 `State=`）。
- **自相矛盾的证据**：`7045` 那条**已被本项目规则 `windows.service_install` 命中**，覆盖度却称它"不含可用于判定的行为字段"——规则能判定，即证明它有判据。

改动：

- 新增共用键名常量 `PROCESS_IMAGE_KEYS` / `PROCESS_ID_KEYS` / `TARGET_FILENAME_KEYS`（含 `process` / `image` / `processname` / `pid` / `servicefile` / `imagepath` 等别名）。
- 两类键值解析器都补上 `process_image` / `process_id` / `target_filename` 映射。
- 新增 `WINDOWS_TRUNCATED_PREFIX` 与 `_windows_event_kv_reason()`：把「文件被截断」与「格式不支持」分开表述，让用户知道该修文件还是该加解析支持。

效果（`evaluation/scenarios/windows-event-kv.log`）：

| 指标 | 改前 | 改后 |
|---|---|---|
| 可判定记录 | 130 / 306（42.5%） | **267 / 306（87.3%）** |
| 未纳入检测 | 1（截断行） | 1（截断行，提示改为"疑似被截断"） |
| 检出事件 | 3 | **3（零新增）** |

仍判为不可判定的 **39 条是 `7036` 服务状态事件**（只有 `Service="Windows Event Log"` + `State="Running"`），确实没有行为字段——保持"不可判定"是诚实的，没有为了消掉这条提示而映射语义不符的字段。

验证：

- 改动前先做只读模拟：补字段后事件 3 → 3、命中记录 10 → 10，**零新增误报**，确认修复安全才落地。
- 校验 `display_log_types` **不参与匹配**（`Rule.logsource_ok` 只看 `log_types` 白名单与 `exclude_log_types` 黑名单）。`21-sysmon.yaml` 的 12 条规则只排除 json/csv/数据库类型，补上 `process_image` 后会开始扫该类型日志——实测零新增事件，确认其词表（lolbin 名单、临时目录路径、密码压缩参数）足够具体。
- 后端 `pytest`：**163 passed**（+1）；规则门禁 **70/70 用例 · 54/54 规则 · TP 83 · FP 0 · FN 0**；真实接口上传验证通过。
- 同步验证 syslog 场景未受副作用影响：`syslog-app-security.log` 可判定 247/276（89.5%）、事件仍为 5 条。

遗留：

- `7036` 服务状态、`2001`/`2002` 监控指标这类**环境状态事件**仍计入不可判定。注意 "未覆盖记录数 296" **不代表漏检**——这些正常运维事件本就不该有规则命中。若要区分「环境状态类」与「有判据但无规则」，需在 `DetectionCoverage` 增加独立计数，**不能塞进 `limitation`**，否则会连带触发结论降级。
- 若要继续增强 Windows 事件侧检出，可补三条"真攻击会响、正常不响"的规则：Defender 检出威胁（`5002` 且 `ThreatsDetected>0`）、关键防护服务被停止（`7036` `State=Stopped`）、服务程序落在可写目录（`7045` `ServiceFile` 位于 `%TEMP%` / `Users\Public`）。三者均需新增正样本语料，且在当前样本内都不触发。

---

## 2026-09-21

### 新增 Windows 事件日志「键值化导出」解析 + 凭据攻击规则

用户提供的第二份 `1.log` 换了形态：`时间 级别 主机 提供程序 EventID=N 键=值`（如 `INFO  WIN-SRV-01 Security EventID=4624 LogonType=3 Account="svc_backup" SourceAddress="192.0.2.21"`）。它与已有的两种 Windows 形态都不同——**程序名后没有冒号、没有 `[PID]`**，所以上一轮加的 syslog 前缀也匹配不上；`Event ID:` 分块解析同样不适用，结果是 309 行全部落进 `generic`、解析成功 0 行。

日志内容是一条完整的 Windows 凭据攻击（404 里挑出的关键事件）：

```text
08:00:22  7045 安装新服务 BackupAgent（StartupType=Auto）      → 持久化候选
08:20:17  4625 ×5  Administrator / LogonType=10 / 198.51.100.77 → RDP 凭据攻击
08:20:31  4740  Administrator 账户被锁定                        → 攻击已造成影响
08:20:34  4625  Status=0xC0000234（AccountLocked）继续尝试
08:20:39  4648  显式凭据使用被拒
```

修复：

- 新增 `WINDOWS_EVENT_KV` 前缀识别与 `_parse_windows_event_lines()`，判定沿用 syslog 那套自适应阈值（样本多时 ≥3 行命中，样本少时按实际行数）。检测顺序放在 firewall / ssh 之后，避免影响既有判定。
- 字段映射**与「事件查看器文本导出」严格保持一致**：4625 → 失败、4624 → 成功，**其余事件的 `result` 留空、动作记为 `event`** —— 否则 `System`/`Application` 的 `Result="Success"` 会混进「认证失败 / 成功」统计，把不相关的业务事件算成认证成功。
- 新增类型 `windows_event`；`20-windows.yaml` 三条既有规则的 `display_log_types` 一并补上（规则本身不限 `log_types`，所以照常匹配）。
- 新增 2 条规则：`windows.account_lockout`（4740 账户锁定）、`windows.service_install`（7045 新服务安装，持久化候选）。两条都接入 ATT&CK 战术映射、排查建议与 `.env.example`；前端补 `windows_event` 类型配色。
- **没有**对 4672（特殊权限分配）与 4648（显式凭据）配规则：管理员每次登录都会产生 4672、`runas` 类脚本会大量产生 4648，纳入必然制造误报（同 `/health` 那次的教训）。

实测效果（同一份日志）：

| 指标 | 修复前 | 修复后 |
|---|---|---|
| 日志类型 | generic（35%） | **windows_event**（90%） |
| 解析记录 / 未纳入 | 0 / 307 | **306 / 1** |
| 检出事件 | 0（结论「信息」） | **3 条 medium**：账户锁定、新服务安装、高权限账户 RDP 登录 |

> 未纳入的那 1 条是**文件尾部被截断的行**（`2026-09-21T08:57:57+08:00 INFO  WIN`），如实计入解析失败并给出原因——这正是覆盖度机制该有的表现。

验证：

- 后端 `pytest`：**162 passed**（+2）
- 规则质量门禁：**70/70 用例 · 54/54 规则 · TP 83 · FP 0 · FN 0**（新增 2 条规则、2 个用例，含 1 个「正常事件流 → 零告警」负样本）
- 真实接口端到端：上传 `1.log` → 类型 `windows_event`、记录 306、未纳入 1、3 条事件
- 前端 `npm run build` 通过；`docs/rule-quality-report.md` 已刷新

已知边界：4625 只有 5 次，未达 `rdp.bruteforce` 的阈值（默认 10），因此**失败聚集本身不单独告警**——本次由 4740 账户锁定覆盖了同一条攻击。是否下调阈值属于误报率取舍，未擅自改动。

### 新增 syslog / 容器日志解析（两个解析缺口）+ 应用层安全规则

用户提供的 `1.log` 是一份**带 syslog / 容器前缀的真实日志**（`时间 级别 主机 程序[PID]:`，内嵌 nginx 访问行、认证、应用与安全程序消息，共 285 行 = 276 条有效 + 9 个空行）。此前这类日志**解析成功 0 行、解析失败 276 行**，结论只能给「无法确认」——不是结论错，而是根本没读进去。实测出**两个叠加的解析缺口**，只补一个都不够：

1. **syslog 前缀没有剥离**：整行匹配不上任何现有解析器。
2. **访问行变体不支持**：该格式是 `IP - - "GET / HTTP/1.1" 200 4218 "-" "UA"`，**缺 `[时间]` 字段**（时间在外层前缀里）。手动剥掉前缀后 158 条仍全部失败，类型识别也判成 `generic`。

修复：

- 新增 `SYSLOG_PREFIX` 识别与 `_looks_like_syslog()`（样本多时要求 ≥3 行命中，样本很少时按实际行数要求，避免一两行的导出片段被判成 generic）；检测顺序放在 firewall / ssh **之后**，带 ISO 前缀的防火墙日志仍按防火墙处理。
- 新增 `WEB_PREFIX_NO_TIME`：访问行没有 `[时间]` 时由调用方补时间戳，`_parse_web_line()` 增加可选参数；单独一份无时间戳的访问日志现在也能被识别为 Web 日志。
- 新增 `_parse_syslog_lines()`：剥壳后按内层内容分派——访问行复用 Web 解析（主机记为 `target_asset`），`key=value` 消息映射出 `src_ip` / `user_id` / `result` / `endpoint`，应用动词只映射已知安全语义（`user_login`→login 等）。**前缀匹配成功即算解析成功**，没有可判定字段也如实计入覆盖度，与「解析失败」分开。
- 应用层安全信号新增 3 条规则（`80-app-security.yaml`）：应用自身已经做出判定的信号（`suspicious_path_sequence` / `temporary_block` / `restricted_resource_access`）直接采信，而不是在日志侧重新推断一遍。
- 应用层事件同步接入 ATT&CK 战术映射、排查建议与 `.env.example` 开关；前端补 `syslog` 类型标签配色。

实测效果（同一份日志）：

| 指标 | 修复前 | 修复后 |
|---|---|---|
| 日志类型 | generic（35%） | **syslog**（90%） |
| 解析记录 / 未纳入 | 0 / 276 | **276 / 0** |
| 检出事件 | 0（结论「信息」，只能给「无法确认」） | **5 条 medium**：`/.env` 与 `/server-status` 探测（203.0.113.88）、应用层敏感路径探测序列、认证阈值触发封禁（198.51.100.77）、受限资源访问被拦截 |

验证：

- 后端 `pytest`：**160 passed**（+4）
- 规则质量门禁：**68/68 用例 · 52/52 规则 · TP 80 · FP 0 · FN 0**（新增 3 条规则、2 个用例，含 1 个「正常业务与健康检查 → 零告警」负样本）
- 真实接口端到端：上传 `1.log` → 类型 `syslog`、记录 276、未纳入 0、5 条事件
- 前端 `npm run build` 通过

遗留：经典 `Mon DD HH:MM:SS 主机 程序[PID]:` 前缀（非 ISO 时间戳）暂不剥壳——该形式的认证日志已由 SSH 解析处理，其余程序的经典 syslog 需要时再扩展。

---

## 2026-09-20

### P1-11：大日志性能验证（含一处误报修复与一处匹配优化）

**基准工具**

新增 `backend/scripts/bench_large_log.py`：按大小生成接近真实形态的 Web 日志（含少量攻击行），分别量出解析耗时、规则匹配耗时、峰值内存、命中记录数与覆盖率。计时与测内存分成两遍跑——tracemalloc 的开销会把耗时放大一个数量级，混在一起量会得出错误结论。

**实测结论（11 MB / 6 万条）**

| 阶段 | 耗时 | 说明 |
|---|---|---|
| 解析 | 2.1 秒 | 线性，约 11 MB/s，**不是瓶颈** |
| 规则匹配 | 9.5 秒 | **瓶颈**，近似 O(规则数 × 记录数) |
| 峰值内存 | 81 MB | 约为原始日志的 10 倍，约 1360 字节/条 |

cProfile 证据：49 条规则 × 37,118 条记录 = **181 万次 `covers()`**、270 万次 `_match_field`。

**结论**：「流式/分块解析」解决不了大日志问题（解析只占 7% 耗时）。真正的优化点是规则匹配索引化与记录表示瘦身，已登记为 P1-17 / P1-18。

**顺带修复：健康检查端点误报（重要）**

基准跑纯正常流量时暴露：`web.sensitive_interface` 对 `/health` 每个 IP 产生一条 medium 事件——`/health`、`/ready` 被负载均衡与编排系统日常高频访问，属于典型正常流量，违反「不得虚假告警」的产品红线。

- 从词表移除 `/health`、`/ready`（保留 `/metrics`：它至少属于信息泄露面），并在规则 description 里写明原因。
- 新增负样本语料 `web-health-check-negative`（kube-probe / ELB-HealthChecker 访问 `/health`、`/ready`）锁住该边界。
- 实测：3,000 条正常流量从 **命中 2,003 条 / 12 个事件 → 0 命中 / 0 事件**。

**顺带优化：谓词归一化预计算**

`_match_field` 每次匹配都在重新归一化常量——`any_contains` 逐个 `.lower()` 所有 values（9.3M 次调用，单一最大热点），`in_set` 每次重建 set。改为在 `Predicate.__post_init__` 里预计算 `normalized` / `normalized_set`，逐记录匹配只做查表；同时删除已无用的 `_normalized` 方法。

- 实测：10 MB 日志规则匹配由 **12.19 秒降到 9.95 秒**。

验证：

- 后端 `pytest`：**156 passed**
- 规则质量门禁：**66/66 用例 · 49/49 规则 · TP 75 · FP 0 · FN 0**（新增 1 个负样本）
- 基准：命中记录数等于注入的攻击行数（3 / 9 / 18），正常流量噪音为 0

### P1-09 / P1-10：上传失败回滚 + 上传目录孤儿清理

**上传失败回滚（P1-09）**

上传流程是「先写分析记录、后落盘原始文件」，落盘失败时会留下一个**结果正常但没有原始日志**的不一致记录，外加一个写到一半的残留目录。

- `main.py` 的 `/api/logs/upload` 把 `_persist_upload_files` 包进 try：失败时删除该分析目录并删除对应数据库记录，返回 `500 原始文件保存失败，本次分析已回滚`。
- **分析阶段自身的失败不走这个回滚**——那种情况仍由 `repository.fail()` 标记为 failed 并保留记录，便于用户在历史里看到失败原因（`test_analysis.py` 已有断言依赖该行为）。
- 测试 +1：模拟「目录和文件已产生后抛错」，断言目录被清理且数据库无该记录。

**上传目录孤儿清理（P1-10）**

- 新增 `backend/scripts/clean_uploads.py`：默认**只列清单**，`--apply` 才执行删除，避免误删。
- 判定依据：分析记录先入库、文件后落盘，因此数据库是权威来源，不在库里的目录即为孤儿；不需要额外时间保护。
- 实测：造 1 个假孤儿目录 → 只读模式正确识别 → `--apply` 删除 → 剩余目录数与有效分析记录一致。

验证：

- 后端 `pytest`：**156 passed**（+1）
- 规则质量门禁：**65/65 用例 · 49/49 规则 · TP 75 · FP 0 · FN 0**
- 清理脚本：只读与删除两种模式均实跑通过，当前 `data/uploads/` 25 个目录、0 个孤儿

### P1-08：上传空间治理

- 增加单文件、单次分析总量和全局上传目录三层容量限制。
- 默认限制为：单文件 50 MB、单次分析 200 MB、全局 `data/uploads/` 2 GB。
- 支持通过 `LOGINSIGHT_MAX_FILE_BYTES`、`LOGINSIGHT_MAX_ANALYSIS_BYTES`、`LOGINSIGHT_MAX_STORAGE_BYTES` 调整。
- 超过单文件或单次分析限制返回 `413`；超过全局上传空间返回 `507`，并在解析前拒绝。
- 新增三类容量限制回归测试。

验证：

- 后端 `pytest`：**155 passed**
- 前端 `vue-tsc --noEmit -p tsconfig.json`：通过

遗留：分析完成后文件落盘失败的回滚和历史孤儿目录清理分别由 P1-09、P1-10 处理。

---

## 2026-09-20

### P1：修正弱目标资产聚合与历史日志服务端分页

- 终端证据链不再仅用 `source_file` 作为缺少 `target_asset` 时的聚合键；优先使用目标资产，其次使用来源 IP，仍无法确认终端身份时按单条证据隔离，避免多个主机行为被错误合并。
- `/api/logs` 新增服务端分页、日志类型、风险等级、状态、关键词和排序参数；无参数请求保留旧数组响应，兼容已有脚本和客户端。
- 前端历史列表改为服务端分页与筛选，避免一次性拉取全部历史分析记录。
- 新增回归测试：未知目标资产不跨记录合并；历史列表分页和关键词筛选可用。

验证：

- 后端 `pytest`：**151 passed**
- 规则质量门禁：**65/65 用例 · 49/49 规则 · TP 75 · FP 0 · FN 0**
- 前端 `vue-tsc --noEmit -p tsconfig.json`：通过

---

## 2026-09-20

### 终端证据链增强：进程树、DNS 外联关联与置信度

- Sysmon / EVTX 字段映射新增 `ProcessId`、`ParentProcessId`、`ParentImage` 和 `QueryResults`，并暴露到日志明细与证据节点。
- 终端证据链新增 `relationships`：同一目标资产内 `ParentProcessId -> ProcessId` 精确匹配标记 `strong`；仅 `ParentImage` 匹配标记 `medium`；仅有父 PID 但缺少对应证据标记 `weak`。
- DNS `QueryResults` 中的 IP 与后续外联目的 IP 一致时生成 DNS 到外联关系，保留起止证据编号、关系依据和 `strong` 置信度。
- 前端终端证据链增加关联展开区，可跳转关系两端的证据编号，并展示置信度和依据。

验证：后端 `pytest` **150 passed**；规则门禁 TP **75** / FP **0** / FN **0**；前端 `vue-tsc -b` 通过。

---

### 解析失败可见化与 XML 单条降级解析

- `ParsedLog` 与 `DetectionCoverage` 新增受限的 `parse_error_details`，记录来源文件、事件/行号、失败原因和最多 240 字符的原文摘要。
- 通用文本日志的无法识别行会保留前 50 条详情；多文件分析合并后最多向结果暴露 100 条，避免大日志撑大 API 响应。
- EVTX 二进制解析继续逐条处理：单条 XML 读取或映射失败只计入覆盖度并记录诊断，不影响后续事件；保留旧的四元组调用兼容性。
- 详情页覆盖度区域新增“解析失败详情”折叠面板；HTML 报告新增同名章节，明确未展示内容不代表解析成功。
- 增加文本失败行与 EVTX 损坏事件的证据断言，覆盖裸 `&` 修复后继续解析的回归场景。

验证：

- 后端 `pytest`：**149 passed**
- 规则质量门禁：**65/65 用例 · 49/49 规则 · TP 75 · FP 0 · FN 0**
- 前端 `vue-tsc -b`：通过

遗留：解析失败详情当前只保留受限摘要，不保存完整失败原文；后续可在原始日志下载与权限控制完善后，再考虑按证据编号提供精确原文定位。

---

## 2026-09-19

### 终端证据链与关联时间线

- 新增 `terminal_chains` 分析结果：按 `target_asset` 聚合进程创建、文件活动、注册表修改、DNS 查询和外联行为，缺少目标资产时退回来源文件分组。
- 每个终端节点同时保留 `record_id` 与 `evidence-record-N`，按 `timestamp_iso` 排序；规则命中的记录继承对应事件最高风险，普通关联默认保持 `info`，避免把行为组合直接表述为攻击结论。
- 新增只读 AI 工具 `query_terminal_chains`，支持按目标资产和节点类型筛选；AI 上下文携带受控数量的链路节点，并明确链路只是日志关联视图。
- 前端新增“终端证据链”模块，可查看目标资产、时间范围、行为节点、证据编号并跳转到日志明细。

验证：新增终端链路与工具测试；后端 `149 passed`，规则评估 `65/65`、`49/49` 规则覆盖、`TP 75 / FP 0 / FN 0`；前端 `vue-tsc -b` 通过。

### 普通终端日志统一证据编号

- 所有分析记录在统一排序后同时生成 `record-N` 与 `evidence-record-N`；规则事件原有的 `evidence-规则-序号` 保持不变。
- `query_evidence` 支持按普通记录的 `record_id` 或 `evidence_id` 查询，并返回进程、命令行、目标文件、注册表、DNS、目标资产和 Windows/Sysmon 事件编号等终端字段。
- `query_uncovered_records` 返回普通记录的证据编号；未命中规则仍明确表示“未覆盖不代表正常”。
- AI 上下文携带受控数量的未覆盖记录，证据合法性校验与 `record-N` 兼容映射同时覆盖普通记录证据。
- 日志明细表新增证据编号列，便于用户将未命中规则的终端记录交给 AI 或报告引用。

验证：后端 `147 passed`，前端 `vue-tsc -b` 通过。

---

## 2026-09-18

### 异常评分补主机维度（E-4）+ 清理孤儿上传目录

**异常评分：新增目标主机维度**

`score_events` 原来对**没有 `source_ip` 的事件直接跳过**——主机侧日志（Sysmon / Windows 事件）在归组阶段就被丢掉，一个评分项都拿不到，而终端取证正是产品当前的主要用途。

- 归组对象改为**优先来源 IP，其次目标主机**；两者都无才跳过。两个维度**互不叠加**（`("source_ip", ip)` 与 `("target_asset", host)` 是不同分组键）。
- `models.RiskScoreItem` 新增 `key` / `kind`（`source_ip` | `target_asset`），`source_ip` 降为可选并保留旧语义（主机维度下为空串），历史结果与既有消费方不受影响。
- 前端异常评分卡按 `kind` 区分显示（主机维度加「主机」前缀），列表 key 改为 `kind+key` 避免跨维度同名冲突。
- **定级语义未变**：升级仍受 `RISK_SCORING_ENABLED` 控制（默认关闭），本次只影响评分明细的归组方式。

实测：

| 日志 | 改前评分项 | 改后评分项 |
|---|---|---|
| `sysmon-intrusion-chain.log` | **0** | 1（`[target_asset] WK001.megacorpone.com` = 45 分，基准 high） |
| `nginx-sensitive-file-probe.log` | 2（按来源 IP） | 2（不变） |

> 注意：若把 `RISK_SCORING_ENABLED` 打开，该主机样本的 45 分会从 high 升级到 critical；此前它连评分都没有，属预期内的能力补充，但正式启用前建议先复核阈值。

**清理孤儿上传目录（并根治来源）**

`data/uploads/` 下每个分析对应一个目录，但只有走 API 删除才会联动清理，其余会长期残留（清理前 2014 个目录在 DB 中已无对应记录）。

- 依据：DB 记录先于文件落盘（`repository.create()` 在 `_persist_upload_files()` 之前），故 **DB 即权威来源**，不在 DB 的目录即为孤儿。
- 删除 **2014 个孤儿目录**（释放约 17MB），剩下 **25 个目录 = DB 中 25 条分析记录**，一一对应。
- 顺带删除根目录废弃的 `.runtime/`（4 个 9-15 的历史启动日志）。`data/backups/` 的 DB 备份保留。
- **根治来源**：`tests/conftest.py` 原先只隔离了 SQLite（`LOGINSIGHT_DB_PATH`），**没有隔离上传目录**，而 `UPLOAD_ROOT` 是硬编码的 `data/uploads` —— 于是每次跑测试，`/api/logs/upload` 都往项目真实数据目录写一份目录，测试库又是临时的，这些目录当场变成孤儿。这也解释了目录为何能涨到 2000 个。
  - `main.py`：`UPLOAD_ROOT` 支持 `LOGINSIGHT_UPLOAD_ROOT` 覆盖（与数据库同一套做法）。
  - `conftest.py`：连同上传目录一起指向临时目录。
  - 验证：跑测试前后 `data/uploads` 目录数 **净增 0**（146 passed）。

验证：

- 后端 `pytest`：**146 passed**（+2）
- 规则质量门禁：**65/65 用例 · 49/49 规则 · TP 75 · FP 0 · FN 0**
- 前端 `npm run build`（vue-tsc + vite）通过
- 后端已重启加载新代码

遗留：`data/uploads/` 仍无全局容量上限（正常使用下靠「删除分析时联动清理」维持），孤儿目录只可能来自异常中断的请求。

### AI 任务状态清理 + README 启动说明对齐现实

**AI 任务生命周期（C-4）**

`AI_TASKS` 是进程内存字典且**没有淘汰策略**，每次 AI 研判都会新增一条，长期运行只增不减。

- `main.py` 新增 `_prune_ai_tasks()`：在新建任务时清理**已结束**任务 —— 超过 TTL（`AI_TASK_TTL_SECONDS` = 1800 秒）的删除；若总条数超过 `AI_TASK_MAX_ENTRIES`（200），按 `updated_at` 从最旧的已结束任务开始删。
- 任务增加 `updated_at`，在创建与进入 completed / failed 时刷新。
- 先登记新任务再清理：新任务是 `running`，不会被自己清掉，容量上限也就不会被越过。
- **运行中的任务永不清理**——否则前端轮询会突然拿到 404。
- 测试 +3（`tests/test_ai_limits.py`）：过期已结束任务被清理、运行中任务即使远超 TTL 也保留、超上限时优先清最旧的已结束任务。

**README 文档漂移（D）**

「本地运行」下的「一键启动（Windows）」整节描述的是 `启动 AI-LogInsight.bat` / `关闭 AI-LogInsight.bat` 与 `.runtime` 日志目录，但这两个脚本**早已删除**（`.runtime` 只剩历史日志）。已删除该节，保留下面真实可用的手动启动命令。

验证：

- 后端 `pytest`：**144 passed**（+3）
- 规则质量门禁：**65/65 用例 · 49/49 规则 · TP 75 · FP 0 · FN 0**（不受影响）
- `grep` 复核 README / PROGRESS / AGENTS / docs 已无 `.bat` 与 `.runtime` 残留描述

遗留：`data/uploads/` 已 1841 个文件 / 52MB，仍无全局容量上限（删除分析时联动清理），需要确认后再做清理策略。

### 检测覆盖度：未纳入检测拆分为「解析失败」与「超出保留上限」

`parse_failures` 是两类完全不同的原因之和（内容解析不出来 / 内容正确但超出单次保留上限），合并显示让人无法判断该去修解析器还是调保留上限。

- `evtx.py`：新增 `parse_evtx_records_detailed()` 返回四元组（记录、事件总数、`parse_errors`、`retention_drops`）；旧 `parse_evtx_records()` 保留三元组语义（第三项为两类之和）并转发，**外部调用不受影响**。
- `parser.py`：`ParsedLog` 新增 `parse_errors` / `retention_drops`；`parse_upload` 的 EVTX 二进制分支按类型分别计数；文本日志没有保留上限，无法解析的行一律计入 `parse_errors`。
- `analyzer._build_coverage` 接收并写入两个新字段，`limitation` 文案按实际构成展开（如「2 条内容未纳入检测（解析失败 2 条）」）；上游传的是各日志段的求和。
- 展示：HTML 报告与前端概览、空事件状态均**优先展示拆分数字、同时保留总数**；前端新增 `coverageDropDetail()`，无拆分数据时退化为只显示总数。
- 修复：`test_evtx_binary_upload_uses_dedicated_parser` 之前打桩的是旧函数名 `parse_evtx_records`，而上传路径已改调 `parse_evtx_records_detailed`，导致打桩失效、真实 python-evtx 被调用而报 `OverrunBufferException`（曾使 `pytest` 变红）。

验证：

- 后端 `pytest`：**141 passed**（修复 1 个失败用例 + 新增拆分断言）
- 规则质量门禁：**65/65 用例 · 49/49 规则 · TP 75 · FP 0 · FN 0**（不受影响）
- 端到端：文本日志「2 行无法解析」→ `parse_failures=2 / parse_errors=2 / retention_drops=0`，HTML 报告输出「未纳入检测 2 条（解析失败 2 条）」
- 前端 `npm run build`（vue-tsc + vite）通过

遗留：`retention_drops` 只能靠单元测试（打桩）覆盖 —— 现有 54 份 EVTX 样本中最大一份 4132 个事件，均未触及 10000 条的保留上限。

### 终端应急响应优先：增强明细取证与 AI 上下文

根据产品主要用于用户终端应急响应的定位，本轮不扩展 WAF 规则，保留现有 Firewall/WAF 扩展能力，优先完善 Windows/Sysmon 证据链。

- `LogRecord` 新增 `process_image`、`command_line`、`target_filename`、`registry_key`、`query_name`、`target_asset`、`event_id` 字段。
- Windows 文本与 EVTX 解析结果补充独立 `event_id`，日志明细页直接展示进程、命令行、文件、注册表、DNS、目标主机、端口和事件号。
- AI 工具新增 `query_behavior_deviations` 和 `query_uncovered_records`，研判前自动执行，帮助模型识别 IOA 信号和当前规则盲区。
- 未覆盖记录复用检测引擎的精确覆盖集合，不通过聚合事件的有限证据反推，避免误报检测盲区。
- 新增终端明细接口和 AI 工具回归测试。

验证：

- 后端 `pytest`：**139 passed**
- 前端 `npx vue-tsc -b`：通过
- `npm run build` 在当前受限环境因 esbuild `spawn EPERM` 未完成，非 TypeScript 类型错误。

后续优先级：普通终端记录统一证据编号、跨分析实体基线、白名单/规则治理、AI 任务和上传文件生命周期管理。

---

## 2026-09-18

### 暗黑主题下换用深色版 logo（背景抠透明）

浅色主题的品牌图在暗色背景上，图内文字与背景同化，品牌标不可读；换成深色版后，图片**自带的不透明背景**又与侧栏底色对不上，出现明显色块。

- `frontend/src/App.vue` 新增 `brandLogo` computed：`theme === "dark"` 时用深色版品牌图，否则用浅色版；模板改为 `<img :src="brandLogo">`。仅此一处改动，无 CSS 变更。
- **根因**：侧栏底色为 `var(--surface)`＝`#121822`（暗色），而图片烧死了背景色（初版 `#28292E`，比底色亮；换图后 `#090E14`，比底色暗）。带不透明背景的图**不可能**与主题底色对齐，只能抠成透明。
- **处理**：从四边泛洪抠背景（不用全局色键，避免误伤 logo 内部深色区域），缩放至高 150px。产物 `frontend/public/` 下的深色版品牌图：3414×1248 / 5.87MB → **410×150 / 31KB（约 1/189）**，且 MIME 由 `image/jpeg` 变为正确值 `image/png`。
- 图片需放在 `frontend/public/`（Vite 静态资源目录），**不能放 `dist/`**：`dist/` 是构建产物，dev server 取不到，且 vite 对缺失资源会回退 index.html 并返回 `200 + text/html`，只看状态码会误判成加载成功（`<img>` 实为坏图）。
- 验证：抠图后合成到 `#121822` 上，四角与底色通道差 **0**（无接缝）；dev server 请求该深色版图片返回 200 + `image/png` + 正确 `Content-Length`；`npm run build` 通过。

### 杀伤链按主机归组（`Event.target_asset`）+ 补 3 条 Sysmon 规则（进程外联 / 落地文件 / 批量注册表）

**改动一：杀伤链按目标资产归组**

主机侧日志（Sysmon / Windows）没有来源 IP，而 `build_attack_chains` 只按来源 IP 归组、无 IP 时退化为「一个规则一条链」——真实入侵链样本的 11 个事件被拆成 **9 条碎片链**，看不到完整攻击过程。

- `models.Event` 新增 `target_asset`；`events.build_event` 增加同名参数并纳入 `correlation_basis`（「同一目标资产」）。
- `rules_engine` 的单记录路径与聚合路径均传入 `record.get("target_asset")`。
- `analytics.build_attack_chains` 改为三级归组：**来源 IP → 目标资产 → 规则**。
- 前端攻击链标题按 `chain.kind` 显示「来源 IP / 目标资产 / 规则」（新增 `chainKindText`），并把 `v-for` 的 key 从 `chain.key` 改为 `` `${chain.kind}-${chain.key}` `` 避免跨维度同名冲突。
- 效果：`sysmon-intrusion-chain.log` **9 条碎片链 → 1 条单主机链**（13 个阶段，按 ATT&CK 阶段序排列，risk=high）；Web 日志仍按来源 IP 分组（2 条链），行为未变。

**改动二：新增 3 条 Sysmon 规则（规则 46 → 49）**

| 规则 | 等级 | 判据 | 说明 |
| --- | --- | --- | --- |
| `windows.payload_outbound_connection` | high | EID 3 + 进程镜像位于临时/缓存/下载目录 + 有目的地址 | 落地程序外联，符合回连或外传特征 |
| `windows.executable_drop_in_temp` | medium | EID 11 + 目标文件在用户可写目录 + 可执行/脚本扩展名 | 落地发生在执行之前，可提前拦截 |
| `windows.registry_bulk_write` | low | EID 12 + 进程位于用户可写目录 + 60 秒内 ≥10 条 | 刻意限定进程位置：合法安装程序多由系统目录进程执行 |

配套：`analytics._TACTICS` 补 T1071 / T1105 / T1112；`analyzer._build_recommendations` 扩充主机侧类型；`.env.example` 增补 3 个开关与 2 个阈值。

**B 的实际收益（`log.txt` 覆盖率）**：无规则覆盖的记录 **24/42 → 8/42**，覆盖率 43% → **81%**。

**验证**

- 后端 `pytest` **137 passed**（+5，新增 `tests/test_attack_chains.py`）；规则质量门禁 **65/65 用例 · 49/49 规则覆盖 · TP 75 · FP 0 · FN 0 · P/R 100%**。
- **链级门禁按设计发挥作用**：新规则在真实样本上命中后，`scenario.yaml` 的 `expect` 立刻被判为少列（2 处 FP 报错），迫使显式复核后才更新预期——`windows.payload_outbound_connection`（count=4）、`windows.registry_bulk_write`（count=16）经核对属实后写入场景契约。
- 3 个「断言旧数字」的测试按新事实更新（事件 11→13、覆盖记录 18→34、场景规则集合 9→11 条）。
- 新增负样本覆盖新规则的误报场景：`msiexec`（系统目录进程）连写 10 条注册表键、`svchost` 正常外联、临时目录写入 `.zip` —— 均不告警。
- 前端 `npm run build` 通过。

**遗留**

- `log.txt` 仍剩 8 条无规则覆盖：EID 11 落地（`.epub`/`.zip`/`.rss`，非可执行扩展名）、EID 5 进程退出、EID 23 归档删除、`news.axonbyte.org` 解析（域名形态正常）、`conhost.exe`、Prefetch 写入。多为噪声或低价值项。
- `windows.registry_certificate_store` 与 `windows.registry_bulk_write` 在真实样本上会同时命中同一批记录（前者看"敏感位置"、后者看"写入量"），属不同视角，暂未合并。

---

## 2026-09-18

### IOA 行为偏离：没有攻击特征时也给出判断（层 1 同批次 + 层 2 白名单）

**背景**

用户要求：「即使没有明显的攻击行为，也必须要通过相应的 IOA 行为去进行判断，特别是出现从来没有出现过的 IP、地址、域名等时候。」

此前 46 条规则绝大多数是 **IOC/特征型**（已知关键字、已知路径、超阈值次数），固有盲区是——攻击者不使用已知特征就检测不到，日志只能落到「未发现异常」。项目内完全没有 IOA / 实体基线 / 首次出现检测能力。

**设计**

新增设计文档 `docs/ioa-behavior-baseline.md`。三层基线中**本期只做层 1 + 层 2**：

- 层 1：与**同一次分析的记录**比较 → 低频/独狼实体；
- 层 2：**内置白名单**（私有网段 / 常用端口 / 常用域名 / 非公网主机名）→ 层 1 不误报的前置条件；
- 层 3：跨批次历史基线**不做**（需持久化实体库，且会改变既有 62 个用例预期）。

**实现**

- 新增 `backend/app/services/behavior_baseline.py`，5 类检测项：
  `rare_destination_ip`（本批次首次出现的公网目的地址）、`rare_domain_query`（首次出现的域名解析）、
  `unusual_outbound_port`（非常用端口外联）、`rare_source_ip`（低频公网来源，需带成功结果）、
  `rare_url_path`（罕见路径，2xx，且**仅在有基线时生效**）。
- 新增 `models.BehaviorDeviation` 与 `AnalysisResult.behavior_deviations`，含 `basis` 字段强制写明基线口径。
- `analyzer._build_judgement` 的三态扩展为**四态**：无事件 + 有偏离 → 「未发现明确攻击特征，但存在 N 项行为偏离（低置信度）」；
  `summary` / `_build_recommendations` 给出「逐项核实」的口径与具体方法。
- HTML 报告新增「行为偏离（IOA）」小节；前端分析概览新增「行为偏离（IOA）」卡片（含基线口径与原始证据折叠）。
- `docs/ioa-behavior-baseline.md` 说明口径、白名单、输出契约与非目标。

**关键设计约束（防止污染既有体系）**

行为偏离**不进入 `events`**、**不改变风险等级**：混进事件会污染定级与杀伤链，并会打破 `evaluation/corpus/scenario.yaml` 的链级契约。多视角命中同一记录（例如既唯一目的地址又是非常用端口）时两条都保留。

**防噪（本轮修掉两个真实误报）**

1. `rare_source_ip` 初版把**内网**只出现一次的来源也当成偏离——真实样本里 `192.168.1.50/51/52`、`::1` 这类正常终端访问被全部误报。已限定为**公网**来源（内网地址只出现一次属正常）。
2. `_unusual_outbound_ports` 的详情文案引用了上一个循环遗留的变量，导致检测到 `8000` 却写成 `443`——检测对、证据文案错（比漏报更危险）。已改为从分组键解包。
   （该 bug 由真实样本核对发现：`145.1.0.92:8000` 正是日志里的 C2 回连端口。）

**验证**

- 后端 `pytest` **132 passed**（+18，新增 `tests/test_behavior_deviations.py`）：5 类偏离正向命中；白名单负向（内网 IP / 常用端口 / 常用域名 / 内网主机名 / 静态资源 / 高基数 URL 日志）全部不报；上限生效；结论四态；接口与字段契约。
- 规则质量门禁**未受影响**：**62/62 用例 · 46/46 规则 · TP 70 · FP 0 · FN 0** —— 证明行为偏离没有进入 `events`。
- 真实样本：`sysmon-intrusion-chain.log` → 11 事件 + **3 项偏离**（`qqqqqqqqqqqqqqqq.org`、`news.axonbyte.org`、`145.1.0.92:8000`）；`nginx-sensitive-file-probe.log` → 3 事件 + **0 项偏离**（无误报）。
- 端到端 `POST /api/logs/upload` 返回 `behavior_deviations`，HTML 报告含「行为偏离（IOA）」小节。
- 前端 `npm run build` 通过。

**注意**

`rare_destination_ip` / `rare_domain_query` 的口径是**与本批次相比**首次出现，**不是**历史首次（后者需层 3）。所有输出均带 `basis` 字段且界面展示，不得改写为历史基线结论。

---

## 2026-09-18

### 分析页模块折叠状态持久化 + 修复存量规则聚合层级错误

**改动一：模块折叠状态持久化（前端）**

`frontend/src/App.vue` 的 `collapsedModules` 之前是纯内存状态，每次打开分析都会被 `watch(result)` 重置为默认值（折叠「关联分析」层：templates / entities / timeline），用户手工展开或收起的偏好刷新后丢失。

现新增 `loginsight-collapsed-modules` 持久化：

- `loadCollapsedModules()` 读取上次状态；**没有存过返回 `null`**，与「显式全部展开」的空数组区分开，因此"从未调过"仍走默认折叠。
- `watch(collapsedModules, ...)` 在任意变更时落盘；localStorage 不可用（隐私模式等）时静默忽略，不影响折叠本身。
- `watch(result)` 改为优先沿用持久化偏好，仅在从未保存过时使用默认折叠。
- 注意：`COLLAPSED_MODULES_KEY` 必须声明在 `collapsedModules` 的 `ref` 初始化之前，否则初始化即调用 `loadCollapsedModules()` 会触发 TDZ `ReferenceError`。

**改动二：修复 `web.scanner_user_agent` 的 `aggregate` 层级（存量 bug）**

`rules/40-web-attack.yaml` 的 `aggregate` 写在 rule 级（与 `detection` 同级）而非 `detection` 之下，被 `build_rule` 静默忽略——**该规则的聚合从未生效**，扫描器的每个请求都会单独产出一个 low 事件。已移入 `detection` 并加注释说明该坑。

**验证**

- 前端 `npm run build`（`vue-tsc` + `vite build`）通过；6 个 `collapsedModules` 写入点全为整体赋值（无 `push/splice`），非 deep 的 `watch(ref)` 必然触发落盘。
- 后端 `pytest` **114 passed**；规则质量门禁 **62/62 用例 · 46/46 规则 · TP 70 · FP 0 · FN 0**。
- 修复效果实测：3 条同源 `sqlmap` UA 请求 → **1 个事件 count=3**（修复前为 3 个逐条事件）。
- 全量 `aggregate` 缩进审计通过（`awk` 检查所有 `rules/*.yaml`，不再有 indent≠5 的规则）；规则 YAML 有 mtime 缓存，无需重启 uvicorn。

**新发现（未处理）**

- **Sigma 导入规则不转换聚合/阈值语义**，导入规则天然逐条产事件：同一批 `sqlmap` UA 请求下 `sigma.19aa4f58...`（Suspicious User-Agents）仍输出 3 个 medium 事件。扫描器刷量时会刷屏，属独立问题。

**未做 / 待决策**

- IOA 行为研判（基线口径 / 输出位置 / 是否升级等级三项待拍板）。
- `Event` 缺 `target_asset`，主机侧事件按 `rule:` 拆成多条链。
- `LogRecord` 未暴露进程与文件字段；`AI_TASKS` 无淘汰策略。
- 异常评分只按来源 IP；规则编辑器与变更审计未做。

---

## 2026-09-17

### AI 研判：放宽时长与深度上限，质量优先于耗时

**背景**

用户要求：AI 日志分析的时间可以长一些，不需要固定时长限制，只要能准确得出结论。排查后确认卡住「跑长 / 跑准」的是三个硬编码上限，且都没有测试依赖：

| 位置 | 原值 | 问题 |
| --- | --- | --- |
| `ai.py` `_request_json` 超时 | `AI_TIMEOUT_SECONDS` 默认 **30 秒** | 长上下文 / 推理型模型容易超时，直接报「AI 服务暂时不可用」，把「模型慢」误报成「服务故障」 |
| `ai.py` `MAX_TOOL_ROUNDS` | 硬编码 **3** | 限制模型继续深挖证据的能力 |
| `ai.py` Anthropic `max_tokens` | 硬编码 **2048** | 11 字段结构化研判容易被截断 |

**改动**

- 三个上限全部改为可配置并提供充足默认值：`AI_TIMEOUT_SECONDS=180`、`AI_MAX_TOOL_ROUNDS=6`、`AI_MAX_OUTPUT_TOKENS=4096`（新增 `DEFAULT_TOOL_ROUNDS` / `DEFAULT_OUTPUT_TOKENS` / `DEFAULT_TIMEOUT_SECONDS` 常量，删除不再使用的 `MAX_TOOL_ROUNDS`）。
- 新增 `_int_setting(name, default)`：非法值（非数字 / 0 / 负数）回退默认值，避免把上限误设成「立即中断」。
- 超时与不可用区分：`TimeoutError`（含 `URLError.reason` 为超时的情况）报「AI 服务响应超时（已等待 N 秒）。研判以准确为先，可调大 AI_TIMEOUT_SECONDS 后重试」；连接类错误仍报「AI 服务暂时不可用」。

**验证**

- 后端 `pytest` **114 passed**（+9）。
- 新增 `tests/test_ai_limits.py`（9 个用例）：默认值余量下限、环境变量可调、`0/-1/abc/空串` 均回退默认、超时与 `URLError(TimeoutError)` 都报超时且含 `AI_TIMEOUT_SECONDS`、连接拒绝仍报「服务不可用」。
- 实测生效值：超时 180 秒 / 工具 6 轮 / 输出 4096 tokens；项目 `.env` 未覆盖这三项，改动立即生效（无需额外配置）。

**说明（未改动）**

- 前端 `pollAiTask` 本来就是 `for(;;)` 无次数上限、按 600ms 轮询直到 completed/failed，符合「可以长点」；进度条基于后端真实阶段与百分比，不是定时假动画。
- `main.py` 的 `AI_TASKS` 内存字典无淘汰策略（任务永不过期，因此长跑不会被清理），但会随分析次数增长——属于既有问题，本轮未处理。
- 放宽上限只是不再提前掐断，不会让结论变松：定级仍来自规则与证据。

---

## 2026-09-17

### 检测可信度：结论三态 + 检测覆盖度 + 攻击链级场景语料门禁

**背景**

用户反馈：同类日志分析必须能自动准确识别，不能依赖人工辨认，否则会影响对产品的信任。复盘发现问题的本质不是「少写了一条规则」，而是机制缺失：

1. 解析层字段被丢弃时，规则没有判据，但产品照旧输出「未发现异常」——**虚假保证**比漏检本身更伤信任；
2. 检测覆盖面取决于「我们想到了哪些规则」，**漏了什么完全不可见**；
3. 测试门禁是 rule-centric（每条规则至少一个正样本），**不是 chain-centric**，所以「一条攻击链上漏掉一环」永远不会让门禁变红（第一轮漏了 7 个行为，门禁仍然 100% 全绿）。

**改动（P0）**

- **结论三态**：`analyzer` 新增 `EVALUABLE_FIELDS`（规则可消费的行为字段，`raw` 不计入）与 `EVALUABLE_RATIO_FLOOR = 0.5`。无事件时按覆盖度分流——覆盖完整输出「当前没有发现当前规则覆盖范围内的明显异常」（confidence 0.35）；覆盖不完整输出「检测覆盖不完整（…），当前无法确认是否存在异常」（confidence 0.2），并给出针对性的补齐建议。
- **检测覆盖度**：新增 `models.DetectionCoverage`（总记录 / 含可判定字段 / 命中规则 / 未覆盖 / 未纳入检测 / `limitation`），随 `AnalysisResult.coverage` 返回。`rules_engine` 新增 `evaluate_rule_with_coverage` / `evaluate_rules_with_coverage`，覆盖度与规则执行**复用同一次字段匹配**，不额外增加一遍开销（`evaluate_rules`、`evaluate_rule` 签名与语义保持不变）。
- **解析失败可见**：`ParsedLog.parse_failures` 新增；文本型日志统计未能解析的非空行，EVTX XML 统计无法映射的事件，EVTX 二进制统计解析失败与超出保留上限的事件（`parse_evtx_records` 改为返回三元组）。此前这些内容被静默丢弃。
- **攻击链级场景门禁**：`rule_quality.load_corpus` 支持 `log_file`（相对语料目录引用真实样本）；新增 `evaluation/scenarios/`（`sysmon-intrusion-chain.log`、`nginx-sensitive-file-probe.log`，即两份真实样本固件）与 `evaluation/corpus/scenario.yaml`，用**整份日志 + 完整行为清单**断言：Windows 入侵链 9 条规则（含 `registry_certificate_store` count=4、`discovery_command` count=6），Nginx 场景 3 条规则，且不允许出现未预期事件。
- **覆盖缺口自检工具**：新增 `backend/scripts/coverage_gaps.py`，列出未被任何规则命中的记录并按状态码/行为主体归并。
- **前端**：结果类型新增可选 `coverage`；分析概览的研判卡在覆盖不足时显示告警条并常驻展示覆盖度数字；空事件状态的硬编码文案改为展示后端 `conclusion` + `summary` + 覆盖度（覆盖不足时用告警色区分），旧历史记录缺少 `coverage` 时优雅降级。`style.css` 增加 `.empty-state-warn` / `.empty-coverage`。
- **HTML 报告**：`report.py` 输出检测覆盖度与覆盖不足告警，空事件占位改为引用分析摘要（不再写死「未发现异常」）。

**验证**

- 后端 `pytest` **105 passed**（+8）；规则质量门禁 **62/62 用例 · 46/46 规则覆盖 · TP 70 · FP 0 · FN 0 · P/R 100%**，`docs/rule-quality-report.md` 已重新生成。
- 前端 `npm run build`（`vue-tsc` + `vite build`）通过。
- 新增 `tests/test_detection_coverage.py` 锁定：正常流量仍输出「未发现异常」；只有 `raw` 的记录输出「无法确认」且 `limitation` 含「不含可用于判定的行为字段」；无法识别文本被计数并降级结论；EVTX 不可修复事件计数为 1 而可修复的裸 `&` 正常解析；上传接口与报告导出均带覆盖度；两个场景用例名称与期望规则集合固定；场景日志覆盖度稳定为 42 条记录 / 18 条命中 / 0 解析失败。
- 实测状态对照：正常 Web 流量 → 未发现异常（confidence 0.35）；只有原文的 JSON → 无法确认（0.2）；无法识别文本 → 无法确认 + 2 条未纳入检测；`log.txt` → 11 事件 / coverage 42·18·0。

**顺带修正**

- `test_upload_handles_empty_log` 的置信度断言 0.35 → 0.2：空文件没有任何可判定内容，原本输出「未发现异常」属于虚假保证，本次按新语义修正。
- EVTX 二进制测试的打桩返回值同步为三元组。

**遗留问题**

- 覆盖度只给「条数」，未逐条列出未覆盖行为（清单由 `scripts/coverage_gaps.py` 在开发侧提供，未进产品界面）。
- 主机侧事件仍无 `source_ip`，`build_attack_chains` 按 `rule:` 归组，同一主机的 11 个事件被拆成 9 条链（需给 `Event` 加 `target_asset`）。
- `log.txt` 仍有 24/42 条记录无规则覆盖，其中值得补的是 EID 3 进程外联、EID 11 落地文件创建、EID 12 批量注册表写入（已有自检工具可复核）。
- `curl` 类脚本客户端 UA 未进任何规则（会与 5 个既有正样本用例冲突，且实际运维极常见）。
- 存量 `web.scanner_user_agent` 的 `aggregate` 层级错误（写在 rule 级，聚合从未生效）仍未修。

---

## 2026-09-17

### 补齐 Sysmon 行为规则（+6）与 Web 敏感文件规则（+2），覆盖两份样本日志的完整行为链

**背景**

上一轮修复后 `log.txt` 已能命中 4 条规则，但仍漏掉链条中的凭据清理、自删、证书注册表、随机域名、主机发现、伪扩展名执行；`access.log` 仍漏 `.ssh/id_rsa` 成功读取（200）、`/metrics` 探测与 IPv6 客户端行解析。本轮补齐。

**新增规则**

- `backend/rules/21-sysmon.yaml` +6 条：`windows.masquerade_extension`（high，进程镜像使用文档 / 图片 / 压缩包扩展名，T1036.008）、`windows.credential_file_access`（high，浏览器凭据库 / SSH 私钥 / 云凭证文件操作，T1555）、`windows.payload_cleanup`（medium，临时目录可执行文件被删除，T1070.004）、`windows.registry_certificate_store`（medium，SystemCertificates 等证书策略写入，T1553.004）、`windows.suspicious_dns_query`（medium，超长随机串或大量重复字符域名，T1071.004）、`windows.discovery_command`（low，同一主机 5 分钟内同一发现命令 ≥3 次，T1082，阈值可用 `WINDOWS_DISCOVERY_THRESHOLD` 调整）。
- `backend/rules/30-web-access.yaml` +2 条：`web.sensitive_file_access.success`（high，敏感文件路径返回 2xx，`suppresses` 基础规则）、`web.sensitive_file_access`（medium，SSH 私钥 / 云凭证 / 运维配置 / 备份文件路径探测）。`.git` 前缀继续由 `web.sensitive_path` 覆盖，新规则不重复列入，避免同一请求双报。
- `web.sensitive_interface` 词表补充 `/metrics`、`/health`、`/ready`。

**解析修复**

`parser.WEB_PREFIX` 的 IP 段扩展为「IPv4 或 IPv6」，`::1` 等 IPv6 来源的 Web 访问行不再被丢弃（`access.log` 解析 20 → 21 行）。

**配套改动**

- `rules_engine` 渲染上下文新增 `{file}`（target_filename）、`{registry}`（registry_key）、`{query}`（query_name）。
- `analytics._TACTICS` 补 8 条规则 → ATT&CK 映射（T1036.008 / T1555 / T1070.004 / T1553.004 / T1071.004 / T1082 / 敏感文件探测与读取）；`_PHASE_ORDER` 新增「防御规避」「命令与控制」两个阶段并顺延后续序号（保持既有相对顺序不变）。
- `analyzer._build_recommendations` 扩充主机侧与 Web 敏感文件两类建议。
- 语料：`sysmon.yaml` +6 个用例（5 正 1 负），`web.yaml` +5 个用例（含 IPv6 来源、敏感文件 200/404、`/metrics` 探测）。
- `.env.example` 增补 8 个规则开关与 2 个发现命令阈值。

**验证**

- 后端 `pytest` **97 passed**；规则质量门禁 **60/60 用例 · 46/46 规则覆盖 · TP 58 · FP 0 · FN 0 · P/R 100%**，`docs/rule-quality-report.md` 已重新生成。
- `log.txt`：事件 4 → **11**（3 high / 7 medium / 1 low），完整覆盖下载 → 伪扩展名执行 → 证书注册表写入 → 凭据清理 → 自删 → 随机域名 → 主机发现 → 密码打包；risk=high。
- `access.log`：事件 1 → **3**（`web.path_traversal` high、`web.sensitive_file_access.success` high、`web.sensitive_interface` medium），解析行 20 → 21；risk=high。
- 端到端 `POST /api/logs/upload` 均 HTTP 200，`GET /api/rules` 返回 46 条，`GET /api/rules/quality` 与 pytest 一致。
- 复盘发现并修正 3 处 `aggregate` 层级写错的问题（见下）。

**注意（本项目写规则的坑）**

`aggregate` 必须写在 `detection:` 之下。写在 rule 级（与其同级）会被 `build_rule` 静默忽略，规则退化为逐条记录产事件，且聚合专用占位符（如 `{statuses}`）会渲染为空——本轮新增的两条 Web 规则与一条 Sysmon 规则各踩一次。**存量 `web.scanner_user_agent` 存在同一问题（`aggregate` 位于 rule 级，聚合从未生效），本轮未改动，待确认后单独修复。**

**遗留问题**

- 主机侧事件无 `source_ip`，`build_attack_chains` 按 `rule:` 归组，同一主机的 11 个事件被拆成 9 条链，未形成单主机杀伤链（需给 `Event` 增加 `target_asset` 并调整归组与前端标签，本轮未做）。
- `_parse_evtx_xml` 修复失败时仍静默丢弃，未对外暴露解析失败计数。
- `LogRecord` 未暴露 `process_image` / `command_line` / `target_asset`，日志明细表只能看 `raw`。
- `curl` 类脚本客户端 UA 未加入任何规则：`curl/8.0` 出现在 5 个既有正样本用例中，加入「攻击工具 UA」会造成 5 处误报，且 curl 在实际运维中极常见，故仅通过 `/metrics` 等敏感目标覆盖探测行为。

---

## 2026-09-17

### 修复：Sysmon 日志整体漏报（EVTX 字段未映射 + 无行为规则 + XML 解析静默丢事件）

**问题**

用户对两份日志分别识别：`access.log`（Nginx，21 行）只出 1 个事件、`log.txt`（Sysmon XML 导出，42 条事件）**0 事件、risk=info、结论「未发现明显异常」**。而 `log.txt` 实为完整入侵链：IMEWDBLD.EXE 下载远程载荷 → 执行伪扩展名文件 → 注册表证书策略写入 ×12 → Chrome 凭据导出并清理 → 7z 密码打包后自删。判定为**漏报**。

**根因（三层）**

1. `app/services/evtx.py: event_to_record` 只映射 `TargetUserName` / `SubjectUserName` / `IpAddress` / `WorkstationName`，Sysmon 的 `Image`、`CommandLine`、`ParentImage`、`TargetFilename`、`DestinationIp`、`QueryName`、`Hashes` 全部被丢弃，`raw` 只剩 `Event ID | Date | Provider | Computer`，没有任何可用判据。
2. 非 4624 / 4625 事件一律 `action="event"`、`result=None`；35 条规则中 Windows 侧仅 `rdp.bruteforce(.success)`、`windows.privileged_logon`，且都要求 `action in [logon, rdp_logon]` → Sysmon 事件天然零命中（无任何进程 / 文件 / 网络 / 注册表 / DNS 类规则）。
3. `parser._parse_evtx_xml` 对 `ElementTree.ParseError` 直接 `continue`：一条 `for /f ... do (start "" "%i" & exit)` 的 CommandLine 含未转义 `&`，整条事件被静默丢弃（42 → 41 条），丢的正好是载荷执行这一步，且无计数无提示。

**修复**

- `evtx.py` 新增 `EVENT_DATA_FIELDS` 映射表，把 Sysmon 的进程镜像、命令行、父进程、落地文件、注册表键、DNS 查询、外联目标 / 端口 / 协议、哈希映射进统一记录，并追加到 `raw`；`username` 增加 `User` 兜底。
- `evtx.py` 新增 `_parse_xml`：解析失败时把未转义的裸 `&` 转义为 `&amp;` 重试一次，修复失败才返回 `None`。
- 新增规则文件 `backend/rules/21-sysmon.yaml`（3 条）：`windows.lolbin_download`（high）、`windows.suspicious_executable_in_temp`（medium，限定 Sysmon EID 1）、`windows.archive_with_password`（medium，命令行正则识别 `-p` / `-hp` / `-mem=aes256`），均按 `process_image` 聚合避免刷屏。
- `rules_engine._single_events` / `_aggregate_events` 的渲染上下文新增 `{asset}`（主机名）与 `{image}`（进程镜像），供主机侧规则撰写摘要。
- `analytics._TACTICS` 补充 3 条规则 → ATT&CK 战术映射（T1218 / T1204 / T1560），否则杀伤链会归入「其他」。
- `analyzer._build_recommendations` 补充主机侧行为的排查建议（方向 + 方法）。
- 新增语料 `backend/evaluation/corpus/sysmon.yaml`（4 个用例，含 1 个原始 `&` 命令行用例验证 XML 修复、1 个负样本）。

**验证**

- 后端 `pytest` **97 passed**（无失败）；规则质量门禁 **50/50 用例、38/38 规则覆盖、TP 48 · FP 0 · FN 0、P/R 100%**，`docs/rule-quality-report.md` 已重新生成。
- `log.txt` 复现：修复前 41 条记录 / 0 事件 / risk=info → 修复后 **42 条记录 / 4 事件**（1 high + 3 medium）/ risk=high；杀伤链正确落到「执行」「数据渗出」阶段。
- `access.log` 结果未变化（1 个 high `web.path_traversal`）。
- 端到端 `POST /api/logs/upload` 返回 HTTP 200，`/records` 返回 42 条明细。

**遗留问题**

- `access.log` 仍漏 3 类：`.ssh/id_rsa` 成功读取（HTTP 200）未升级为敏感文件访问、`/metrics` 403 + `curl` UA 未命中词表、`::1 "OPTIONS * / HTTP/1.0"` 未解析（21 行 → 20 行且无提示）。
- `_parse_evtx_xml` 修复失败时仍静默丢弃，未对外暴露解析失败计数。
- 主机侧事件无 `source_ip`，杀伤链按 `rule:` 归组，同一主机的多条行为被拆成多条链（建议按 `target_asset` 归组）。
- `LogRecord` 未暴露 `process_image` / `command_line` / `target_asset`，日志明细表暂只能看 `raw`。

---

## 2026-09-17

### 修复：EVTX 二进制上传 500（python-evtx 需要文件路径而非 BytesIO）

**问题**

用户上传真实 EVTX 文件（`安全.evtx` / `应用程序.evtx` / `系统.evtx`，4132/389/1048 条事件）时报 `Internal Server Error`（HTTP 500）。

**根因**

`backend/app/services/evtx.py` 的 `parse_evtx_records` 把上传的字节内容以 `io.BytesIO(content)` 传给 `Evtx(...)`；而 `python-evtx==0.8.1` 的 `Evtx.__init__` 只接受**文件路径字符串**，`__enter__` 内部执行 `open(self._filename, "rb")` + `mmap.mmap(fileno, ...)`，传入 `BytesIO` 会抛 `TypeError: expected str, bytes or os.PathLike object, not BytesIO`。

此前 `test_evtx_binary_upload_uses_dedicated_parser` 将 `parse_evtx_records` 打桩为 lambda，真实函数从未对真实二进制跑过，掩盖了该缺陷。

**修复**

`parse_evtx_records` 改为把内容先写入 `tempfile.NamedTemporaryFile(suffix=".evtx", delete=False)`，用其路径打开 `Evtx`，解析完成后在 `finally` 中清理临时文件。去掉不再使用的 `io` 导入。

**验证**

- 新增回归测试 `test_evtx_binary_parser_uses_real_path_and_cleans_temp`：用假 `Evtx` 断言收到的是 `str` 路径（非 `BytesIO`）且临时文件已清理。
- 后端 `pytest` **91 passed**（+1）。
- 真实文件端到端：三份 EVTX 经 `POST /api/logs/upload` 均返回 **HTTP 200**，识别为 `windows_evtx`，`安全.evtx` 命中 10 个可疑事件（risk=medium），另两份 info。

**顺带清理**

历史测试数据清理完成：`analyses` 表清空（498→0）、`VACUUM` 后 DB 缩至 12 KB、`data/uploads/` 清空；清空前备份到 `data/backups/loginsight-20260917-143656.db`。

---

## 2026-09-17

### AI 研判模块充实（赋能流水线）+ MongoDB 明文适配 + 全类型富化

**需求**

① AI 研判模块「鸡肋」（0 事件时只剩工具轨迹），充实内容更好体现「AI 赋能」，且不与概览重复；② MongoDB 风格日志被误判 generic（只支持 JSON 格式）；③ SSH / Nginx / IIS / Windows / JSON/CSV / Firewall 等全部日志类型均需适配标准化→富化→AI 研判链路。

**改动**

- **AI 研判模块**（`App.vue` + `style.css`）：
  - 工具轨迹升级为「AI 赋能流水线」：标准化 → 统计富化 → 事件研判 → 证据检索 → 时间线 → 溯源校验 6 阶段横向流程，每阶段展示产出计数（行数/解析、成败登录、事件、证据、时间线、未支撑数），工具调用详情收进可折叠 `<details>`，避免信息冗余；
  - 溯源校验新增**正面状态**（`ai_status=completed` 且无未支撑声明时显示绿色「溯源校验通过」卡），此前只在出问题时才提示；
  - 模块副标题增加「结构化研判 ✓」。
- **MongoDB 明文适配**（`parser.py`）：新增明文 mongod 格式（`ISO+0800 级别 组件 [ctx] message`）识别与解析，ACCESS=认证、NETWORK=连接，提取账号与来源 IP；`_looks_like_mongodb` 兼容 JSON 与明文。此前用户 1.log 落到 generic/0 行解析即此因。
- **全类型富化**（`evtx.py` + `ai.py`）：EVTX/Windows 记录新增 `target_asset`（主机名），使结构化研判「目标资产」字段可落地；溯源索引新增 `targets` 集合，`目标资产` 主机名也纳入幻觉校验。
- 新增明文 MongoDB 演示日志（DEMO_VISIBLE 12→13）。

**验证**

- 后端 `pytest` **97 passed**；前端 `vue-tsc && vite build` 通过；
- 端到端：明文 MongoDB → 识别 `mongodb`、13 行全解析、2 事件；真实 AI → 结构化研判 11 字段卡 + 6 阶段流水线渲染正常、控制台零报错。

**说明**

- 结构化研判（11 字段）与富化流水线本质是**日志类型无关**的：SSH/IIS/Windows/JSON/CSV/Firewall 等已走同一链路（已用真实 AI 验证 SSH、MySQL）。此前截图里的「0 行解析 / appuser 不存在」是旧进程解析的历史数据，修复解析器后重新上传即可。

---

## 2026-09-17

### AI 强制结构化研判（11 字段）+ SQL Server / Oracle 适配

**需求**

① 验证并完善「日志 → 标准化 → 富化 → AI 研判」关键链路：让 AI 最终**强制输出** 11 个结构化字段（事件时间 / 攻击源IP / 目标资产 / 涉及账号 / 异常行为 / 关联日志 / 攻击类型 / 风险等级 / 判断依据 / 是否存在成功迹象 / 建议处置）；② 不止四种数据库，补 SQL Server、Oracle 等其它数据库日志适配。

**① AI 强制结构化研判（后端 + 前端）**

- 新增 `StructuredVerdict` 模型（11 字段）与 `AnalysisResult.structured_verdict`。
- `SYSTEM_PROMPT` 显式要求输出 `structured` 子对象（11 个键、无法确定的留空、禁止编造）；`_build_structured_verdict` 归一化兼容顶层直给 / `structured` / `verdict` 子对象与同义键名，全空返回 None。
- 溯源校验扩展：`attack_source_ip` / `target_asset` 须在日志 IP 集合中，`involved_account` 须在日志账户集合中（新增账户索引），否则记入 `ai_unsupported_claims`。
- 前端：AI 研判模块顶部新增「AI 结构化研判」卡片，两列 11 字段表格；风险等级彩色标签、成功迹象红绿区分、关联日志/建议处置以胶囊展示。
- 真实 DeepSeek 联调通过：SSH 暴力破解日志 → 11 字段完整输出（攻击源IP 203.0.113.7、账号 root、判断依据引用规则与证据编号、成功迹象含 evidence 编号），无幻觉。

**② SQL Server / Oracle 适配（后端 + 前端）**

- `parser.py`：新增 SQL Server errorlog（`Logon` + `Login failed/succeeded for user` + `[CLIENT: ip]`）与 Oracle alert.log（`DAY MON DD HH:MM:SS YYYY` + `ORA-xxxxx`）识别与解析；SQL Server 提取用户名与来源 IP，Oracle 提取 ORA 错误码（01017/28000 → 认证失败）。
- `db.bruteforce(.success)` / `db.privileged_login` 规则 logsource 扩展到 sqlserver / oracle。
- 前端配色：sqlserver=fuchsia、oracle=slate（新增两个不撞色色调）；演示日志 +2（sqlserver.log / oracle.log），DEMO_VISIBLE 10→12。
- 语料 +2（SQL Server / Oracle 爆破），测试 +1（识别与字段映射扩展）。

**验证**

- 后端 `pytest` **97 passed**；前端 `vue-tsc && vite build` 通过；
- SQL Server / Oracle 实测各命中 `db.bruteforce`（10 次失败，SQL Server 带来源 IP）；真实 AI 联调输出完整 11 字段结构化结论。

---

## 2026-09-17

### 分析概览「日志类型」指标卡改为彩色标签 + DB 类型专属配色

**需求**

识别出 MySQL 等数据库类型后，概览的「日志类型」也要像列表页一样显示彩色标签，且新配色不能与既有标签撞色。

**改动（仅前端）**

- 分析概览「日志类型」指标卡由纯文本改为 `kind-tag` 彩色标签（与列表页同一体系，动态取 `logTypeTone`）；`.metric span` 收窄为 `.metric > span` 避免标签被标签外样式覆盖，新增 `.metric .kind-tag` 放大版式（14px / 12px 内边距）。
- 色调重排（避免撞色）：`mysql=orange`、`postgresql=cyan`、`mongodb=lime`、`redis=rose`；新增 cyan/lime/rose 三个色调（浅色用 100 级更饱和底色与既有 50 级标签明显区分），orange 底色从 #fffaeb 调整为 #ffedd5 与 amber 拉开；补齐对应 picker-dot 色点与暗黑主题变体。

**验证**

- `vue-tsc && vite build` 通过（CSS 48.56 kB）；
- Edge 无头实测：上传 MySQL 演示日志 → 识别 `mysql`、4 个事件，概览标签渲染 `kind-tag tone-orange`；浅色/暗黑截图人工核对通过，页面零报错。

---

## 2026-09-17

### 新增数据库日志识别与研判（MySQL / PostgreSQL / MongoDB / Redis）

**需求**

能够完整识别各种数据库类型的日志并进行研判，规则同步编写完善。

**后端改动**

- `parser.py`：
  - 新增 4 类 DB 日志识别与解析：MySQL（general log + error log 的 Access denied）、PostgreSQL（stderr `LEVEL: message`，含 `connection authorized` / `password authentication failed` / `statement:`）、MongoDB（结构化 JSON `t/s/c/msg` + `attr.user/remote`）、Redis（`pid:role DD Mon YYYY ...` 单行）。
  - 记录字段映射：`action` = login/query/connect/event/error；`result` = success/failure（认证）；`url` = 查询语句/命令文本；`username` = 数据库用户；`source_ip` = 客户端来源（从 `@host` / `remote` / `host=` 提取）。
  - 识别顺序置于通用 JSON 之前（MongoDB 用专属特征区分），并修复 MySQL 误判过宽（去掉仅靠时间戳前缀的判定）、Redis 日期格式（日在前，同 syslog）。
- `rules/70-database.yaml`：新增 7 条规则 —— `db.bruteforce`（聚合认证失败）/ `db.bruteforce.success`（后续成功）/ `db.sql_injection`（union/布尔/报错/时间盲注特征）/ `db.destructive_query`（DROP/TRUNCATE/DELETE/SHUTDOWN）/ `db.privilege_escalation`（GRANT/CREATE/ALTER USER/SET GLOBAL）/ `db.data_exfiltration`（INTO OUTFILE/LOAD_FILE/COPY TO/dump）/ `db.privileged_login`（root/postgres/sa 等高权限账户登录）。
- **跨类型隔离修复**：SSH/Windows 认证规则与 Web 攻击规则此前用 `display_log_types`（仅展示、不参与过滤）或 `exclude: [json, csv]` 粗筛，会误命中 DB 的 login/query 记录；现为这些规则补 `exclude_log_types: [mysql, postgresql, mongodb, redis]`，杜绝 `ssh.privileged_login`/`web.sql_injection` 命中数据库日志。
- `analytics.py`：DB 规则接入 ATT&CK 风格战术映射（凭据访问/初始访问/权限提升/数据渗出/影响），攻击链阶段新增「数据渗出」。
- `analyzer.py`：新增数据库研判处置建议。

**语料 / 测试**

- `evaluation/corpus/database.yaml`：11 个用例（7 条规则正样本 + 正常查询/阈值以下 2 个负样本）。
- 测试 +2（DB 识别与字段映射、SQL 入 `url`）：后端 **96 passed**；语料 **44/44、规则覆盖 35/35、TP 43 / FP 0 / FN 0**。

**演示日志**

- `sample_logs/database/`：MySQL general log（含注入/删表/提权/外传）、PostgreSQL（认证失败聚集 + 特权登录）、MongoDB（认证失败聚集）、Redis（口令错误聚集）；`DEMO_VISIBLE_FILES` 6→10 份。

**前端**

- `LOG_TYPE_TONES` 增加 mysql（sky）/ postgresql（indigo）/ mongodb（green）/ redis（red）彩色标签。

**验证**

- 端到端：4 份 DB 演示日志合并分析 → **8 个事件**（3×db.bruteforce + sql_injection + destructive_query + privilege_escalation + data_exfiltration + privileged_login），攻击链正确给出「初始访问/影响/权限提升/凭据访问/数据渗出」阶段。

**遗留**

- PostgreSQL 文本日志（stderr）的认证失败行不含来源 IP（IP 在 CSVlog 的 `connection_from`），爆破按账户聚合；如需来源 IP 可扩展 CSVlog 解析。
- 未覆盖 SQL Server（错误日志）、Oracle（alert.log）等；可后续按同样模式扩展。

---

## 2026-09-17

### 品牌区改版 + 暗色 tooltip 白块修复 + 柱状图基线对齐

**修复 / 改动（仅前端）**

1. **品牌区**：只保留品牌 logo（居中、高 26px→40px），删除 "AI-LogInsight / 安全日志研判" 文字，logo 下方改为「安全日志分析平台」小字；`.brand` 改纵向布局居中。
2. **暗色白块 bug**：共两处根因——① logo 上的原生 `title` 属性，悬停时弹出浏览器默认白色 tooltip；② `.page-header` 硬编码 `rgb(255 255 255 / 92%)` + backdrop-filter（与上次 `.toolbar` 同类问题）。修复：移除 `title`（保留 `alt`）；页头暗黑下改为不透明深色 `#0f141e`。全量扫描确认样式表已无其他硬编码白色背景，实测顶部区域浅色背景元素 **0 个**。
3. **柱状图基线不齐**：根因是 x 轴时间刻度 `.hist-tick` 放在柱子列内部，有刻度的列底部多占一行把柱子顶起。改为独立轴层 `.hist-axis`（绝对定位按百分比分布 ≤8 个刻度），柱列只含数值+柱体。

**验证**

- `vue-tsc && vite build` 通过（CSS 47.88 kB / JS 136.09 kB）；
- Edge 无头实测：brand 区域 logo 109×40 + 副标题、旧文字已移除、`title=null`；顶部 70px 内白色背景元素 **0 个**；**22 根柱子底边坐标唯一**（基线完全齐平）；暗色截图人工核对通过。

---

## 2026-09-17

### AI 洞察（时间柱状图 + 攻击链）+ 品牌 logo + 暗黑标签增色

**需求**

① 分析概览增加"AI 赋能"场景：时间柱状图（对比攻击前后频次）+ 多日志攻击链关联（ATT&CK 风格前因后果）；② 品牌位替换为用户提供的品牌图；③ 暗黑下标签颜色更突出。

**后端（`backend/app/services/analytics.py` 新增，`main.py`/`models.py` 配套）**

- 新增 `GET /api/analysis/{id}/insights` 返回 `Insights { timeseries, attack_chains }`：
  - **时间序列**：全量记录按时间分桶（桶宽按跨度自动归整到 1s~7d 档位，目标 ≤48 桶），每桶输出记录数、独立来源 IP 数、失败/成功登录数——攻击发生时柱子显著高于平时。
  - **攻击链**：把可疑事件按来源 IP（无 IP 按规则）分组，按「战术阶段 → 时间」排序串成链；每阶段映射 ATT&CK 风格战术（凭据访问/初始访问/权限提升/发现/持久化/执行/影响，含 T 编号），链风险取阶段最高。
- 测试 +3：`test_insights_endpoint_returns_timeseries_and_attack_chain`、`..._maps_bruteforce_to_credential_access`、`..._unknown_analysis_returns_404`。后端 **94 passed**。

**前端（`App.vue` + `style.css`）**

- 新增详情页模块 **「AI 洞察」**（新 tier `insight`，玫红配色 `--tier-insight`，动态编号 + 可折叠，空数据自动隐藏）：
  - **时间频次柱状图**：flex 柱状图，柱高=记录频次，hover 提示（时间/记录/独立IP/失败/成功），峰值柱红色高亮 + 底部「峰值 N 条」徽标，两端显示起止时间刻度；
  - **攻击链**：每条链 = 风险徽章 + 来源 IP + 阶段卡片流（战术胶囊 + 事件名 + 技术/时间），阶段间箭头连接，左边框按风险着色。
- **品牌 logo**：品牌图复制到 `frontend/public/`，品牌位替换为 `<img class="brand-logo">`（高 26px 自适应），副标题改为「安全日志研判」。
- **暗黑增色**：`.kind-tag` 加 currentcolor 描边 + 更饱和的深色底/亮字；`.badge` 描边加强；critical/high 风险徽章加发光；picker 色点加光环。

**验证**

- 后端 `pytest` **94 passed**（+3）；前端 `vue-tsc && vite build` 通过（CSS 47.71 kB / JS 135.89 kB）。
- Edge 无头端到端 11 项全 PASS（组合演示日志 ssh+iis+firewall）：insights 22 桶 / 2 条攻击链 / 3 阶段、峰值高亮、logo `naturalWidth>0`、导航出现「AI 洞察」、暗黑切换、**控制台零报错**；浅色/暗黑全页截图人工核对通过。

**遗留**

- 战术映射为简化版（非完整 MITRE ATT&CK 编号库），Sigma 导入规则统一落到「其他」阶段；
- 时间桶宽为全局统一值，超长时间跨度（月级）可考虑支持 `?bucket=` 参数。

---

## 2026-09-17

### AI 真实进度 + 日志下载 + 下拉色点 / 类型彩色标签

**需求**

① AI 研判进度条反映真实阶段（此前为前端模拟）；② 用户上传的日志可下载（演示日志不需要）；③ 列表页日志类型列由纯文本改为彩色小标签；④ 四个筛选下拉（风险等级/状态/排序/日志类型）选项加颜色标识。

**后端改动（`backend/app/main.py`、`backend/app/services/ai.py`）**

- `request_ai_judgement` 新增 `progress_cb` 回调，在 5 个真实阶段上报：`prepare_context`（构建上下文）→ `run_tools`（确定性工具）→ `call_model`（AI 调用）→ `parse_response`（解析校验）→ `grounding`（溯源校验）。
- 新增 `POST /api/analysis/{id}/ai/start`：启动后台线程执行研判，返回 `task_id`；`GET /api/ai/tasks/{task_id}`：轮询任务状态/阶段/百分比，完成时附带完整结果。阶段→进度映射：10/25/65/85/95/100%。
- 旧同步接口 `POST /api/analysis/{id}/ai` 保留（兼容与测试）；合并逻辑抽取为 `_apply_ai_judgement` 复用。
- 上传日志落盘：`_persist_upload_files()` 将原始文件保存到 `data/uploads/{analysis_id}/`（同名自动加序号；演示日志不落盘）。
- 新增 `GET /api/analysis/{id}/download`：单文件直接下载，多文件打包 zip；无原始文件（演示日志）返回 404。删除分析时顺带清理上传目录。

**前端改动（`frontend/src/App.vue`、`frontend/style.css`）**

- `analyzeWithAi` 改为 start + 每 600ms 轮询，`aiProgressActive` / `aiProgressPercent` 由后端真实阶段驱动；浮层进度条显示真实百分比（运行中蓝-青流光，完成变绿 100%）。步骤文案与后端阶段一一对应（6 步含「研判完成」）。
- `PickerChoice` 新增 `tone` 字段：风险等级（严重红/高浅红/中橙/低绿/信息蓝）、状态（绿/蓝/红）、排序（蓝/蓝/红/绿）、日志类型（ssh 紫、web 蓝、windows/evtx 青、json 琥珀、csv 绿、firewall_waf 红、mixed 靛、generic 灰）选项带色点，选中后触发器同步显示。
- 列表页日志类型列改为 `.kind-tag` 彩色标签（soft 底 + 色点 + 等宽字体）。
- 下载入口：详情页头部「下载原始日志」按钮 + 列表行「下载」按钮；`canDownload` 判定（文件名以 `demo-` 开头不显示），演示日志自动隐藏。

**验证**

- 后端 `pytest`：**90 passed**（新增 6 个：任务启动/轮询/失败传播/未知 task 404/单文件下载/多文件 zip/演示日志 404）。
- 前端 `vue-tsc && vite build` 通过；产物 CSS 37.89 kB / JS 130.50 kB。
- Edge 无头端到端实测（1440×940，15 项全 PASS）：
  - 列表 kind-tag ×10；四个下拉色点 ×5/×11/×3/×4；
  - 上传行有「下载」、演示行无；详情页下载按钮点击得到原始内容（1765 bytes 与上传一致）；
  - AI 进度浮层出现后显示真实阶段「调用 AI 模型 · 65%」、6 步渲染、完成后自动关闭；
  - **控制台零报错**。
- 过程中发现并排除环境问题：8000 端口被旧会话遗留的 uvicorn 占用（Errno 10048），导致新路由 404；终止旧进程（PID 32088）后恢复。

**遗留**

- AI 任务状态存于进程内存 `AI_TASKS`，多 worker 部署（uvicorn --workers >1）时轮询可能路由到不同进程；单进程部署无影响，如需多 worker 可改为 SQLite 存储。
- `data/uploads/` 会随上传增长，删除分析时已联动清理，但无全局容量上限。

---

## 2026-09-17

### AI 研判进度浮层（步骤条 + 百分比 + 动画）

**问题**

用户反馈「AI 研判的时候能不能加个进度条，让用户知道 AI 研判了，而不是无感」。当前页面仅在右上角按钮内有一个小 spinner + "AI 研判中..." 文案，缺乏全局可见的进度反馈，等待时间较长时用户会以为页面卡死。

**改动**

仅改前端（`frontend/src/App.vue` + `frontend/style.css`），无后端改动，不改动 AI 调用 API。

- 新增全局浮层 `v-if="aiLoading"`：固定居中卡片，z-index 70，覆盖当前页面，避免用户在研判期间误操作。
- 新增 5 步状态：`准备日志上下文` → `调用 AI 模型` → `解析研判结果` → `合并证据链` → `AI 研判完成`。
- 进度表现：
  - 上方大标题显示当前步骤描述；
  - 中间进度条带百分比（按步骤数平滑推进），未完成时播放蓝-青流光动画，完成后变绿并 100%；
  - 下方步骤列表显示序号 / 对勾 / 当前高亮。
- 实现机制：点击「进行 AI 研判」后启动 850ms 间隔的步骤推进，请求返回后跳到「完成」并延迟 500ms 再关闭浮层，让用户感知到结果已应用。
- 可访问性：`aria-live="polite"`、`aria-busy="true"`、进度条 `role="progressbar"`。

**验证**

- `cd frontend && npm run build` → `vue-tsc -b && vite build` 通过，控制台零报错；
- 产物 CSS 36.47 kB / JS 128.61 kB，体积增长在合理范围（新增样式 + 模板）；
- TypeScript 类型检查通过（`aiProgressActive`、`AI_PROGRESS_STEPS`、`aiProgressTimer` 均带类型）。

**遗留**

- 当前为前端模拟步骤，因为后端 `/api/analysis/{id}/ai` 是单次同步 POST；如需真实进度，可后续改为 SSE / 异步任务轮询。

---

## 2026-09-17

### 减少详情页线条/边框，改用色块与顶线分层

**问题**

用户截图反馈「这一部分线条太多了」。红线框住的区域包含模块左侧 3px 色条、研判结论卡片左侧 3px 色条、当前结论/处置建议等带左边框的提示卡片，以及指标卡的边框——多条竖线与框线平行叠加，显得杂乱。

**改动**

仅改前端样式（`frontend/style.css`），无后端改动、无模板结构改动。

- **模块容器**：去掉左侧 3px 实色条；改为顶部 2px  tier 色线（研判结论=蓝 / AI=紫 / 关联分析=青 / 原始数据=灰），既保留分层辨识度，又减少一条竖线；同步把 `.module-head` 左侧内边距从 21px 调回 18px（原本为色条留空）。
- **指标卡**：去掉 1px 边框，改为 `--surface-soft` 浅灰底 + 极浅投影，从「线框卡片」变成「底色卡片」。
- **研判结论卡**：去掉边框与左侧 3px 色条，改为风险等级对应背景色（严重/高=红软底、中=橙软底、低=绿软底、信息=蓝软底）。
- **当前结论提示条 / 处置建议卡**：去掉左侧 3px 主色条与边框，改为 `primary-soft` 浅蓝底圆角块。
- **可疑事件条目**：左侧风险线从 3px 减到 2px，并同步调小左内边距 1px，保持对齐。

**验证**

- `cd frontend && npm run build` → `vue-tsc -b && vite build` 通过，控制台零报错；
- 产物 CSS 34.48 kB / JS 126.41 kB，体积无异常增长；
- 模块、概览、事件、时间线、明细等区块渲染无样式错位。

**遗留**

- 若用户仍觉得顶部色线太多，可进一步改为「仅模块索引块着色 + 完全无边框」；
- 指标卡去边框后，白色页面背景上依赖投影分层，极浅主题下对比度略低，后续可微调 `--surface-soft` 明度。

---

## 2026-09-17

### 日志明细筛选栏视觉重构

**问题**

用户截图反馈「日志分析的这些框框都太难看了」。截图中的筛选栏由 6 个纯输入框/原生下拉 + 3 个按钮平铺组成，边框、内边距、高度均不统一，缺少图标和视觉分组，在复杂的分析详情页中显得零乱。

**改动**

仅改前端（`frontend/src/App.vue` + `frontend/style.css`），无后端改动。

- 引入 `frontend-design` skill 的设计原则：把筛选栏视为「证据检索命令栏」，用图标、统一的灰底输入区和紧凑卡片容器来降低认知负荷。
- 新增 `.filter-bar` / `.filter-cell` / `.filter-actions` 结构：
  - 每个输入框/选择器外部包一个 `.filter-cell`，左侧放置 16px 图标（源 IP = 地球、目的 IP = 箭头、路径/URL = 链接、日志类型 = 图层、动作 = 活动、状态码 = 对勾圆环）；
  - 输入框统一 34px 高、左侧 32px 内边距留给图标、浅灰背景，focus 时白底 + 主色光圈；
  - 自定义选择器触发器同样左内边距 32px，与输入框严格等高；
  - 筛选/重置/导出 CSV 按钮归为一组 `.filter-actions`，靠右对齐；
  - 整个筛选栏加 12px 圆角卡片容器 + 极浅投影，与工具栏其他区域形成层级。
- 响应式：窄屏（≤900px）时路径输入框占满行、操作按钮组另起一行右对齐。

**验证**

- `cd frontend && npm run build` → `vue-tsc -b && vite build` 通过；
- 产物 CSS 34.69 kB / JS 126.41 kB，控制台零报错；
- 列表页不受影响（仍使用原 `.toolbar-fields`）。

**遗留**

- 列表页顶部筛选栏未同步改造，后续若需要可复用 `.filter-bar` 结构；
- 图标使用内联 SVG，若后续引入图标库可统一替换为组件。

---

## 2026-09-17

### 状态徽章风格差异化

**问题**

列表页的风险等级、状态、AI 状态等徽章长期使用同一套「圆点 + 浅色填充」样式，视觉上单调且不易区分语义。用户反馈「状态栏可以风格变换，不用统一格式」。

**改动**

- `frontend/src/App.vue`：为所有徽章增加语义修饰类：
  - 风险等级使用 `.badge-risk`（严重/高风险为实心红，中/低/信息保持浅色）；
  - 分析状态使用 `.badge-status`（已完成 ✓ / 分析中 加载环 / 失败 ×）；
  - AI 状态使用 `.badge-ai`（小绿点 / 小红点 / 灰点）；
  - 顶部引擎状态使用 `.badge-state`（绿/橙双色点）；
  - 时间线「事件 / 证据」标签使用 `.badge-kind`（方块点 + 圆角矩形）。
- `frontend/style.css`：新增 `.badge-risk` / `.badge-status` / `.badge-ai` / `.badge-state` / `.badge-kind` 样式；为工具栏/分页选择器补充高度对齐（`.toolbar-select .picker-trigger` 34px / `.pager-select .picker-trigger` 30px）。

**验证**

- `cd frontend && npm run build` → `vue-tsc -b && vite build` 通过，控制台零报错；
- 产物 `dist/assets/index-C1O7Ae6E.css` / `index-Dm-33jyt.js` 生成正常。

**遗留**

- 日志类型列仍为纯文本，后续若需要可改为带颜色点的小标签；
- 状态徽章图标使用内联 SVG data URI，后续若引入图标库可替换为组件。

---

## 2026-09-17

### 视觉柔化（圆角 / 投影）与自定义选择器

**一、视觉柔化（令牌级调整，不改变既有风格）**

| 令牌 / 组件 | 调整前 | 调整后 |
| --- | --- | --- |
| `--radius-lg`（面板、指标卡、模块卡、表格容器） | 12px | **16px** |
| `--radius`（卡片、下拉面板） | 10px | **12px** |
| `--radius-sm` | 7px | 9px |
| `--radius-control`（按钮 / 输入框 / 下拉触发器） | 复用 `--radius-sm`(7px) | **10px**（新增令牌） |
| `--shadow-xs` | `0 1px 2px /5%` | `0 1px 2px /4%, 0 2px 6px /4%` |
| `--shadow-sm` | `0 1px 3px /8%, 0 1px 2px /4%` | `0 2px 6px /6%, 0 1px 2px /4%` |
| `--shadow-md`（弹窗、下拉面板） | `0 12px 32px /12%` | `0 20px 48px /16%` |
| 弹窗圆角 / 弹窗底栏 | 14px | **20px** |
| 输入框聚焦光圈 | `0 0 0 3px /12%` | `0 0 0 4px /10%` |
| 侧栏导航项 / 品牌标 / 模块序号块 / 关闭按钮 | 7–9px | 10–11px |

指标卡、面板、模块卡、表格容器、上传拖拽区等均引用上述令牌，因此同时变圆润；未改动配色、字号、间距、栅格与布局结构。

**二、自定义选择器（替代原生 `select`）**

原生 `select` 在 Provider（18 个候选）上会弹出全宽灰底长列表，与其他控件风格割裂。新增内联实现的选择器（`frontend/src/App.vue` + `style.css`，未新增文件）：

- **触发器**：品牌字母头像（按 provider 名哈希取 6 套柔和配色）+ 中文名称 + 原始 provider 键 + 旋转箭头；打开时显示 4px 主色聚焦光圈；
- **面板**：圆角卡片 + 深投影，顶部搜索框（"搜索 Provider 或模型…"，匹配名称 / 键 / 默认模型），列表最大高度 260px 内部滚动，选中项高亮并显示对勾；
- **选项内容**：头像 + 名称 + 副标题（`默认模型 xxx · 共 N 个`），**不含参考图中的「倍率」徽章**；
- **交互**：点击触发器开合、点击选项立即生效、点击面板外关闭、`Esc` 先关下拉再关弹窗、遮罩点击关闭；
- **覆盖范围**：AI 配置弹窗的 **Provider** 与 **模型** 两个字段（其余筛选类 `select` 保持原生，避免动到吸顶工具栏）。

**三、顺带修复**

1. 模型下拉原先选择「自定义模型...」只是把值置空、没有输入框可填，形成死路；现在选择「自定义模型…」会切换为文本输入框，Provider 无预设模型时同样直接给输入框；
2. 新增 `Esc` 关闭上传弹窗 / AI 配置弹窗（此前只能点关闭按钮或遮罩）。

**验证**

- `vue-tsc --noEmit` 通过；
- Chrome 无头实测（1440×940）：
  - AI 配置弹窗内原生 `select` 数量由 2 → **0**；Provider 面板 18 个选项、搜索框、选中项对勾、面板圆角 12px、列表 max-height 260px 且内部可滚动（scrollHeight 984 / clientHeight 260）、面板完全落在弹窗内不裁剪；
  - 搜索 `claude` → 仅 1 条 `Anthropic Claude`；选择后 `provider=anthropic`、`Base URL` 自动填 `https://api.anthropic.com`、模型自动填 `claude-3-5-haiku-latest`、面板自动关闭；
  - 模型选择器列出 2 个预设模型 + 「自定义模型…」，选择自定义后出现文本输入框；
  - `Esc` 关闭弹窗、点击弹窗内非下拉区域关闭下拉、遮罩点击关闭弹窗均生效；
  - 圆角令牌实测：`--radius-lg` 16px / `--radius` 12px / `--radius-control` 10px，弹窗 20px、按钮与输入框 10px；
  - 列表页与详情页（模块导航、模块卡、指标卡、表格、分页）渲染正常，控制台零报错、零 4xx。

**遗留**

- 工具栏与分页中的筛选类 `select`（日志类型 / 风险等级 / 状态 / 排序 / 每页）仍为原生控件，若需要统一样式需再改造 5–6 处；
- 下拉面板为文档流内绝对定位（会受弹窗 `overflow` 裁剪），当前弹窗高度足够；若后续弹窗内出现更高的下拉列表，需要改为浮层定位。

---

## 2026-09-17

### 分析详情页模块化重构（信息层级与导航）

**问题**

分析详情页此前是「4 个指标卡 + 左栏可疑事件 + 右栏统计侧栏 + 4 个平铺面板（模板 / 实体 / 时间线 / 明细）」的线性堆叠：所有面板外观一致、无分区编号、无导航，AI 结论与工具轨迹嵌在可疑事件面板内部，用户需要长距离滚动才能判断当前处于哪个部分。新增能力（模板挖掘、实体关联、时间线、AI 轨迹、异常评分）持续追加后，问题被放大。

**一、模块化分区（`frontend/src/App.vue`）**

| 模块 | 内容 | 分层 |
| --- | --- | --- |
| `01 分析概览` | 4 个指标卡 + 研判结论卡 + 关键统计（来源 IP Top / HTTP 状态码 / 异常评分）+ 处置建议 | 研判结论 |
| `02 可疑事件` | 规则命中事件、证据、事件时间线 | 研判结论 |
| `03 AI 研判` | AI 识别行为、未支撑声明、工具调用轨迹（原嵌在可疑事件面板内，现独立） | AI 语义 |
| `04 日志模板` | Drain3 模板挖掘结果 | 关联分析 |
| `05 实体关联` | 跨日志类型实体串联 | 关联分析 |
| `06 统一时间线` | 事件与证据的时序合并 | 关联分析 |
| `07 日志明细` | 原始记录、筛选、分页、CSV 导出 | 原始数据 |

- **统一模块头**：两位序号 + 标题 + 一行摘要 + 分层标签 + 操作按钮 + 收起/展开；模块序号按「当前实际可见的模块」动态生成，空模块（无 AI 结果、无模板、无实体、无时间线）自动隐藏且不留编号空档；
- **分层配色**：四个分层颜色令牌（研判结论 = 蓝、AI 语义 = 紫、关联分析 = 青色、原始数据 = 灰）分别作用于模块左侧色条、序号块、分层标签与导航标签激活态，用于一眼分辨「结论 / AI / 关联 / 原始数据」；
- **可折叠**：每个模块可单独折叠，折叠状态在导航标签上以虚线边框体现；默认折叠「关联分析」层的模板 / 实体 / 时间线，首屏只保留结论、事件与明细；导航栏提供「折叠关联分析 / 展开关联分析」一键切换；
- **统计与建议归位**：原右侧栏（来源 IP Top / HTTP 状态码 / 异常评分 / 进一步排查）拆分为概览模块内的「关键统计」卡片与「处置建议」卡片，取消左右分栏，避免同一层级信息被切成两列；
- **去重**：移除与概览重复的研判徽章行（置信度 / 分析来源 / AI 状态 / 事件数）与面板上的英文 eyebrow 标签，减少同屏重复信息。

**二、模块导航（常驻于工具栏首行）**

- 与「返回日志列表」「折叠关联分析」「进行 AI 研判」同处吸顶工具栏首行，滚动时始终可见；标签带序号、名称与计数（事件数 / 模板数 / 实体数 / 时间线条数 / 明细条数）；
- 点击标签平滑滚动到对应模块，折叠中的模块先自动展开；
- 高亮跟随：滚动时按「已滚过吸顶区域的最后一个模块」高亮，页面滚到底时锁定最后一个模块（短板模块也能正确高亮）；点击标签后由点击目标锁定高亮，用户再次滚动 ≥48px 才交还给滚动位置，避免短页面下高亮被抢走；
- 明细筛选行与计数收敛到第二行，工具栏由三行压缩为两行（1440 宽下吸顶高度 199px → 161px）。

**三、顺带修复**

1. **跳转落点被吸顶遮挡**：原先按模块导航底部计算滚动偏移，而吸顶区域还包含筛选行，导致点击跳转后模块标题被遮住；改为按整个工具栏底部避让，实测 6 个模块标题落点均为工具栏下方 12px、完全可见；
2. **明细表 IP 列折行**：`.cell-mono` 的 `overflow-wrap: anywhere` 让 IP 在窄列里被拆成多行（`203` / `.0.` / `113` / `.99`），新增 `.cell-ip` 单独控制为不折行；
3. **证据定位与折叠冲突**：点击事件证据的「定位日志」时若明细模块处于折叠状态，`scrollIntoView` 会失效；现自动展开明细模块后再定位；
4. 清理重构后失效的样式（`.detail-grid`、`.stack`、`.aside-block`、`.judgement-row`、`.panel-pad`）。

**验证**

- `vue-tsc --noEmit` 通过；`vite build` 通过（CSS 27.15 kB / JS 117.33 kB）；后端 `84 passed`（未改后端逻辑）；
- Chrome 无头实测（1440×940）：
  - 六模块场景（混合日志）：导航 01–06 编号连续、模块左侧色条 3px、头部内边距 21px；逐个点击标签，激活项与目标模块一致，6 次跳转模块标题落点均在工具栏下方 12px 且完全可见；
  - 高亮跟随：点击后滚动到顶部 → `01 分析概览`；滚到底部 → 最后模块；按 0% / 25% / 50% / 75% / 100% 分屏滚动 → `分析概览 → 可疑事件 → AI 研判 → 日志明细`；
  - 折叠：默认折叠关联分析层，点击已折叠标签自动展开，一键折叠/展开按钮文案与状态一致；
  - 最小场景（无事件、无模板、无实体、无时间线的普通访问日志）：仅渲染 `01 分析概览 / 02 可疑事件 / 03 日志明细`，无空模块；
  - 窄屏 900px：侧栏隐藏、模块导航独占一行并横向滚动、窄屏隐藏次要按钮；
  - 列表视图未受影响（无模块导航、筛选栏与列表结构不变）；
  - 全程控制台零报错、零 4xx 响应。

**遗留**

- 模块折叠状态不持久化（刷新后回到默认折叠）；
- 模块导航为标签式（无分组标题），分层信息靠配色与标签文字承载；
- 规则编辑器与规则变更审计仍未做。

---

## 2026-09-17

### 规则声明式引擎、Sigma 社区规则导入、基准集与异常评分

**背景**

- 21 条检测规则此前全部硬编码在 `detector.py`（906 行），新增一条规则必须改代码；
- `detector.py` 中还存在重复定义（`_detect_windows` 定义两次，AuthProfile 版本已被覆盖）；
- 「规则质量」无法验证：只有 67 个功能测试，没有标注语料，也没有误报率口径。

**一、声明式规则引擎（新增 `app/services/rules_engine.py`，585 行）**

| 原语 | 作用 |
| --- | --- |
| `detection.where` / `detection.any` | 记录级条件：AND 列表 + 可选 OR-of-AND 组；支持 11 种操作符、5 种字段变换、取反与大小写策略 |
| `detection.aggregate` | 时间窗聚合：`group_by`（支持派生字段，如「URL 归一化后的路径」）、`count_gte`、`window_seconds`、`distinct_field` + `distinct_gte`（端口扫描这类多目标规则）、`bucket`（仅分组汇总） |
| `detection.aggregate.follow_up` | 跨记录关联：在窗口之后匹配另一类记录（失败聚集 → 成功登录），带关联时间窗 |
| `suppresses` / `upgrade_rule` | 同一行为的规则优先级：升级规则命中时压制基础规则；升级规则被关闭时基础规则改用「降级措辞」 |
| `event.*` | 事件构造策略：计数口径、last_seen 口径、证据选取策略、文案占位符与按关联状态切换的措辞 |

- 规则文件：`backend/rules/*.yaml`（6 个文件、21 条规则），`source: builtin`；
- 阈值 / 开关沿用既有环境变量（`threshold_env` / `window_env` / `enabled_env`），`.env` 配置无需改动；
- YAML 解析结果按文件 mtime 缓存，但 `Rule` 对象每次重建，环境变量改动立即生效；
- `detector.py` 从 **906 行缩到 14 行**（改为调用引擎），`rules.py` 从 293 行缩到 33 行（改为 YAML 元数据访问层），硬编码规则目录删除，重复定义一并消除。

**二、基准集与误报率评估（新增 `evaluation/corpus/`、`app/services/rule_quality.py`）**

- 语料：4 个 YAML 文件、**33 个用例**，含 21 个正样本用例与 8 个负样本用例（阈值以下、正常流量、同端口重复访问、非高权限登录等）；
- 评估口径：用例必须命中期望规则且风险 / 次数 / 来源 IP 一致，未列出的规则命中即计 FP；
- 交付形式：`scripts/eval_rules.py`（支持 `--write` 生成 `docs/rule-quality-report.md`，存在偏差时退出码 1）、`GET /api/rules/quality`、以及测试门禁 `tests/test_rule_quality.py`。

**三、Sigma 社区规则导入（新增 `app/services/sigma_import.py`）**

- 转换链路：logsource 映射 → 条件表达式解析（`and` / `or` / `not` / 括号 / `1 of` / `all of`）→ 字段映射 pipeline → 修饰符映射 → DNF 归一化；
- 条件按布尔代数严格转换，含 De Morgan 展开（`not 1 of filter_main_*` → 逐条件取反）；
- **不猜测**：字段无法映射（`SourcePort`、`TargetServerName`）、修饰符不支持（`base64` / `cidr` / `fieldref` / `windash` / 大小比较）、条件展开超限时整条规则跳过并报告原因；
- 样例取自 SigmaHQ（`evaluation/sigma-samples/`，9 条）：7 条导入成功、2 条明确跳过；
- 导入结果写入 `backend/rules/90-sigma.yaml`（脚本生成），具备全局开关 `RULE_SIGMA_IMPORTED_ENABLED` 与逐条开关；
- 新增 `POST /api/rules/sigma/preview`（上传预演，只转换不写盘）与 `scripts/import_sigma.py`。

**四、异常评分（新增 `app/services/risk_scoring.py`，借鉴 OWASP CRS）**

- 同源事件按权重累计（critical 10 / high 5 / medium 3 / low 1），达到阈值升级风险等级；
- 跨来源不叠加；阈值可配置（`RISK_SCORE_MEDIUM` / `RISK_SCORE_HIGH` / `RISK_SCORE_CRITICAL`）；
- **默认关闭**：分数照常计算并在详情页展示，但不改变等级与结论，保证规则基线与回归稳定。

**顺带修复**

1. Windows **文本**解析器此前丢弃非认证事件（如 4825），与 EVTX 路径行为不一致，同时挡住了一整类 EventID 规则；现统一为非认证事件保留为明细记录（`action=event`、`result` 为空，不进认证统计）；
2. Web 特征规则收紧作用范围（要求记录带 URL，User-Agent 规则限定为「有 URL 或 Web 类日志」），避免把 Windows 事件中的 `cmd.exe` / `nmap` 等词误判为 Web 攻击；
3. `ssh.bruteforce` 等规则的实际适用范围是「非结构化认证日志」，`/api/rules` 元数据由 `exclude_log_types` 如实展示（`[ssh, generic]`）；
4. README / PROGRESS 中「20 条规则」的旧口径由 21 更正，现为 28 条（21 内置 + 7 Sigma）。

**验证**

- 后端测试：**84 passed**（新增 13 个引擎 / Sigma / 评分测试，67 个既有测试全部保持通过，含措辞与证据编号断言）；
- 规则质量：**33/33 用例通过、28/28 规则有正样本、TP 34 / FP 0 / FN 0、precision 与 recall 均为 100%**；
- 等价性验证过程：先用同一套语料在「旧实现」上冻结基线，再切引擎比对；迁移中修正了 3 处不等价（窗口把后续成功记录计入计数、升级规则缺少 follow_up 约束、SSH 规则来源范围过窄），修正后逐项与基线一致；
- 导入规则实测：`/.git` 探测、SQL 注入、XSS、Java 载荷、路径遍历、扫描器 User-Agent、4825 事件共 7 条真实社区规则均能命中并进入事件与报告；
- 异常评分实测：默认关闭时等级不变（分数 21 仅展示），开启后同一份日志由 high 升级为 critical 并在结论中注明。

**遗留**

- Sigma 字段映射仅覆盖本项目记录模型已有字段（日志文本类）；进程创建 / 注册表 / 网络连接类字段需要先补齐记录模型才能导入；
- 异常评分按来源 IP 单一维度累计，未按账户 / 主机维度；
- 规则编辑器与变更审计未做（当前以 YAML + 质量评估脚本管理）。

---

## 2026-09-17

### AI 工具调用、证据溯源与模型返回兼容修复

**背景**

- `AGENTS.md §6` 承诺的 5 个只读工具（`log_metadata` / `log_statistics` / `query_events` / `query_evidence` / `timeline`）一直未实现，AI 研判是「一次性塞上下文」；
- 真实联调发现：DeepSeek 返回的 JSON 使用 `behavior_id` / `title` / `description` / `risk_assessment` 等字段，而 `_validate_response` 只认 `type` / `name` / `analysis` / `summary`，导致 **AI 输出被整段丢弃**，页面只剩兜底文案「AI 无法根据当前证据确认更具体的结论」且 behaviors 恒为空 —— 属于长期静默失效。

**新增**

| 项 | 实现 |
| --- | --- |
| 工具层 | 新增 `backend/app/services/agent_tools.py`：5 个只读工具 + JSON Schema；未知工具/执行异常返回可读错误，不抛出 |
| 工具轮次 | `OpenAICompatibleProvider.complete_with_tools()`：下发 tools，执行 `tool_calls` 后回填 `role=tool` 消息，最多 3 轮；轮次用尽会要求模型直接出结论 |
| 确定性工具预处理 | 研判前先本地跑一轮 `AUTO_TOOL_PLAN`（metadata → statistics → query_events → query_evidence → timeline），结果放入 `context["tool_results"]`，与 `AGENTS.md §7` 的 6 步流程对齐；轨迹标记 `source=auto` |
| 降级 | `OllamaProvider` / `AnthropicProvider` 标记 `supports_tools=False` 走单次调用；支持工具的 Provider 若工具轮次失败也会自动降级为单次调用 |
| 证据溯源 | 新增 `_check_grounding()`：结论与 behaviors 中的 IP、记录编号必须存在于本次日志记录集合，否则记录为未支撑声明；口径包含未被规则命中的记录，避免把日志事实误判为幻觉 |
| 模型兼容 | `_validate_response()` 归一化字段别名：`risk_level`/`risk`、`summary`/`conclusion`、`behaviors`/`findings`、`type`/`behavior_id`、`name`/`title`、`analysis`/`description`、`recommendations`/`next_steps`；`evidence_ids` 兼容 `record-N` 并映射回证据编号 |
| 提示词 | `SYSTEM_PROMPT` 显式给出输出 JSON 结构与字段名，减少 schema 漂移；说明 `tool_results` 可直接引用 |
| 前端 | 「AI 调用工具轨迹」（工具名 / 参数 / 来源标注 / 结果摘要）与「未在日志证据中找到对应记录」提示条 |

**验证**

- 后端测试：**67 passed**（新增 8 个：5 个工具返回、未知工具、工具轮次与轨迹、schema 漂移兼容、真实模型输出保留、溯源误报回归、端到端持久化）。
- 真实 AI 联调（DeepSeek，`ssh/auth.log` + `iis/iis-access.log`）：工具轨迹 **5 次**（全部 `自动执行`），AI 结论与 2 个 behaviors 完整保留，`evidence_ids` 映射为 `evidence-privileged_login-1`、`evidence-sensitive_path_access-1`，未支撑声明为 0。
- 前端（Chrome 无头 1440×1000）：轨迹 5 条、证据链接 2 个、行为 2 条，控制台零报错、零 4xx。
- `vue-tsc --noEmit` 通过。

**遗留**

- 工具调用只实现 OpenAI-compatible 协议，Anthropic 走单次调用（协议差异，暂不做双实现）；
- 未支撑声明仅做文本级校验（IP / 记录编号），账户名与 URL 未纳入；
- README/PROGRESS 的规则总数由 20 修正为实际的 21。

---

### 未知日志模板挖掘（Drain3）与跨事件实体关联 / 统一时间线

**背景**

- 未匹配已知类型的日志此前只落 `log_type=generic`、解析 0 行，等于「无内容可看」；
- `PROGRESS.md` 已把「跨事件实体关联与统一时间线」列为下一步，事件之间此前只在单类型内部关联（`correlation_basis`）。

**新增依赖**

- `drain3==0.9.11`（纯 Python，附带 `cachetools`、`jsonpickle`），已写入 `backend/requirements.txt`。

**模板挖掘**

| 项 | 实现 |
| --- | --- |
| 模块 | 新增 `backend/app/services/templates.py` |
| 触发条件 | `parse_log()` 中仅当识别结果为 `generic` 时挖掘，已知类型不做（避免无意义开销与噪声） |
| 掩码 | 聚类前把 IP、12 位以上十六进制串掩码为 `<IP>` / `<HEX>`，防止同类日志被拆成大量模板 |
| 输出 | 模板、出现次数、占比；仅出现一次的模板标记 `rare`；最多 20 个，按次数排序；最多扫描 20000 行 |
| 模型 | 新增 `LogTemplate`；`AnalysisResult.templates`；`ParsedLog.templates` |
| 合并 | 多文件分析时按模板文本合并计数（`analyzer._merge_templates`） |

**实体关联与统一时间线**

| 项 | 实现 |
| --- | --- |
| 模块 | 新增 `backend/app/services/correlation.py` |
| 实体维度 | 来源 IP、目的 IP、账户；命中可疑事件的实体，或跨 ≥2 份日志文件出现的实体会被列出 |
| 实体输出 | 风险等级（取其关联事件的最高风险，不新增独立结论）、关联事件数、命中规则、日志类型、来源文件、首次/末次出现、中文摘要 |
| 时间线 | 可疑事件 + 其日志证据合并，按归一化时间排序、去重，最多 200 条；每条含时间、事件/证据、标题、规则编号、来源 IP / 账户 / 文件 |
| 模型 | 新增 `EntityProfile`、`TimelineEntry`；`AnalysisResult.entities` / `AnalysisResult.timeline` |
| AI 上下文 | `build_ai_context` 对模板、实体摘要、时间线（前 50 条）统一脱敏后一并提供给 AI |

**前端**

- 详情页新增三块：**日志模板**（次数 / 占比 / 罕见标记）、**实体关联**（类型 / 实体 + 摘要 / 风险 / 关联事件 / 命中规则 / 首末时间）、**统一时间线**（左侧时间轴 + 风险点 + 事件/证据徽章 + 规则编号），均为有数据才渲染；
- 事件空状态在存在模板时补充提示，指向下方「日志模板」；
- 新增样式：`.records-table.compact`、`.timeline-*`、`.cell-note`、`.rule-code`。

**演示日志**

- 新增 `sample_logs/generic/app.log`（33 行 Java 应用日志，含订单/库存/超时/缓存模板与 3 条罕见行），并加入 `DEMO_VISIBLE_FILES`（5 → 6 份）。

**验证**

- 后端测试：**59 passed**（新增 6 个：模板挖掘、已知类型不挖掘、跨类型实体关联、时间线有序、无事件时时间线为空、AI 上下文携带新字段）。
- `sample_logs/generic/app.log` 实测：`generic`、解析 0 行 → 7 个模板（13 / 8 / 6 / 3 次 + 3 条罕见），罕见模板命中 `OutOfMemoryError`、`异常请求签名 source=<IP>`、`主从延迟`。
- 多文件实测（`ssh/auth.log` + `iis/iis-access.log`）：`mixed`、4 个实体、4 条时间线，实体摘要正确指出命中规则与来源文件。
- 前端（Chrome 无头 1440×980）：模板 7 行 / 罕见徽章 3 个、实体 4 行、时间线 4 条，控制台零报错、零 4xx。
- `vue-tsc --noEmit` 通过。

**遗留**

- 模板挖掘只做结构归纳，不参与风险判定（有意为之，避免与规则结论混淆）；
- 实体关联目前是「一次分析内」的关联，不跨历史分析；时间线展示混合时间格式（各日志原有格式）。

---

### 演示样本精简与 Web 时间窗规则修正

**新增与修复**

- `/api/demo/logs` 继续只暴露 5 份白名单样本；展示样本压缩到约 30 条解析记录，保留 SSH、IIS、Windows XML、CSV、Firewall 五类体验入口。
- 前端默认选择 `structured/auth-events-demo.csv`，打开演示即可看到本地规则研判结果，避免把“没有命中规则”误认为上传失败。
- `web.404_scan` 现在按 `WEB_404_WINDOW_SECONDS` 的滑动时间窗口判断，不再把跨长时间累计的 404 直接判为路径扫描。
- 增加普通 `access.log` 上传成功但未命中规则的回归测试，明确验证 `nginx_apache`、解析行数、`analysis_source=rules` 和 `risk_level=info`。
- 增加 404 跨时间窗不告警测试；保留 `web.5xx_burst` 的中风险候选及故障/攻击触发区分建议。

**验证**

- 后端：新增普通 access.log、404 时间窗测试；完整测试待本次样本文件调整后运行。
- 前端：默认演示选择逻辑保持 TypeScript 类型安全，待 `vue-tsc` 运行确认。

**限制**

- 规则是确定性候选检测；正常访问日志没有命中规则时仍会显示无可疑事件，AI 研判需要单独配置 Provider/API Key。

---

## 2026-09-16

### Windows EVTX 支持、Web 登录聚集规则、冗余清理与文档精简

**新增能力**

1. **Windows EVTX（本机事件日志）研判**
   - 二进制 `.evtx`：按文件头魔数 `ElfFile\x00` 识别，使用 `python-evtx` 流式读取事件，`Evtx(BytesIO(...))` 支持内存解析；
   - XML 导出：兼容事件查看器「另存为 XML」/ `wevtutil` 导出的 `<Event>` 文本；
   - 事件映射：`4625` → failure、`4624` → success，账户取 `TargetUserName`，来源取 `IpAddress`（回退 `WorkstationName`），登录类型 7/10 → `rdp_logon`，其余 `logon`；
   - 复用既有 Windows/RDP 规则（`rdp.bruteforce`、`rdp.bruteforce.success`、`windows.privileged_logon`，规则 `log_types` 增加 `windows_evtx`），非认证事件保留为明细记录（`action=event`、`status=事件 ID`）用于取证，认证事件优先保留 5000 条、其它事件最多 500 条；
   - 上传上限由 10 MB 提升到 50 MB（EVTX 文件通常较大），演示日志白名单放开 `.xml`。
2. **Web 登录失败聚集规则**：`web.auth_bruteforce`（medium，默认 4 次 / 300 秒）与 `web.auth_bruteforce.success`（high），针对含 `login`/`auth`/`token` 等路径的 401/403 聚集，并关联窗口内的 2xx 响应；规则总数 18 → 20。

**修复**

- **时间窗口跨时区崩溃**：EVTX 时间戳带时区（`+00:00`），与其它日志类型的无时区时间戳混合分析时，`_failure_window` 抛 `TypeError: can't compare offset-naive and offset-aware datetimes`（多文件混合分析直接 500）。`_record_time()` 现统一归一化为无时区 UTC 后比较。

**冗余清理（行为等价）**

| 项 | 处理 |
| --- | --- |
| 风险等级排序元组重复（`analyzer.py` / `main.py` / `ai.py`） | 统一为 `models.RISK_ORDER` |
| `analyzer` 中 records 列表构建两次 | 合并为一次构建 |
| 风险等级计算两次（`_build_judgement` + 独立循环） | `_build_judgement` 直接返回风险等级，删除重复循环 |
| `_build_judgement` 恒为 `"rules"` 的第三个返回值 | 删除，改用模型默认值 |
| `analyze_parsed_log()` 仅被 `analyze_log()` 调用的中间层 | 删除，直接调用 `analyze_parsed_logs()` |
| `style.css` 中未被引用的 3 条规则（`.btn-block`、`.icon-button`、`.panel-body`） | 删除 |

**文档精简**

- `PROGRESS.md`：463 行 → 66 行，只保留当前能力、规则清单、运行验证、已知问题与下一步；历史过程记录完整归档到 `docs/archive/PROGRESS-历史记录-2026-09.md`；
- `README.md`：补充 EVTX 小节、上传格式与大小上限、新规则说明，规则总数更新为 20；
- 变更明细统一收敛到本文件，避免 PROGRESS 与 CHANGELOG 重复记录。

**验证证据**

| 项目 | 结果 |
| --- | --- |
| 后端测试 | `50 passed`（新增 7 个：EVTX XML 映射 / 非认证事件映射 / XML 导出识别与研判 / 二进制分发 / 非 EVTX 二进制容错 / Web 登录聚集 / 阈值以下不告警） |
| EVTX XML 端到端 | `log_type=windows_evtx`（0.92）、14 行 → 11 条记录、失败 10 / 成功 1、`rdp_bruteforce_success`（high）+ `privileged_login`，`status=4625` 过滤 10 条 |
| 多文件混合分析 | 8 份演示日志（含 EVTX XML）混合 → `log_type=mixed`、13 个事件、风险 high（验证时区归一化修复） |
| 测试隔离 | 完整测试前后 `data/loginsight.db` 记录数不变 |

**遗留**

- 二进制 `.evtx` 的真实文件端到端未在本机验证（`C:\Windows\System32\winevt\Logs` 在受控环境中不可读），已通过单元测试与 monkeypatch 分发测试覆盖解析与检测链路；
- `System.evtx` 等非安全日志不含 4624/4625 时不会产生事件，仅保留明细记录；
- 契约类冗余（`LogStatistics.total`、`top_users`、`Event.evidence` 与 `evidence_items`）未清理，属 API 变更需单独评估。

---

### 脱敏访问日志解析容错与 Web 攻击特征规则

**问题**：上传一份 76 行 `access.log` 被判为 `generic`、已解析 0 行、风险 info。该文件是脱敏后的访问日志——请求段无引号，路径与时间中的 `/` `:` 被剥离（`16Sep2026090112 +0800`、`wp-admin`、`HTTP1.1`）。原 Web 解析依赖 `"METHOD URL HTTP/1.1"` 引号结构，无法匹配；同时日志中的注入、XSS、命令注入、WebShell 等特征在规则库中没有对应条目。

**文件变更**

| 文件 | 类型 | 说明 |
| --- | --- | --- |
| `backend/app/services/parser.py` | 修改 | 新增 `_parse_web_line()` 容错解析；时间戳兼容分隔符被剥离的写法 |
| `backend/app/services/detector.py` | 修改 | 新增 `WEB_ATTACK_SIGNATURES` 与 `_detect_web_signatures()`；敏感路径补齐前导 `/`；路径遍历同时匹配原始与解码 URL |
| `backend/app/services/rules.py` | 修改 | 新增 6 条 Web 攻击特征规则（12 → 18） |
| `backend/app/services/analyzer.py` | 修改 | 新增攻击特征排查建议分支 |
| `backend/app/database.py` | 修改 | 数据库路径支持 `LOGINSIGHT_DB_PATH` |
| `backend/tests/conftest.py` | 新增 | 测试固定使用临时 SQLite |
| `backend/tests/test_analysis.py` | 修改 | 新增 2 个测试；新增 autouse fixture 隔离项目 `.env` |
| `sample_logs/windows/security-rdp.log` | 精简 | 350 → 98 行（10 次 4625 + 1 次 4624） |
| `sample_logs/structured/vpn-events.json` | 精简 | 193 → 21 行（改为 NDJSON） |
| `.env.example` | 修改 | 增加 6 个 `RULE_WEB_*` 开关 |
| `README.md` | 修改 | §5 Nginx/Apache 补充三种解析写法与攻击特征规则清单；实现状态更新 |

**关键实现**

1. `_parse_web_line()` 先定位 `IP - - [时间]` 前缀，再解析请求段：有引号时取引号内内容，无引号时按 HTTP 版本标记切分；URL 允许包含空格，因此 `searchq=' OR '1'='1` 可完整保留。
2. 时间戳先剥离 `/` `:` 再按 `DD Mon YYYY HH MM SS` 匹配，同时覆盖标准与脱敏写法。
3. Web 攻击特征以数据表描述（规则 ID、事件类型、名称、风险、markers、可选 predicate / scan_raw），按「来源 IP + 规则」聚合为一条事件，携带命中次数、首末时间与最多 10 条证据。
4. 测试隔离：`conftest.py` 在导入应用前设置 `LOGINSIGHT_DB_PATH` 指向临时目录。

**验证证据**

| 项目 | 结果 |
| --- | --- |
| 后端测试 | `43 passed`（新增 2 个；修复 3 个受本机 `.env` 影响的既有测试） |
| 用户脱敏 `access.log` | `log_type=nginx_apache`（0.90）、76 行解析 59 条、风险 high、15 个事件：敏感路径 ×2、路径遍历 ×2、SQL 注入 ×4 + ×1、XSS ×3、命令注入 ×2、WebShell ×1、敏感接口 ×4 + ×2 + ×2、攻击工具 UA ×3×3 |
| 精简演示日志 | `security-rdp.log`（98 行）→ `rdp_bruteforce_success` + `privileged_login`；`vpn-events.json`（21 行）→ `auth_bruteforce_success` |
| 测试隔离 | 完整测试前后 `data/loginsight.db` 记录数不变（473） |
| 前端 | 详情页 15 个事件、规则编号、证据折叠正常；控制台零报错 |

**遗留**

- 未实现「Web 登录爆破」规则（同一来源 HTTP 401 聚集 + 后续 200 成功），用户样例中 `POST apilogin` 4×401 后 200 目前不会被判定；
- 若脱敏过程把分隔符本身删除（`/.git/config` → `.gitconfig`），无法还原原始路径；
- `data/loginsight.db` 现有 473 条历史记录（多数为历史测试数据），清理需用户确认。

---

### 本地规则研判演示样例与 Detection 状态优化

- 新增 `sample_logs/structured/auth-events-demo.csv`：同一来源 IP 在 5 分钟内出现 20 次认证失败，随后成功登录。
- 未调用 AI 时，Detection 明确显示“本地规则初步研判”，并说明结论来自确定性规则和日志证据。
- 事件卡按风险等级增加左侧色带，规则 ID 使用等宽标签，便于快速识别风险和检测规则。
- 样例端到端验证：CSV、21 条记录、`auth.bruteforce.success`、high、20 次、来源 IP `203.0.113.90`。

验证：业务相关后端测试 `38 passed`（3 个 AI 配置测试因根目录 `.env` 现存配置而被排除），前端 `vue-tsc --b` 通过。

---

### AI 配置预设与内置演示日志

- AI 配置接口返回各 Provider 的推荐 Base URL 和常用模型列表。
- 前端 Provider 选择自动填充 Base URL 和模型，模型改为选择框并保留自定义网关能力。
- 新增 `/api/demo/logs` 和 `/api/demo/analyze`，在上传弹窗提供预置日志选择和批量体验。
- 演示日志覆盖 SSH、IIS、Windows/RDP、JSON/CSV、Firewall/WAF，读取范围限制在 `sample_logs/` 白名单目录。
- 增加演示日志完整分析和目录越界测试。

验证：后端 `40 passed`，前端 `vue-tsc --b` 通过。

---

## 2026-09-16

### Firewall/WAF 解析与端口扫描候选

- 新增 `firewall_waf` 日志识别和常见 syslog 键值解析：`SRC`、`DST`、`PROTO`、`DPT`、`ACTION/VERDICT`。
- 统一记录和证据增加目的端口、协议字段。
- 新增 `firewall.port_scan` 规则，默认在 300 秒内访问 10 个不同端口时生成中风险候选事件。
- 新增 `sample_logs/firewall/firewall.log` 和对应回归测试，覆盖阈值、规则关闭和明细字段。

验证：后端 `38 passed`，前端 `vue-tsc --b` 通过。

---

## 2026-09-16

### 规则独立启停配置

- 为 SSH、Web、Windows/RDP、JSON/CSV 认证检测规则增加 `.env` 独立启停开关，默认启用。
- `GET /api/rules` 返回每条规则当前的 `enabled` 状态。
- 增加规则全部关闭后的回归测试，确认日志解析、统计和证据链仍可用。
- README 补充可识别的布尔值、重启要求和只读配置边界。

验证：后端 `35 passed`，前端 `vue-tsc --b` 通过。

---

## 2026-09-15

### 变更一：前端首页重构为「分页日志列表 + 常驻筛选栏」

#### 需求

| 编号 | 需求 | 实现情况 |
| --- | --- | --- |
| R1 | 首页要有日志列表，不能像原来那样无限往下堆叠 | 已实现：表格列表 + 完整分页 |
| R2 | 日志筛选要固定在首页，而不是点开某条日志后才出现 | 已实现：常驻 `sticky` 筛选栏，随视图切换字段 |
| R3 | 结合网上现有项目风格整体改版 | 已实现：左侧固定侧边栏 + 吸附页头 + 卡片化内容区 |

#### 文件变更

| 文件 | 类型 | 说明 |
| --- | --- | --- |
| `frontend/style.css` | 全量重写（123 → 525 行） | 设计令牌、双栏骨架、吸附页头与筛选栏、表格/徽章/分页/弹窗/拖拽区/空状态/滚动条/响应式 |
| `frontend/src/App.vue` | 全量重写（599 → 1090 行） | 列表视图 + 详情视图 + 上传弹窗 + AI 配置弹窗 |
| `frontend/index.html` | 修改 | 增加内联 SVG favicon，消除控制台 404 |
| `backend/app/database.py` | 修改（`get_record_page`） | `status` 筛选同时匹配 `status` 与 `result` |
| `backend/tests/test_analysis.py` | 新增 1 个测试 | `test_record_status_filter_matches_result_and_status_code` |
| `PROGRESS.md` | 追加 | 本次进度记录 |

未新增前端组件文件、未引入任何新依赖、未改动 API 契约。

#### 详细变更

**1. 日志列表（R1）**

- 由「历史分析」纵向堆叠列表改为表格列表；
- 列：文件名 + 任务号短码、日志类型、风险等级徽章、状态徽章、上传时间、操作（查看 / 删除）；
- 分页：每页 10 / 20 / 50 条可选，含首页 / 上一页 / 页码（超 7 页自动省略号）/ 下一页 / 末页，并显示「第 x / y 页 · 共 n 条」；
- 变更筛选项或每页条数时自动回到第 1 页；记录被删除后页码自动收敛。

**2. 常驻筛选栏（R2）**

- 新增 `.toolbar`，`position: sticky; top: 60px`，吸附在吸附式页头下方，任何视图下始终可见；
- 列表范围「日志列表筛选」：关键词（文件名 / 日志类型 / 任务号）、日志类型、风险等级、状态、排序（最近上传 / 最早上传 / 风险从高到低 / 风险从低到高）、重置；
- 明细范围「日志明细筛选」：源 IP、目的 IP、路径 / URL、日志类型、动作、状态码 / 结果、筛选、重置、导出 CSV，并附加「← 返回日志列表」；
- 打开某条日志后筛选栏自动切换为明细范围，返回列表后自动切回列表范围；
- 原实现中「筛选项位于页面底部、且只在选中某条分析后渲染」的行为已删除。

**3. 视觉与交互（R3）**

- 左侧固定侧边栏：品牌区、日志列表导航（含记录数）、AI 配置入口（含 ON/OFF）、后端服务与分析引擎状态卡；
- 页头吸附：面包屑、导出 JSON / 导出 HTML、AI 状态徽章、上传日志按钮；
- 上传日志改为弹窗：支持拖拽、点击选择、多选按名称+大小去重、展示文件大小、单文件移除、分析中加载态；成功后自动进入该分析详情；
- 详情页重排：4 个指标卡 → 可疑事件（含证据 / 时间线折叠）→ 侧栏来源 IP Top、HTTP 状态码、进一步排查 → 日志明细表；
- 统一设计令牌（颜色 / 圆角 / 阴影 / 间距 / 字号）、按钮体系（主 / 幽灵 / 柔和 / 危险 / 小尺寸）、徽章、空状态、加载态、滚动条样式；
- 响应式断点：1100px（指标卡 2 列、详情单列）、900px（隐藏侧边栏）、640px（单列 + 分页换行）；
- 视觉风格遵循 `AGENTS.md` §27：浅色、白 / 浅灰 / 蓝色、无渐变、无霓虹。

**4. 后端配套修复（真实缺陷）**

- 现象：明细筛选的 `status` 参数只匹配记录中的 `status` 字段（Web 状态码），而 SSH 日志的结果存放在 `result` 字段（`success` / `failure`），导致按「状态码 / 结果」筛选 SSH 日志恒为 0 条；
- 修复：`repository.get_record_page()` 中 `status` 改为对 `status` 与 `result` 字段拼接后做不区分大小写的包含匹配；
- 新增测试覆盖：`status=failure` → 20 条、`status=success` → 1 条、`status=404` → 1 条。

#### 验证证据

| 项目 | 命令 | 结果 |
| --- | --- | --- |
| 后端测试 | `.venv\Scripts\python.exe -m pytest tests -q` | `21 passed, 1 warning` |
| 前端类型检查 | `vue-tsc --noEmit -p tsconfig.json` | 通过（退出码 0） |
| 生产构建 | `vite build --outDir <临时目录>` | 通过：CSS 18.1 kB / JS 99.1 kB（gzip 4.3 / 36.8 kB） |
| 浏览器实测 | Playwright + 本机 Chrome 无头，1440×940 | 见下 |

浏览器实测结果：

- 列表每页 10 行，共 110 条 → 11 页；
- 风险筛选「高风险」→ 72 条；
- 筛选栏计算样式 `position: sticky`、`top: 60px` 生效；
- 翻页至第 2 页正常；
- 返回列表后筛选范围自动切回「日志列表筛选」；
- 明细每页由 50 切为 20 后翻至第 2 / 2 页正常；
- 明细按 `failure` 筛选 → 20 条，与后端接口返回一致；
- 控制台零报错，零 4xx 响应。

#### 已知问题与遗留

1. **测试污染真实数据库**：后端测试会写入 `data/*.db`，首页因此混入大量测试数据（当前 117 条，文件名如 `report.log`、`empty.log`、`2 个日志文件`）。建议测试改用临时数据库。
2. **列表分页为客户端分页**：当前一次性拉取 `/api/logs` 后在前端筛选分页，记录量大后需后端支持分页与筛选。
3. `App.vue` 已达 1090 行，建议尽早拆分为 `LogList` / `AnalysisDetail` / `UploadModal` / `AiConfigModal` 等组件。
4. `npm run build` 在本沙箱内会因 `rmSync` 的安全删除 shim 超时失败（`prepareOutDir` 阶段），属环境限制而非代码问题；`vite build --outDir <不存在的目录>` 可正常产出。
5. 项目无版本控制，本次改动无法通过 git 回滚，建议尽快 `git init` 建立基线。

---

### 变更二：修复 `start_loginsight.ps1` 解析错误

#### 现象

双击 `启动 AI-LogInsight.bat` 报错：

```text
start_loginsight.ps1:139 字符: 41  字符串缺少终止符: "。
start_loginsight.ps1:132 字符: 6   语句块或类型定义中缺少右"}。
```

#### 根因

- 脚本保存为 UTF-8 **无 BOM**；
- `.bat` 调用的是 `powershell.exe`（Windows PowerShell 5.1），对无 BOM 脚本按系统 ANSI 代码页（简体中文为 CP936/GBK）解码；
- 中文多字节序列的尾字节把紧随其后的 ASCII `"` 一并吞掉，导致引号配对整体错位；
- 因此报错行 139 并非真正出错行，真实位置是上一处中文提示的收尾引号；
- 此前「PowerShell 启停脚本语法检查通过」的结论是在 PowerShell 7 下得出的（pwsh 默认 UTF-8），掩盖了 5.1 的编码问题。

#### 修复

| 文件 | 变更 |
| --- | --- |
| `start_loginsight.ps1` | 重存为 UTF-8 with BOM；文件头注释固化该约束；三处中文提示在收尾引号前保留一个 ASCII 空格作为二次保险；就绪轮询上限 5s → 60s；输出区分前后端各自就绪状态 |
| `stop_loginsight.ps1` | 纯 ASCII，无需改动 |

#### 验证

- 后端测试 `20 passed`；
- 脚本通过最坏情况 DBCS 解码校验，引号配对无错位；
- 真实 PowerShell 5.1 双击验证待执行（当时的执行环境无法调用 `powershell.exe`）。

#### 经验固化

1. 项目内所有 `.ps1` 必须保存为 UTF-8 with BOM；
2. PowerShell 语法校验必须使用真实解释器 `powershell.exe`，不能只用 `pwsh`；
3. 中文提示若紧邻引号，优先在引号前补一个 ASCII 空格。

---

### 变更三：新增 IIS 与 Windows / RDP 日志类型

对应 `PROGRESS.md`「当前差距评估」第 2 项：增加 IIS 等高价值解析器，并为 README §4.2 / §5 中已声明但未实现的两类日志补齐能力。

#### 需求依据

| 文档 | 要求 |
| --- | --- |
| `README.md` §4.2 自动日志识别 | 识别 SSH、Nginx、Apache、Windows Security、RDP、Firewall、WAF、Generic |
| `README.md` §5 日志类型 | Windows / RDP 需覆盖登录成功/失败、高频认证失败、RDP 暴力破解、异常账户与来源、失败后成功 |
| `README.md` §6 异常行为检测 | 规则 + 统计 + AI，不依赖纯 AI |
| `AGENTS.md` §33 添加新日志类型 | Parser → 测试日志 → Parser 测试 → Detector → Detector 测试 → 接入统一模型 → 接入前端 |

#### 文件变更

| 文件 | 类型 | 说明 |
| --- | --- | --- |
| `backend/app/services/parser.py` | 修改（112 → 约 330 行） | 新增 IIS 与 Windows/RDP 解析；`detect_log_type` 扩展；原逐行解析逻辑抽为 `_parse_generic_lines` |
| `backend/app/services/rules.py` | 修改 | 新增 `rdp.bruteforce`、`rdp.bruteforce.success`、`windows.privileged_logon`；`web.*` 规则 `log_types` 增加 `iis` |
| `backend/app/services/detector.py` | 修改 | 新增 `_detect_windows()`、`WINDOWS_LOGON_ACTIONS`，`detect_events` 增加 Windows 分支 |
| `backend/app/services/analyzer.py` | 修改 | `_build_recommendations` 增加 Windows / RDP 排查建议分支 |
| `backend/tests/test_analysis.py` | 新增 3 个测试 + 3 个数据构造器 | IIS 识别与 Web 规则、Windows/RDP 检测、阈值以下不告警 |
| `sample_logs/iis/iis-access.log` | 新增 | IIS W3C 示例（正常访问 + 敏感路径 + 路径遍历 + 24 次 404） |
| `sample_logs/windows/security-rdp.log` | 新增 | Windows Security 示例（12 次 4625 + 1 次 4624，登录类型 10） |
| `.env.example` | 修改 | 新增「检测规则阈值与开关」段（SSH / Web / RDP） |
| `README.md` | 修改 | 实现状态、§4.2 实现范围标注、§5 新增 IIS 小节与 Windows/RDP 实现说明、§6.2 新增检测说明、示例日志路径 |

前端未改动：日志类型筛选项与规则编号展示均为动态渲染，新类型自动出现。

#### 详细实现

**IIS（W3C 扩展日志）**

- 以 `#Fields:` 指令行确定列顺序，缺省时使用 IIS 默认字段序列；忽略 `#` 开头的注释行；
- 字段映射：`c-ip` → 源 IP，`s-ip` → 目的 IP，`date + time` → 时间，`cs-method` → 动作，`cs-uri-stem` 拼接 `cs-uri-query` → 路径，`cs-username` → 账户，`sc-status` → 状态码；
- `-` 与 `N/A` 归一化为空值，`DOMAIN\user` 归一化为 `user`；
- 复用既有 Web 规则，因此敏感路径、路径遍历、404 扫描对 IIS 直接生效。

**Windows Security / RDP**

- 支持事件查看器 / `wevtutil` 文本导出格式（事件头 + 空行 + 正文），按空行切块后把不含事件 ID 的块并入上一事件，保证正文不被丢弃；
- 仅 `4625` / `4624` 计入认证记录，其余事件 ID 跳过；
- 账户优先取「Account For Which Logon Failed」/「New Logon」段落，避免取到 Subject 段中的计算机账户 `WIN-SRV01$`；
- 登录类型 7 / 10 → `rdp_logon`，其余 → `logon`；兼容中文字段名；
- 时间字段兼容 `YYYY-MM-DD HH:MM:SS`、`YYYY/MM/DD HH:MM:SS`、`MM/DD/YYYY hh:mm:ss AM/PM` 等格式。

**新增规则**

| 规则 ID | 风险 | 阈值 / 窗口 | 环境变量 |
| --- | --- | --- | --- |
| `rdp.bruteforce` | medium | 10 次 / 300 秒 | `RDP_FAILURE_THRESHOLD`、`RDP_FAILURE_WINDOW_SECONDS` |
| `rdp.bruteforce.success` | high | 同上，成功后 30 分钟内 | 同上 |
| `windows.privileged_logon` | medium | — | `RULE_WINDOWS_PRIVILEGED_LOGON_ENABLED` |

规则总数 6 → 9，`GET /api/rules` 自动对外暴露。

#### 验证证据

| 项目 | 结果 |
| --- | --- |
| 后端测试 | `28 passed`（新增 3 个） |
| 端到端 HTTP（IIS） | `log_type=iis`、32 行解析 28 条记录、目的 IP `10.0.0.5`、404×24、敏感路径 ×3、路径遍历（high）、整体风险 high |
| 端到端 HTTP（Windows） | `log_type=windows_rdp`、13 条记录、失败 12 / 成功 1、`rdp_bruteforce_success`（high）、`windows.privileged_logon`、`status=4625` 过滤返回 12 条 |
| `GET /api/rules` | 9 条规则，`web.*` 的 `log_types` 含 `iis` |
| 前端（Chrome 无头 + Playwright） | 类型下拉自动出现 `iis`、`windows_rdp`；详情页指标 / 事件 / 规则编号正常；明细按 `4625` 过滤 12 条；控制台零报错 |

#### 遗留

- Firewall、WAF 与通用 JSON / CSV 事件解析器仍未实现（`README.md` §4.2 中已标注为规划）；
- 跨日志类型的轻量实体关联（同 IP / 同账户串联）与统一时间线尚未实现；
- 项目当前启动方式为 `启动关闭.txt` 中的双终端命令，历史 PowerShell 脚本已删除（见变更二）。

---

### 变更四：通用 JSON / CSV 事件解析与认证检测复用

对应 `PROGRESS.md`「当前差距评估」第 2 项剩余部分（IIS 已在变更三完成）。

#### 文件变更

| 文件 | 类型 | 说明 |
| --- | --- | --- |
| `backend/app/services/parser.py` | 修改（约 330 → 560 行） | 新增 JSON / CSV / NDJSON 解析、字段别名表、取值归一化；`detect_log_type` 支持完整文本判定 |
| `backend/app/services/detector.py` | 重构（约 500 → 531 行） | `_detect_ssh` / `_detect_windows` 合并为 `_detect_auth(records, profile)`；新增 `STRUCTURED_PROFILE` 与按 `log_type` 分派 |
| `backend/app/services/rules.py` | 修改 | 新增 `auth.bruteforce`、`auth.bruteforce.success`（规则 9 → 11） |
| `backend/app/services/analyzer.py` | 修改 | 增加通用结构化日志的排查建议分支 |
| `backend/tests/test_analysis.py` | 新增 5 个测试 + 3 个数据构造器 | JSON / NDJSON / 分号 CSV / 缩进 JSON 采样窗口 / 无结构文本回落 |
| `sample_logs/structured/vpn-events.json` | 新增 | 20 次失败 + 1 次成功，缩进 JSON（193 行） |
| `sample_logs/structured/bastion-auth.csv` | 新增 | 分号分隔 + 中文表头 |
| `README.md` | 修改 | §4.2 识别清单、§5 新增「通用 JSON / CSV 事件」小节、§6.3 新增检测说明、示例日志路径 |
| `.env.example` | 修改 | 增加 `AUTH_FAILURE_*` 与 `RULE_AUTH_*` |

#### 关键设计

1. **字段别名映射**：JSON / CSV 行对象经别名表映射到统一记录结构，键名大小写、下划线、中文均可识别；无需为每种导出格式单独写解析器。
2. **取值归一化**：结果值统一为 `success` / `failure`（覆盖中英文与安全设备常见措辞），动作 `signin` 系列归一为 `login`；归一化后直接复用既有认证规则。
3. **认证检测去重**：三种认证来源（SSH / Windows-RDP / 通用结构化）共用 `_detect_auth`，差异以 `AuthProfile` 数据描述，消除了两份几乎相同的聚合逻辑。
4. **按 `log_type` 分派**：结构化日志使用 `auth.*` 规则，避免 VPN / 堡垒机的认证失败被表述为「SSH 暴力破解」。

#### 验证证据

| 项目 | 结果 |
| --- | --- |
| 后端测试 | `33 passed`（既有 28 个全部保持通过，新增 5 个） |
| 端到端（`vpn-events.json`） | `log_type=json`、193 行 → 21 条记录、失败 20 / 成功 1、`auth_bruteforce_success`（high）、带时区时间戳保留、目的 IP 映射成功 |
| 端到端（`bastion-auth.csv`） | `log_type=csv`、22 行 → 21 条记录、同一规则命中 |
| `GET /api/rules` | 11 条规则，含 `auth.bruteforce`、`auth.bruteforce.success` |
| 前端 | 无需改动（类型选项与规则编号动态渲染） |

#### 修复

- 缩进格式 JSON 超过 `detect_log_type` 的 100 行采样窗口时被误判为 `generic`；改为 JSON 判定使用完整文本，并补回归测试。

#### 遗留

- Firewall、WAF 解析器仍未实现；
- 跨日志类型的轻量实体关联与统一时间线尚未实现。

---

## 2026-09-14 及更早

见 `PROGRESS.md` 的历史记录。
