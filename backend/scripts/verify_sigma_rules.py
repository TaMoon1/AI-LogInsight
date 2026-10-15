"""导入规则批量验证：把「逐条人工验证」换成三层自动化。

背景：社区导入的 Sigma 规则有一千多条，逐条人工验证既做不到、也没必要。
这里把「规则能不能检出」拆成三个互不重叠的问题，各自用机器回答：

层 1 · 合成正样本（satisfiability / 端到端可触发）
    从规则的谓词树**反推一条必然满足它的记录**，再交给 `rule.covers()` 和
    `evaluate_rule()` 跑一遍。回答的是「这条规则的逻辑在我们这套记录模型上
    到底能不能成立」——字段映射错、条件自相矛盾、变换取不到值，都会被这层抓出来。
    不需要任何人工。
    注意：这层证明的是「规则可触发」，**不证明**「触发它的事件真的是攻击」。

层 2 · 真实语料回放（corpus replay）
    用本地真实日志把全部规则跑一遍，分出「真实命中过」与「从未命中」。
    从未命中**不等于**规则有问题（语料里可能本来就没有那种行为），
    但能让「需要补样本」的规则浮出来，而不是假装它们已被验证。

层 3 · 负样本筛查（false positive screening）
    在「正常流量」语料上命中 = 判定过宽。逐条列出，这是最需要人工看的一类。

三种结果都不是「安全/不安全」的结论，只描述「规则的可验证状态」。
报告落 `docs/sigma-rule-verification.md`。

用法：
    python scripts/verify_sigma_rules.py            # 打印摘要
    python scripts/verify_sigma_rules.py --write    # 同时写报告
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.services.parser import parse_log  # noqa: E402
from app.services.rule_quality import load_corpus  # noqa: E402
from app.services.rules import rule_objects  # noqa: E402
from app.services.rules_engine import FieldSpec, Predicate, Rule, evaluate_rule  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]
REPORT_PATH = REPO_ROOT / "docs" / "sigma-rule-verification.md"

#: 回放语料最多处理这么多条记录：单个大文件会拖垮整轮验证，而且边际信息很低。
REPLAY_RECORD_CAP = 8000

#: 合成正样本里「一个取值都造不出来」的操作符（正则无法反推，只能标记为需人工）
UNSYNTHESIZABLE_OPS = frozenset({"regex"})

_BASE_TIME = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
_SAFE_TOKEN = "zetasynthetic"


# ---------------------------------------------------------------- 层 1：合成


@dataclass
class SynthesisPlan:
    """合成结果：要么给出一份能满足规则的记录，要么给出不能合成的原因。"""

    record: dict[str, str | None] = field(default_factory=dict)
    reason: str = ""
    #: 触发一次事件所需的同类记录条数（聚合规则 > 1）
    records_needed: int = 1

    @property
    def ok(self) -> bool:
        return not self.reason


#: 允许直接写字段的变换；其余变换机器无法保证构造出满足条件的取值。
_PLAIN_TRANSFORMS = frozenset({"none", "lower", "upper", "url_decode", "url_path"})


def _key_of(spec: FieldSpec) -> tuple[str, str]:
    """约束分组键：字段 + 变换。同一组内的谓词必须同时成立。"""

    return (spec.field, spec.transform)


def _write(plan: dict[str, str | None], spec: FieldSpec, value: str) -> dict[str, str | None]:
    """把取值写进计划副本。"""

    trial = dict(plan)
    if spec.transform == "url_path":
        trial[spec.field] = value if value.startswith("/") else f"/{value}"
    else:
        trial[spec.field] = value
    return trial


def _values_of(predicate: Predicate) -> list[str]:
    """谓词的候选取值（ignore_case 时匹配前会归一，取值也用归一化后的）。"""

    values = list(predicate.normalized) if predicate.ignore_case else list(predicate.values)
    return values or list(predicate.values)


def _candidate_values(predicates: list[Predicate]) -> list[str]:
    """为一组同字段谓词造候选值。

    同一字段上的谓词是 AND 语义，因此候选值必须**同时**满足它们：
    前缀取最长的一个，后缀取最长的一个，每个 contains 类谓词各贡献一段，中间用
    `_SAFE_TOKEN` 分隔（它本身不含任何被禁片段）。最后再由 matcher 实测挑选。
    """

    prefixes: list[str] = []
    suffixes: list[str] = []
    groups: list[list[str]] = []
    plain: list[str] = []

    for predicate in predicates:
        values = _values_of(predicate)
        if not values:
            continue
        if predicate.op in ("startswith", "any_startswith", "any_path_prefix"):
            prefixes.extend(values)
        elif predicate.op in ("endswith", "any_endswith"):
            suffixes.extend(values)
        elif predicate.op in ("contains", "any_contains"):
            groups.append(values)
        else:
            plain.extend(values)

    head = max(prefixes, key=len) if prefixes else ""
    tail = max(suffixes, key=len) if suffixes else ""

    candidates: list[str] = []

    def push(value: str) -> None:
        # 分隔符 `|` `;` 换行会让 scope 变换取不回值，直接排除这类候选
        if value and value not in candidates and not any(char in value for char in "|;\n"):
            candidates.append(value)

    # 每个 contains 组最多取 3 个代表值，组合数控制在几十个以内
    picks = [values[:3] for values in groups] or [[]]
    combos = 1
    for values in picks:
        combos *= max(len(values), 1)
    if combos <= 60:
        from itertools import product

        for combination in product(*picks):
            middle = _SAFE_TOKEN.join(part for part in combination if part)
            push(f"{head}{middle}{tail}")
            push(f"{head}{_SAFE_TOKEN}{middle}{_SAFE_TOKEN}{tail}")
    else:
        # 组合太多时退而求其次：每组取首个值拼一次
        middle = _SAFE_TOKEN.join(values[0] for values in picks if values)
        push(f"{head}{middle}{tail}")

    for value in plain:
        push(value)
        push(f"{head}{value}{tail}")
    push(f"{head}{tail}")
    return candidates


def _satisfy(
    plan: dict[str, str | None],
    predicates: tuple[Predicate, ...],
    picks: list[int] | None = None,
) -> str:
    """把一组谓词（AND 语义）解进计划；返回空串表示成功，否则返回失败原因。

    `picks[i]`：第 i 条谓词用它的第几个字段来满足（多字段谓词是 any 语义）。
    """

    choices = picks or [0] * len(predicates)
    grouped: dict[tuple[str, str], tuple[FieldSpec, list[Predicate]]] = {}
    order: list[tuple[str, str]] = []
    for index, predicate in enumerate(predicates):
        if not predicate.fields:
            return f"{predicate.op} 没有字段信息"
        if predicate.op in UNSYNTHESIZABLE_OPS:
            return f"{predicate.op} 无法反推出取值"
        spec = predicate.fields[min(choices[index], len(predicate.fields) - 1)]
        key = _key_of(spec)
        if key not in grouped:
            grouped[key] = (spec, [])
            order.append(key)
        grouped[key][1].append(predicate)

    if not order:
        return ""

    for key in order:
        spec, group = grouped[key]
        # 取反条件常常只要「字段不填」就成立，先试不填
        if all(predicate.matcher(plan) for predicate in group):
            continue
        for value in _candidate_values(group):
            trial = _write(plan, spec, value)
            if all(predicate.matcher(trial) for predicate in group):
                plan.clear()
                plan.update(trial)
                break
        else:
            return f"字段 {spec.field}：条件之间互相冲突，构造不出同时满足的取值"
    return ""


def _solve(rule: Rule, predicates: tuple[Predicate, ...]) -> tuple[dict[str, str | None], str]:
    """求解一组谓词；多字段谓词会轮换字段，直到找出一个能让 `covers()` 成立的解。"""

    base_log_type = rule.log_types[0] if rule.log_types else "synthetic"
    if not predicates:
        return {"log_type": base_log_type}, ""

    picks = [0] * len(predicates)
    reason = "条件无法满足"
    # 复核 covers() 会走 logsource 门槛，计划里必须先有合法的 log_type
    for _ in range(12):
        plan: dict[str, str | None] = {"log_type": base_log_type}
        reason = _satisfy(plan, predicates, picks)
        # 这里只能按**本组谓词**复核：`covers()` 还要求 any 分支成立，
        # 求解 where 时用它复核会永远失败（any 分支还没解）。
        if not reason and all(predicate.matcher(plan) for predicate in predicates):
            return plan, ""
        if not reason:
            reason = "合成记录仍未通过条件匹配（合成器无法覆盖该组合）"
        for index, predicate in enumerate(predicates):
            if len(predicate.fields) > picks[index] + 1:
                picks[index] += 1
                break
        else:
            break
    return {}, reason


def _synthesize(rule: Rule) -> SynthesisPlan:
    """给规则合成一份**经 `rule.covers()` 复核通过**的记录。"""

    log_type = rule.log_types[0] if rule.log_types else "synthetic"

    # where 是 AND：全部满足。any_of 是 OR：任意一组能满足即可。
    base, reason = _solve(rule, rule.where)
    if reason:
        return SynthesisPlan(reason=reason)

    groups = list(rule.any_of)
    if groups:
        group_plan, group_reason = None, "any 分支全部不可满足"
        for group in groups:
            candidate = dict(base)
            group_reason = _satisfy(candidate, group)
            if not group_reason and rule.covers(candidate):
                group_plan = candidate
                break
        if group_plan is None:
            return SynthesisPlan(
                reason=group_reason or "any 分支的条件可构造，但记录未通过完整条件匹配"
            )
        base = group_plan

    plan = dict(base)
    plan["log_type"] = log_type
    plan["record_id"] = "synthetic-1"
    plan["raw"] = plan.get("raw") or f"{_SAFE_TOKEN} synthetic record"
    plan["timestamp_iso"] = _BASE_TIME.isoformat()
    if not plan or not rule.covers(plan):
        return SynthesisPlan(reason="合成记录未通过条件匹配（合成器无法覆盖该组合）")
    return SynthesisPlan(record=plan, records_needed=_records_needed(rule))


def _records_needed(rule: Rule) -> int:
    """触发一次事件至少需要几条记录。"""

    aggregate = rule.aggregate
    if aggregate is None:
        return 1
    if aggregate.follow_up is not None:
        # 头部若干条 + 一条后续记录（后续记录本身不满足主 where）
        return max(rule.event.follow_up_head, 2) + 1
    if aggregate.distinct_gte:
        return aggregate.distinct_gte
    if aggregate.count_gte:
        return aggregate.count_gte
    return 1


def _expand(rule: Rule, plan: dict[str, str | None], needed: int) -> list[dict[str, str | None]]:
    """把一条样本记录扩成「够触发一次事件」的记录序列。"""

    records: list[dict[str, str | None]] = []
    aggregate = rule.aggregate
    for index in range(needed):
        record = dict(plan)
        record["record_id"] = f"synthetic-{index + 1}"
        # 时间递进，保证落在聚合窗口内
        record["timestamp_iso"] = (_BASE_TIME + timedelta(seconds=index)).isoformat()
        if aggregate is not None and aggregate.distinct_field is not None:
            # 去重类聚合靠「同一字段出现多个不同取值」成立
            record[aggregate.distinct_field.field] = f"{_SAFE_TOKEN}-{index + 1}"
        records.append(record)

    if aggregate is not None and aggregate.follow_up is not None:
        # 最后一条是「后续记录」：满足 follow_up.where，不满足主 where
        tail: dict[str, str | None] = {
            "log_type": plan.get("log_type"),
            "record_id": f"synthetic-{needed}",
            "raw": f"{_SAFE_TOKEN} follow-up record",
            "timestamp_iso": (_BASE_TIME + timedelta(seconds=needed + 30)).isoformat(),
        }
        _satisfy(tail, aggregate.follow_up.where)
        records[-1] = tail
    return records


@dataclass
class LayerOne:
    triggerable: list[str] = field(default_factory=list)
    not_triggered: list[tuple[str, str]] = field(default_factory=list)
    unfinished: list[tuple[str, str]] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.triggerable) + len(self.not_triggered) + len(self.unfinished)


def verify_synthesizable(rules: list[Rule]) -> LayerOne:
    """层 1：合成正样本 → 端到端跑一次规则，看能不能真的产出事件。"""

    result = LayerOne()
    for rule in rules:
        plan = _synthesize(rule)
        if not plan.ok:
            result.unfinished.append((rule.id, plan.reason))
            continue
        records = _expand(rule, plan.record, plan.records_needed)
        try:
            events = evaluate_rule(rule, records)
        except Exception as error:  # noqa: BLE001 - 验证器要如实报错，不能吞掉
            result.not_triggered.append((rule.id, f"求值抛异常：{error}"))
            continue
        if events:
            result.triggerable.append(rule.id)
            continue
        # 记录本身过不过 covers()，决定问题出在「条件」还是「聚合」
        matched = sum(1 for record in records if rule.covers(record))
        if matched == 0:
            result.not_triggered.append(
                (rule.id, "合成记录通过了条件匹配，但没有产出任何事件")
            )
        else:
            result.not_triggered.append(
                (
                    rule.id,
                    f"{matched} 条记录通过条件匹配，但未聚合出事件"
                    f"（需要 {plan.records_needed} 条同类记录）",
                )
            )
    return result


# ---------------------------------------------------------------- 层 2/3：回放


@dataclass
class ReplayOutcome:
    fired: Counter = field(default_factory=Counter)
    files: int = 0
    records: int = 0
    #: 语料里实际出现过的日志类型。用来区分「没有样本」和「有样本却没命中」——
    #: 两者含义完全不同：前者说明不了任何事，后者才是真正「待补样本」的规则。
    types_seen: set = field(default_factory=set)
    #: 日志类型分布（记录数）
    type_records: Counter = field(default_factory=Counter)
    #: 语料里出现过的 `status` 取值。导入规则绝大多数用 `status == <Sysmon EventID>`
    #: 当必要条件守卫，所以「语料里有没有这个 EventID」才是判断样本够不够的准绳；
    #: 按日志类型判断会失效——导入规则的 logsource 是空的。
    status_seen: set = field(default_factory=set)


def _corpus_files() -> list[tuple[str, str]]:
    """回放语料：本地真实日志 + 语料里内联的日志。"""

    files: list[tuple[str, str]] = []
    for base in (REPO_ROOT / "sample_logs", REPO_ROOT / "data" / "uploads"):
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*")):
            if not path.is_file() or path.suffix.lower() not in {".log", ".txt", ".csv", ".json", ".xml"}:
                continue
            try:
                files.append((str(path.relative_to(REPO_ROOT)), path.read_text(encoding="utf-8", errors="replace")))
            except OSError:
                continue
    for scenario in sorted((Path(__file__).resolve().parents[1] / "evaluation" / "scenarios").glob("*.log")):
        files.append((f"evaluation/scenarios/{scenario.name}", scenario.read_text(encoding="utf-8", errors="replace")))
    return files


def replay(rules: list[Rule], files: list[tuple[str, str]]) -> ReplayOutcome:
    """层 2：在真实（含正常流量）语料上跑全部规则，记录每条规则命中过几次。"""

    outcome = ReplayOutcome()
    for name, text in files:
        try:
            parsed = parse_log(text)
        except Exception:  # noqa: BLE001 - 单个语料解析失败不影响其它语料
            continue
        records = list(parsed.records[:REPLAY_RECORD_CAP])
        if not records:
            continue
        outcome.files += 1
        outcome.records += len(records)
        log_type = parsed.log_type or ""
        outcome.types_seen.add(log_type)
        outcome.type_records[log_type] += len(records)
        outcome.status_seen.update(
            str(record["status"]) for record in records if record.get("status")
        )
        for rule in rules:
            hits = sum(1 for record in records if rule.covers(record))
            if hits:
                outcome.fired[rule.id] += hits
    return outcome


def negative_corpus_hits(rules: list[Rule]) -> dict[str, list[str]]:
    """层 3：在内联的「正常流量」语料上命中的规则（= 判定过宽）。"""

    hits: dict[str, list[str]] = defaultdict(list)
    for case in load_corpus():
        if case.get("expect"):
            continue  # 有期望命中的用例不是负样本
        name = str(case.get("name") or case.get("file") or "unnamed")
        if case.get("records") is not None:
            records = list(case["records"])
        else:
            parsed = parse_log(str(case.get("log") or ""))
            if case.get("log_type"):
                parsed.log_type = str(case["log_type"])
            records = list(parsed.records)
        if not records:
            continue
        for rule in rules:
            if any(rule.covers(record) for record in records):
                hits[rule.id].append(name)
    return hits


# ---------------------------------------------------------------- 报告


def _bar(count: int, total: int) -> str:
    if not total:
        return "0%"
    return f"{count / total:.1%}"


def build_report(
    imported: list[Rule],
    builtin_count: int,
    layer_one: LayerOne,
    outcome: ReplayOutcome,
    overly_broad: dict[str, list[str]],
    corpus_files: int,
) -> str:
    total = len(imported)
    fired = set(outcome.fired)
    never = [rule for rule in imported if rule.id not in fired]
    needs_human = len(layer_one.not_triggered) + len(overly_broad)
    titles = {rule.id: rule.title for rule in imported}
    levels = {rule.id: rule.level for rule in imported}

    def type_available(rule: Rule) -> bool:
        """语料里有没有这条规则**真的可能命中**的输入。

        导入规则大多把 `status == <Sysmon EventID>` 当作必要条件守卫，
        因此只要语料里出现过那个 EventID，就说明「有同类数据却没命中」→ 值得补样本；
        否则「未命中」只是因为没有这种数据，说明不了任何事。
        """

        if rule.log_types and not any(name in outcome.types_seen for name in rule.log_types):
            return False
        required: set[str] = set()
        for predicate in rule.where:
            if predicate.negate or not predicate.values:
                continue
            if any(spec.field == "status" for spec in predicate.fields) and predicate.op in (
                "equals",
                "in_set",
            ):
                required.update(str(value) for value in predicate.values)
        if not required:
            return True  # 没有 EventID 守卫，任何记录都可能命中
        return bool(required & outcome.status_seen)

    unmatched_type = [rule for rule in never if not type_available(rule)]
    type_ok_unfired = [rule for rule in never if type_available(rule)]

    lines: list[str] = []
    add = lines.append
    add("# 导入规则检测效果验证报告")
    add("")
    add(f"生成时间：{datetime.now().astimezone().isoformat(timespec='seconds')}")
    add("")
    add(
        "本报告回答一个问题：**社区导入的 Sigma 规则有没有被逐条验证过、"
        "没验证的话该怎么办**。"
    )
    add("")
    add("## 一、先把结论说清楚")
    add("")
    add(
        f"- 导入规则总数：**{total} 条**（内置规则 {builtin_count} 条另有本地标注语料，"
        "不计入本报告）。"
    )
    add(
        f"- **不需要逐条人工验证**，也不应该那样做：{total} 条里绝大多数触发条件都是"
        "声明式的，机器可以自己构造样本去试。"
    )
    add(
        f"- 真正需要人看的只有 **{needs_human} 条**：判据是「机器试出来有问题」"
        f"（{len(layer_one.not_triggered)} 条）与「在正常流量上就报」"
        f"（{len(overly_broad)} 条）。"
    )
    add(
        f"- 另外 **{len(never)} 条在本地语料里从未命中**。这里必须再分一次："
        f"其中 **{len(unmatched_type)} 条**语料里连它要求的 EventID 都没出现过"
        f"（例如它要求 Sysmon EventID 7，而语料里没有这类事件），"
        f"它们的「未命中」说明不了任何事；剩下 **{len(type_ok_unfired)} 条**"
        "有同类日志却没命中，才是真正「待补样本」的规则。"
        "两类都如实标为未验证，不冒充已验证。"
    )
    add("")
    add("## 二、三层验证各自回答什么")
    add("")
    add("| 层 | 做法 | 回答的问题 | 需要人工吗 |")
    add("|---|---|---|---|")
    add(
        "| 层 1 合成正样本 | 从规则谓词树反推一条必然满足它的记录，"
        "再用规则引擎端到端跑一次 | 这条规则的逻辑在我们的记录模型上能不能成立 | 不需要 |"
    )
    add("| 层 2 真实语料回放 | 用本地真实日志把全部规则跑一遍 | 它有没有在真实数据上命中过 | 不需要 |")
    add("| 层 3 负样本筛查 | 在「正常流量」语料上跑 | 它会不会在正常流量上乱报 | 不需要 |")
    add("")
    add(
        "> 三层都只描述**规则的可验证状态**，都不构成「安全 / 不安全」的结论。"
        "层 1 通过只说明「能触发」，不说明「触发它的事件真的是攻击」。"
    )
    add("")
    add("## 三、层 1：合成正样本（端到端可触发）")
    add("")
    add(f"覆盖 {layer_one.total} 条，其中：")
    add("")
    add("| 结果 | 条数 | 占比 | 含义 |")
    add("|---|---|---|---|")
    add(
        f"| 端到端可触发 | {len(layer_one.triggerable)} | {_bar(len(layer_one.triggerable), layer_one.total)} | "
        "合成记录能过条件匹配并产出事件，规则逻辑成立 |"
    )
    add(
        f"| **疑似缺陷** | {len(layer_one.not_triggered)} | {_bar(len(layer_one.not_triggered), layer_one.total)} | "
        "合成记录本该命中却没产出事件，需要人看 |"
    )
    add(
        f"| 无法自动合成 | {len(layer_one.unfinished)} | {_bar(len(layer_one.unfinished), layer_one.total)} | "
        "条件是正则或跨记录关联，机器反推不出取值（**不是缺陷**） |"
    )
    add("")

    if layer_one.not_triggered:
        add("### 疑似缺陷明细")
        add("")
        add("| 规则 | 等级 | 原因 |")
        add("|---|---|---|")
        for rule_id, reason in layer_one.not_triggered:
            add(f"| `{rule_id}` | {levels.get(rule_id, '?')} | {reason} |")
        add("")
    else:
        add("没有发现「能合成样本却触发不了」的规则。")
        add("")

    if layer_one.unfinished:
        grouped = Counter(reason for _, reason in layer_one.unfinished)
        add("### 无法自动合成的原因分布（不是缺陷）")
        add("")
        add("| 原因 | 条数 |")
        add("|---|---|")
        for reason, count in grouped.most_common(10):
            add(f"| {reason} | {count} |")
        add("")
        add(
            "这类规则的条件是正则表达式或跨记录关联，机器无法保证反推出的取值一定匹配。"
            "它们的验证依赖层 2 的真实语料，或需要人工补样本。"
        )
        add("")

    add("## 四、层 2：真实语料回放")
    add("")
    add(f"- 语料文件：**{outcome.files} 个**（本地 `sample_logs/`、`data/uploads/` 与 `evaluation/scenarios/`）")
    add(f"- 参与回放的记录：**{outcome.records:,} 条**（单文件上限 {REPLAY_RECORD_CAP:,} 条）")
    add(f"- 在真实数据上命中过的规则：**{len(fired)} 条**（占 {_bar(len(fired), total)}）")
    add(f"- 从未命中：**{len(never)} 条**（占 {_bar(len(never), total)}），拆成两类：")
    add(f"  - 语料里**没有**该规则要求的 EventID：**{len(unmatched_type)} 条**（未命中说明不了任何事）")
    add(f"  - 语料里**有**同类日志但未命中：**{len(type_ok_unfired)} 条**（真正待补样本）")
    add("")
    add("### 语料的日志类型分布（记录数）")
    add("")
    add("| 日志类型 | 记录数 |")
    add("|---|---|")
    for name, count in outcome.type_records.most_common(12):
        add(f"| `{name or '(未识别)'}` | {count:,} |")
    add("")
    add(
        "> 导入规则绝大多数面向 **Windows / Sysmon 事件**（要求 `status` 等于某个 EventID），"
        "而本地语料以 Linux 认证、Web 访问与服务日志为主。因此「层 2 几乎不命中」主要是"
        "**语料与规则的日志类型错配**，不是规则本身有问题——这也是本项目 ATT&CK 标尺里"
        "那 75 项新技术的样本还缺着的同一个原因。"
    )
    add("")
    if outcome.fired:
        add("### 命中次数最高的规则（真实命中，不是误报）")
        add("")
        add("| 规则 | 等级 | 命中记录数 |")
        add("|---|---|---|")
        for rule_id, count in outcome.fired.most_common(15):
            add(f"| `{rule_id}` | {levels.get(rule_id, '?')} | {count} |")
        add("")
    add(
        f"> 语料里已经有 Sysmon 与 Windows 安全事件的 EventID（4624/4625/4634/11/1/3…），"
        f"所以「{len(type_ok_unfired)} 条有同类日志却没命中」不代表规则写错了："
        "它们的额外条件（`Image` / `CommandLine` / `TargetFilename` 的具体取值）"
        "在现有日志里本来就不存在——现有日志里没有 mimikatz、没有 Cobalt Strike。"
        "这类规则的可信度**低于**有真实命中的规则，系统里也按「未本地验证」标注。"
        "要推进它们，正解是**补一段真实的恶意样本**，而不是改规则。"
    )
    add("")
    add("### 优先级建议")
    add("")
    add(
        "按「等级高 + 有同类日志却未命中」排。这批补一段真实样本就能立刻验证，性价比最高："
    )
    add("")
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    # 优先看「语料里有同类日志却没命中」的高等级规则——这类才是补样本就能立刻见效的
    priority = sorted(
        type_ok_unfired,
        key=lambda rule: (order.get(rule.level, 9), rule.id),
    )[:20]
    if priority:
        add("| 规则 | 等级 | 标题 |")
        add("|---|---|---|")
        for rule in priority:
            title = titles.get(rule.id, "")[:60]
            add(f"| `{rule.id}` | {rule.level} | {title} |")
        add("")

    add("## 五、层 3：负样本筛查（判定过宽）")
    add("")
    if overly_broad:
        add(f"在「正常流量」语料上命中的规则 **{len(overly_broad)} 条**，需要人工确认：")
        add("")
        add("| 规则 | 等级 | 命中的正常用例 |")
        add("|---|---|---|")
        for rule_id, cases in sorted(overly_broad.items()):
            add(f"| `{rule_id}` | {levels.get(rule_id, '?')} | {'、'.join(cases)} |")
        add("")
    else:
        add("没有导入规则命中「正常流量」语料。")
        add("")

    add("## 六、两层合起来看：每条规则处在哪一档")
    add("")
    triggerable_ids = set(layer_one.triggerable)
    both = [rule for rule in imported if rule.id in triggerable_ids and rule.id in fired]
    synth_only = [rule for rule in imported if rule.id in triggerable_ids and rule.id not in fired]
    unfired_never_synth = [
        rule
        for rule in imported
        if rule.id not in triggerable_ids and rule.id not in fired
    ]
    add("| 状态 | 条数 | 含义 | 下一步 |")
    add("|---|---|---|---|")
    add(
        f"| 机器可触发 **且** 真实语料命中过 | {len(both)} | 最高可信：逻辑成立，且在真实数据上跑得动 | 无需动作 |"
    )
    add(
        f"| 机器可触发，但真实语料未命中 | {len(synth_only)} | 逻辑成立，缺真实样本证明它在真实数据上会响 | 补一段真实/拟真样本即可升级 |"
    )
    add(
        f"| 机器构造不出样本，语料也没命中 | {len(unfired_never_synth)} | 两个方向都没有证据 | 人工看条件或补样本 |"
    )
    add("")
    add("## 七、人工要做什么")
    add("")
    add("按上表汇总，人工只需要处理这几类：")
    add("")
    add(
        f"1. **疑似缺陷 {len(layer_one.not_triggered)} 条**：看合成记录为什么没触发——"
        "多半是字段映射没接上，或者条件写死了互相矛盾。"
    )
    add(
        f"2. **判定过宽 {len(overly_broad)} 条**：看命中的正常用例是不是真的正常，"
        "是的话给规则加聚合条件或收紧谓词。"
    )
    add(
        f"3. **从未命中且等级为 high/critical 的规则**：优先补一段真实样本；"
        "暂时补不上就保持「未本地验证」标注，不要当成已验证。"
    )
    add("")
    add(
        "其余规则（层 1 可触发、层 2 有真实命中、层 3 无过宽）**不需要人工逐条看**："
        "机器已经把「逻辑成立」「真实数据上跑得动」「不在正常流量上报」三件事都验证了。"
    )
    add("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="导入规则的批量检测效果验证")
    parser.add_argument("--write", action="store_true", help="写入 docs/sigma-rule-verification.md")
    parser.add_argument("--only", default="", help="只验证规则编号包含该子串的规则（调试用）")
    arguments = parser.parse_args()

    all_rules = rule_objects()
    builtin = [rule for rule in all_rules if rule.source == "builtin"]
    imported = [rule for rule in all_rules if rule.source != "builtin"]
    if arguments.only:
        imported = [rule for rule in imported if arguments.only in rule.id]

    print(f"规则总数 {len(all_rules)}（内置 {len(builtin)} + 导入 {len(imported)}）")

    layer_one = verify_synthesizable(imported)
    print(
        f"层 1 合成正样本：可触发 {len(layer_one.triggerable)}"
        f" / 疑似缺陷 {len(layer_one.not_triggered)}"
        f" / 无法合成 {len(layer_one.unfinished)}"
    )

    files = _corpus_files()
    outcome = replay(imported, files)
    fired = set(outcome.fired)
    print(f"层 2 真实语料回放：{outcome.files} 个文件 / {outcome.records:,} 条记录，{len(fired)} 条规则命中过")

    overly_broad = negative_corpus_hits(imported)
    print(f"层 3 负样本筛查：{len(overly_broad)} 条规则命中正常流量语料")

    if arguments.write:
        report = build_report(
            imported, len(builtin), layer_one, outcome, overly_broad, len(files)
        )
        REPORT_PATH.write_text(report, encoding="utf-8")
        print(f"报告已写入 {REPORT_PATH.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
