"""Sigma 规则导入：把社区 Sigma 规则转换成本项目可执行的声明式规则。

转换链路：

```text
Sigma YAML
  → logsource 映射（product/category/service → 本项目日志类型）
  → detection 条件解析（and / or / not / 括号 / 1 of / all of）
  → 字段映射 pipeline（Sigma 字段 → 本项目记录字段 + 变换）
  → 修饰符映射（contains / startswith / endswith / re / all）
  → DNF 归一化（OR of ANDs）→ 本项目 where / any 结构
```

原则：

- **不猜测**：字段或修饰符无法映射时整条规则跳过，并给出可读原因，不做「尽力而为」的近似。
- **语义保守**：条件表达式按布尔代数严格转换（含 De Morgan 展开），转换后语义与 Sigma 一致。
- **可追溯**：导入规则 id 为 `sigma.<原始 uuid>`，标签保留 ATT&CK，来源标注为 `sigma`。
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

import yaml

from ..models import SigmaConvertedRule, SigmaImportReport, SigmaSkippedRule
from ..runtime_paths import backend_root
from .rules_engine import FieldSpec, Predicate

MAX_DNF_GROUPS = 64
MAX_PREDICATES_PER_GROUP = 64

# Sigma 字段 → （本项目记录字段, 变换）。语义等价但名称不同的走这张表；
# 表里没有的字段**原样直通**——Sigma 的 Windows 规则用的就是 EVTX 标准字段名
# （`OriginalFileName` / `ParentCommandLine` / `Details` …），解析器已按标准名
# 把它们落进记录（见 `evtx._event_data`），这里不需要再登记一遍。
FIELD_MAP: dict[str, tuple[str, str]] = {
    "cs-method": ("action", "upper"),
    "cs-uri-query": ("url", "url_decode"),
    "cs-uri-stem": ("url", "url_decode"),
    "cs-uri": ("url", "url_decode"),
    "cs-user-agent": ("raw", "lower"),
    "sc-status": ("status", "none"),
    "uri": ("url", "url_decode"),
    "url": ("url", "url_decode"),
    "request_url": ("url", "url_decode"),
    "request": ("url", "url_decode"),
    "status": ("status", "none"),
    "status_code": ("status", "none"),
    "user_agent": ("raw", "lower"),
    "eventid": ("status", "none"),
    "sourceaddress": ("source_ip", "none"),
    "sourceip": ("source_ip", "none"),
    "src_ip": ("source_ip", "none"),
    "client_ip": ("source_ip", "none"),
    "ipaddress": ("source_ip", "none"),
    "destaddress": ("destination_ip", "none"),
    "destinationip": ("destination_ip", "none"),
    "dst_ip": ("destination_ip", "none"),
    "server_ip": ("destination_ip", "none"),
    "destport": ("destination_port", "none"),
    "destinationport": ("destination_port", "none"),
    "targetusername": ("username", "lower"),
    "subjectusername": ("username", "lower"),
    "user": ("username", "lower"),
    "accountname": ("username", "lower"),
    "username": ("username", "lower"),
    "result": ("result", "lower"),
    "action": ("action", "lower"),
    "message": ("raw", "lower"),
    # Sigma 用 `Provider_Name` 指事件头里的提供者，EVTX 的标准元素名是 `Provider`。
    "provider_name": ("provider", "none"),
    "image": ("process_image", "none"),
    "commandline": ("command_line", "none"),
    "parentimage": ("parent_image", "none"),
    "processid": ("process_id", "none"),
    "parentprocessid": ("parent_process_id", "none"),
    "targetfilename": ("target_filename", "none"),
    "targetobject": ("registry_key", "none"),
    "queryname": ("query_name", "none"),
    "queryresults": ("query_results", "none"),
    "hashes": ("hashes", "none"),
    "hash": ("hashes", "none"),
    "logontype": ("login_type", "none"),
    "servicename": ("service_name", "none"),
    "param1": ("service_name", "none"),
}

MODIFIER_OPS: dict[str, str] = {
    "contains": "contains",
    "startswith": "startswith",
    "endswith": "endswith",
    "re": "regex",
}
# 值侧变换修饰符：不改匹配方式，只把取值展开成等价的多值集合
VALUE_TRANSFORMS = {"windash", "base64offset"}
UNSUPPORTED_MODIFIERS = {
    "base64",
    "cidr",
    "fieldref",
    "expand",
    "lt",
    "gt",
    "lte",
    "gte",
    "utf16",
    "wide",
    "utf16le",
    "utf16be",
    "cased",
    "exists",
}

# Sigma `windash`：值里的 `-` 可被替换为 5 种变体（sigmahq.io modifiers 规范），
# 纯值侧展开，多值谓词（any_contains / in_set）即可表达
WINDASH_VARIANTS = ("-", "/", "–", "—", "―")

#: Sysmon 行为类（process_creation 等）的结构性排除名单：这些日志类型**不可能**携带
#: 进程创建 / 注册表 / 网络连接事件，扫它们纯属浪费（2026-10-14 实测：45 条无类型约束的
#: 无键规则占规则耗时 58%，最大单条 1375ms）。`xml` 与 `generic` 不排除：
#: Sysmon 的通用 XML 导出、无法识别格式的文本是关键词规则（扫 raw）的合理兜底场景。
BEHAVIOR_EXCLUDES = (
    "json",
    "csv",
    "mysql",
    "postgresql",
    "mongodb",
    "redis",
    "sqlserver",
    "oracle",
    "nginx_apache",
    "iis",
    "ssh",
    "syslog",
    "firewall_waf",
)

#: webserver 类的结构性排除：非 Web 类型不可能产生带 url 字段的访问记录
WEBSERVER_EXCLUDES = (
    "ssh",
    "syslog",
    "firewall_waf",
    "mongodb",
    "mysql",
    "postgresql",
    "redis",
    "sqlserver",
    "oracle",
    "windows_rdp",
    "windows_evtx",
    "windows_event",
    "windows_auth_export",
    "unsupported_xlsx",
)

LOGSOURCE_MAP: dict[str, dict[str, object]] = {
    "webserver": {
        "log_types": (),
        "exclude_log_types": WEBSERVER_EXCLUDES,
        "display_log_types": ("nginx_apache", "iis", "json", "csv"),
    },
    "windows-security": {
        "log_types": ("windows_rdp", "windows_evtx"),
        "display_log_types": ("windows_rdp", "windows_evtx"),
    },
    "authentication": {
        "exclude_log_types": ("json", "csv"),
        "display_log_types": ("ssh", "windows_rdp", "windows_evtx"),
    },
    # Sysmon 行为类：用黑名单而不是白名单，因为同一批行为字段在 EVTX 与「键值化导出」
    # 两种形态里分属不同 log_type（windows_evtx / windows_event），白名单会漏掉一种。
    "process_creation": {
        "exclude_log_types": BEHAVIOR_EXCLUDES,
        "display_log_types": ("windows_evtx", "windows_rdp"),
    },
    "file_event": {
        "exclude_log_types": BEHAVIOR_EXCLUDES,
        "display_log_types": ("windows_evtx", "windows_rdp"),
    },
    "registry_set": {
        "exclude_log_types": BEHAVIOR_EXCLUDES,
        "display_log_types": ("windows_evtx", "windows_rdp"),
    },
    "registry_event": {
        "exclude_log_types": BEHAVIOR_EXCLUDES,
        "display_log_types": ("windows_evtx", "windows_rdp"),
    },
    "dns_query": {
        "exclude_log_types": BEHAVIOR_EXCLUDES,
        "display_log_types": ("windows_evtx", "windows_rdp"),
    },
    "network_connection": {
        "exclude_log_types": BEHAVIOR_EXCLUDES,
        "display_log_types": ("windows_evtx", "windows_rdp"),
    },
}

# Windows 安全/系统通道（Sigma 的 windows/builtin）：本项目的 windows_evtx 已覆盖这些通道，
# 因此 service 为 security / system / application 时统一按同一组日志类型处理。
WINDOWS_SERVICES = ("security", "system", "application", "taskscheduler", "windefend")

LEVEL_MAP = {
    "informational": "info",
    "info": "info",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}


class ConversionError(Exception):
    """规则无法在保持语义的前提下转换。"""


@dataclass(frozen=True)
class SigmaRule:
    path: Path
    id: str
    title: str
    level: str
    tags: tuple[str, ...]
    document: dict[str, Any]


def slug(value: str) -> str:
    cleaned = re.sub(r"[^0-9a-zA-Z]+", "_", value).strip("_").lower()
    return cleaned[:48] or "rule"


# --------------------------------------------------------------------------- 条件解析


@dataclass(frozen=True)
class Node:
    kind: str
    name: str = ""
    names: tuple[str, ...] = ()
    children: tuple["Node", ...] = ()


TOKEN_PATTERN = re.compile(r"\(|\)|[^\s()]+")


def parse_condition(text: str) -> Node:
    tokens = TOKEN_PATTERN.findall(text)
    position = 0

    def peek() -> str | None:
        return tokens[position] if position < len(tokens) else None

    def take() -> str:
        nonlocal position
        if position >= len(tokens):
            raise ConversionError(f"条件表达式不完整：{text}")
        token = tokens[position]
        position += 1
        return token

    def parse_or() -> Node:
        node = parse_and()
        while peek() == "or":
            take()
            node = Node("or", children=(node, parse_and()))
        return node

    def parse_and() -> Node:
        node = parse_unary()
        while peek() == "and":
            take()
            node = Node("and", children=(node, parse_unary()))
        return node

    def parse_unary() -> Node:
        token = peek()
        if token == "not":
            take()
            return Node("not", children=(parse_unary(),))
        if token == "(":
            take()
            node = parse_or()
            if take() != ")":
                raise ConversionError(f"条件表达式括号不匹配：{text}")
            return node
        if token in {"1", "all"} and position + 1 < len(tokens) and tokens[position + 1] == "of":
            quantifier = take()
            take()
            return Node("quantifier", name=quantifier, names=(take(),))
        if token is not None and token.endswith("*"):
            take()
            return Node("quantifier", name="1", names=(token,))
        if token is None:
            raise ConversionError(f"条件表达式意外结束：{text}")
        return Node("selection", name=take())

    node = parse_or()
    if position != len(tokens):
        raise ConversionError(f"条件表达式存在多余内容：{text}")
    return node


def _negate(predicate: Predicate) -> Predicate:
    return replace(predicate, negate=not predicate.negate)


def _conjunction(groups: list[list[Predicate]]) -> list[list[Predicate]]:
    """AND 两个 DNF：逐个分组做笛卡尔积拼接。"""

    result: list[list[Predicate]] = [[]]
    for dnf in groups:
        combined: list[list[Predicate]] = []
        for left in result:
            for right in dnf:
                if len(left) + len(right) > MAX_PREDICATES_PER_GROUP:
                    raise ConversionError("条件展开后谓词过多，无法保持语义转换")
                combined.append(left + right)
        result = combined
        if len(result) > MAX_DNF_GROUPS:
            raise ConversionError("条件展开后分支过多，无法保持语义转换")
    return result


def to_dnf(
    node: Node, selections: dict[str, list[list[Predicate]]]
) -> list[list[Predicate]]:
    """把条件表达式转换为 DNF（OR of AND），并保持布尔语义。"""

    if node.kind == "selection":
        if node.name not in selections:
            raise ConversionError(f"条件引用了不存在的检测块：{node.name}")
        return selections[node.name]
    if node.kind == "quantifier":
        names = _resolve_quantifier(node, selections)
        if node.name == "all":
            groups: list[list[Predicate]] = [[]]
            for name in names:
                groups = _conjunction([groups, selections[name]])
            return groups
        merged: list[list[Predicate]] = []
        for name in names:
            merged.extend(selections[name])
        if len(merged) > MAX_DNF_GROUPS:
            raise ConversionError("条件展开后分支过多，无法保持语义转换")
        return merged
    if node.kind == "not":
        return _negate_dnf(to_dnf(node.children[0], selections))
    if node.kind == "and":
        groups = to_dnf(node.children[0], selections)
        for child in node.children[1:]:
            groups = _conjunction([groups, to_dnf(child, selections)])
        return groups
    if node.kind == "or":
        result: list[list[Predicate]] = []
        for child in node.children:
            result.extend(to_dnf(child, selections))
        if len(result) > MAX_DNF_GROUPS:
            raise ConversionError("条件展开后分支过多，无法保持语义转换")
        return result
    raise ConversionError(f"未知条件节点：{node.kind}")


def _resolve_quantifier(node: Node, selections: dict[str, list[list[Predicate]]]) -> list[str]:
    pattern = node.names[0]
    if pattern in {"them", "all"}:
        return list(selections)
    if pattern.endswith("*"):
        prefix = pattern[:-1]
        matched = [name for name in selections if name.startswith(prefix)]
    else:
        matched = [name for name in selections if name == pattern]
    if not matched:
        raise ConversionError(f"条件引用的检测块不存在：{pattern}")
    return matched


def _negate_dnf(groups: list[list[Predicate]]) -> list[list[Predicate]]:
    """De Morgan 展开：NOT(OR of AND) = AND of OR of NOT。"""

    accumulator: list[list[Predicate]] = [[]]
    for group in groups:
        terms = [[_negate(predicate)] for predicate in group]
        if not terms:
            raise ConversionError("检测块为空，无法取反")
        combined: list[list[Predicate]] = []
        for left in accumulator:
            for term in terms:
                if len(left) + len(term) > MAX_PREDICATES_PER_GROUP:
                    raise ConversionError("取反后谓词过多，无法保持语义转换")
                combined.append(left + term)
        accumulator = combined
        if len(accumulator) > MAX_DNF_GROUPS:
            raise ConversionError("取反后分支过多，无法保持语义转换")
    return accumulator


# --------------------------------------------------------------------------- 字段与修饰符映射


def _split_key(key: str) -> tuple[str, list[str]]:
    parts = key.split("|")
    return parts[0].strip(), [item.strip().lower() for item in parts[1:]]


def _values(raw: Any) -> list[str]:
    if isinstance(raw, list):
        return [str(item) for item in raw]
    return [str(raw)]


def _expand_windash(values: list[str]) -> list[str]:
    """`windash`：把值里的 `-` 逐个替换成 5 种破折号变体，去重保序。"""

    expanded: list[str] = []
    for value in values:
        for variant in WINDASH_VARIANTS:
            expanded.append(value.replace("-", variant))
    return list(dict.fromkeys(expanded))


def _expand_base64offset(values: list[str]) -> list[str]:
    """`base64offset`：展开成 3 种对齐偏移下、完全由原值决定的 base64 子串。

    记录里被匹配的串是 `b64(任意前缀 + 值 + 任意后缀)`。base64 每 3 字节编 4 字符，
    字符 c 覆盖比特 [6c, 6c+6)：只有落在值字节区间 [8p, 8(p+L)) 内的字符才与
    前后缀无关——即切片 `b64("A"*p + 值)[ceil(4p/3) : floor(4(p+L)/3)]`。
    三种对齐 p ∈ {0,1,2} 覆盖记录中值的全部字节对齐情况。
    """

    variants: list[str] = []
    for value in values:
        raw = value.encode("utf-8")
        length = len(raw)
        for pad in range(3):
            encoded = base64.b64encode(b"A" * pad + raw).decode("ascii")
            start = -(-4 * pad // 3)
            end = 4 * (pad + length) // 3
            if end > start:
                variants.append(encoded[start:end])
    return list(dict.fromkeys(variants))


def _wildcard_to_regex(value: str) -> str:
    """把带 Sigma 通配符的取值转成锚定正则：`*` → `.*`，`?` → `.`，其余转义。"""

    parts: list[str] = []
    for ch in value:
        if ch == "*":
            parts.append(".*")
        elif ch == "?":
            parts.append(".")
        else:
            parts.append(re.escape(ch))
    return "^" + "".join(parts) + "$"


def _wildcard_shape(values: list[str]) -> tuple[str, list[str]] | None:
    """按 Sigma 语义处理普通取值里的 `*` 通配符。

    - 整组不带 `*` → 返回 None（调用方走 equals / in_set，语义最紧）
    - 全部是 `*x*` → contains；全部是 `x*` → startswith；全部是 `*x` → endswith
    - **中间通配（`a*b`）或混合形态 → 全组转锚定正则**（op=regex，
      `re.search` 语义所以必须加 `^...$`），语义与 Sigma 通配符一致
    """

    if not any("*" in value for value in values):
        return None
    shapes: set[str] = set()
    cleaned: list[str] = []
    middle_wildcard = False
    has_plain = False
    for value in values:
        if value in {"*", "**"}:
            raise ConversionError("取值为纯通配符，无法映射")
        if "*" not in value:
            has_plain = True
            cleaned.append(value)
            continue
        stripped = value.strip("*")
        if "*" in stripped:
            middle_wildcard = True
            break
        if value.startswith("*") and value.endswith("*"):
            shapes.add("contains")
            cleaned.append(value[1:-1])
        elif value.endswith("*"):
            shapes.add("startswith")
            cleaned.append(value[:-1])
        elif value.startswith("*"):
            shapes.add("endswith")
            cleaned.append(value[1:])
        else:
            cleaned.append(value)
    if middle_wildcard or len(shapes) > 1 or has_plain:
        # 全组转锚定正则：不带 `*` 的取值转成精确匹配，语义才与 Sigma 一致
        return "regex", [_wildcard_to_regex(value) for value in values]
    if any(not item for item in cleaned):
        raise ConversionError("去掉通配符后取值为空")
    return shapes.pop(), cleaned


def _build_predicates(key: str, raw_value: Any, ignore_case: bool) -> list[Predicate]:
    field_name, modifiers = _split_key(key)
    unsupported = [item for item in modifiers if item in UNSUPPORTED_MODIFIERS]
    if unsupported:
        raise ConversionError(f"暂不支持修饰符：{'、'.join(unsupported)}")
    unknown = [
        item
        for item in modifiers
        if item not in MODIFIER_OPS and item not in VALUE_TRANSFORMS and item != "all"
    ]
    if unknown:
        raise ConversionError(f"未知修饰符：{'、'.join(unknown)}")

    # `|re` 这类只有修饰符的键：Sigma 语义是全字段搜（隐式 keywords）；
    # 空字段名且无修饰符仍然是不合法规则
    is_keywords = field_name.lower() == "keywords" or not field_name
    if is_keywords:
        if not field_name and not modifiers:
            raise ConversionError("字段名为空")
        # 关键字在 url 与 raw 两处找；url 先解码再比，raw 保持原样
        targets = (("url", "url_decode"), ("raw", "none"))
    else:
        mapped = FIELD_MAP.get(field_name.lower())
        # 表里没有的字段原样直通：Sigma 的 Windows 规则用的就是 EVTX 标准字段名，
        # 解析器已按标准名把 `<EventData>` 里的字段落进记录（见 evtx._event_data）。
        targets = (mapped or (field_name, "none"),)
    specs = tuple(
        FieldSpec(field=name, transform=transform) for name, transform in targets
    )

    values = _values(raw_value)
    if not values:
        raise ConversionError(f"字段 {field_name} 取值为空")

    if "windash" in modifiers and "base64offset" in modifiers:
        raise ConversionError("windash 与 base64offset 不能组合使用")
    if "all" in modifiers and ("windash" in modifiers or "base64offset" in modifiers):
        raise ConversionError("|all 不支持与 windash / base64offset 组合")
    if "base64offset" in modifiers:
        if not ({"contains", "startswith", "endswith"} & set(modifiers)):
            raise ConversionError(
                "base64offset 必须与 contains / startswith / endswith 组合"
            )
        values = _expand_base64offset(values)
    if "windash" in modifiers:
        values = _expand_windash(values)

    if is_keywords and "re" not in modifiers and values_look_like_regex(values):
        raise ConversionError("keywords 中出现疑似正则，建议使用 |re 修饰符")

    all_mode = "all" in modifiers
    operation_selected = next(
        (modifier for modifier in modifiers if modifier in MODIFIER_OPS), None
    )

    if all_mode and operation_selected is None:
        raise ConversionError("|all 仅支持与 contains / startswith / endswith / re 组合")

    predicates: list[Predicate] = []
    if operation_selected is None:
        wildcard = _wildcard_shape(values)
        if wildcard is not None:
            shape, cleaned = wildcard
            if shape == "regex":
                return [
                    Predicate(
                        fields=specs,
                        op="regex",
                        values=(pattern,),
                        ignore_case=True,
                    )
                    for pattern in cleaned
                ]
            op = {
                "contains": "any_contains",
                "startswith": "any_startswith",
                "endswith": "any_endswith",
            }[shape]
            return [
                Predicate(
                    fields=specs,
                    op=op,
                    values=tuple(cleaned),
                    ignore_case=ignore_case,
                )
            ]
        op = "equals" if len(values) == 1 else "in_set"
        predicates.append(
            Predicate(
                fields=specs,
                op=op,
                values=tuple(values),
                ignore_case=ignore_case,
            )
        )
        return predicates

    op = MODIFIER_OPS[operation_selected]
    if op == "contains":
        if all_mode:
            for value in values:
                predicates.append(
                    Predicate(
                        fields=specs,
                        op="contains",
                        values=(value,),
                        ignore_case=True,
                    )
                )
            return predicates
        return [
            Predicate(
                fields=specs,
                op="any_contains",
                values=tuple(values),
                ignore_case=True,
            )
        ]
    if op in {"startswith", "endswith"}:
        any_op = "any_startswith" if op == "startswith" else "any_endswith"
        if all_mode:
            return [
                Predicate(
                    fields=specs,
                    op=op,
                    values=(value,),
                    ignore_case=ignore_case,
                )
                for value in values
            ]
        return [
            Predicate(
                fields=specs,
                op=any_op,
                values=tuple(values),
                ignore_case=ignore_case,
            )
        ]
    if op == "regex":
        return [
            Predicate(
                fields=specs,
                op="regex",
                values=(value,),
                ignore_case=True,
            )
            for value in values
        ]
    raise ConversionError(f"暂不支持的操作：{op}")


def values_look_like_regex(values: list[str]) -> bool:
    return any(re.search(r"[\[\](){}|\\^$*+?]", value) for value in values)


def _selection_dnf(name: str, block: Any) -> list[list[Predicate]]:
    """把单个检测块转换为 DNF。

    Sigma 允许三种写法：
      - 字段映射：``{field: value}``            → 一个 AND 分组
      - 关键字列表：``[kw1, kw2]``              → 关键字在 url / raw 上做 OR 匹配
      - 映射列表：``[{a: 1}, {b: 2}]``          → 列表内为 OR，映射内为 AND
    """

    if isinstance(block, dict):
        predicates: list[Predicate] = []
        for key, value in block.items():
            predicates.extend(_build_predicates(key, value, ignore_case=True))
        if not predicates:
            raise ConversionError(f"检测块 {name} 为空")
        return [predicates]

    if isinstance(block, list) and block and all(isinstance(item, str) for item in block):
        return [
            [
                Predicate(
                    fields=(
                        FieldSpec(field="url", transform="url_decode"),
                        FieldSpec(field="raw", transform="none"),
                    ),
                    op="any_contains",
                    values=tuple(str(item) for item in block),
                    ignore_case=True,
                )
            ]
        ]

    if isinstance(block, list) and block and all(isinstance(item, dict) for item in block):
        groups: list[list[Predicate]] = []
        for item in block:
            predicates: list[Predicate] = []
            for key, value in item.items():
                predicates.extend(_build_predicates(key, value, ignore_case=True))
            if predicates:
                groups.append(predicates)
        if not groups:
            raise ConversionError(f"检测块 {name} 为空")
        return groups

    raise ConversionError(f"检测块 {name} 的写法暂不支持")


def _selections(detection: dict[str, Any]) -> dict[str, list[list[Predicate]]]:
    selections: dict[str, list[list[Predicate]]] = {}
    for name, block in detection.items():
        if name in {"condition", "timeframe"}:
            continue
        selections[name] = _selection_dnf(name, block)
    if not selections:
        raise ConversionError("detection 中没有可用的检测块")
    return selections


def _field_dict(spec: FieldSpec) -> str | dict[str, Any]:
    """多字段谓词的单个字段引用：无变换时写成裸字符串，保持生成文件紧凑。"""

    if spec.transform == "none":
        return spec.field
    return {"field": spec.field, "transform": spec.transform}


def _predicate_dict(predicate: Predicate) -> dict[str, Any]:
    payload: dict[str, Any] = {"op": predicate.op}
    if len(predicate.fields) == 1:
        spec = predicate.fields[0]
        payload["field"] = spec.field
        if spec.transform != "none":
            payload["transform"] = spec.transform
    else:
        payload["field"] = [_field_dict(spec) for spec in predicate.fields]
    if len(predicate.values) == 1:
        payload["value"] = predicate.values[0]
    else:
        payload["values"] = list(predicate.values)
    if not predicate.ignore_case:
        payload["ignore_case"] = False
    if predicate.negate:
        payload["negate"] = True
    return payload


HOST_CATEGORIES = frozenset(
    {
        "process_creation",
        "file_event",
        "registry_set",
        "registry_event",
        "dns_query",
        "network_connection",
    }
)

# Sigma 的分类本身就蕴含 Sysmon EventID：不补这个必要条件，规则会跑到「所有 Windows 记录」上，
# 既语义不对（进程创建规则不该匹配注册表事件），也让规则索引失去最有区分度的键。
# 只在 service 为空或 sysmon 时生效——`service: security` 的 process_creation 实际是 4688，
# 补成 EID 1 会把安全通道的记录全部漏掉。
#: 分类 → Sysmon EventID。这些 ID 会变成规则的**必要条件守卫**（`status == EID`），
#: 也是规则索引唯一能用上的高区分度键。缺了这一层，规则只能靠 `exists` 弱键参与索引，
#: 逐条扫描会让规则耗时成倍上升（2026-10-13 实测：扩量后 2.99s → 19.53s 就是这么来的）。
#:
#: 只填 Sysmon 标准 EventID，且必须是本项目解析器真的会写进 `status` 的那些。
#: 填错会让守卫把本该命中的记录挡在门外（假阴性），所以宁缺勿错。
SYSMON_EVENT_IDS: dict[str, tuple[str, ...]] = {
    "process_creation": ("1",),
    "process_termination": ("5",),
    "driver_load": ("6",),
    "image_load": ("7",),
    "create_remote_thread": ("8",),
    "raw_access_read": ("9",),
    "raw_access_thread": ("9",),
    "process_access": ("10",),
    "file_event": ("11",),
    "file_delete": ("23", "26"),
    "registry_set": ("12", "13", "14"),
    "registry_event": ("12", "13", "14"),
    "registry_add": ("12",),
    "registry_delete": ("12",),
    "registry_rename": ("14",),
    "create_stream_hash": ("15",),
    "pipe_created": ("17", "18"),
    "wmi_event": ("19", "20", "21"),
    "dns_query": ("22",),
    "network_connection": ("3",),
    "process_tampering": ("25",),
    "clipboard_capture": ("24",),
    "ps_script": ("4104",),
}


def _is_host_category(document: dict[str, Any]) -> bool:
    """判断这条规则是「终端行为」还是「网络/服务访问」类，决定归组字段与摘要写法。"""

    logsource = document.get("logsource") or {}
    category = str(logsource.get("category") or "").lower()
    product = str(logsource.get("product") or "").lower()
    # Windows 事件都带主机（与进程）上下文：`EventID` 决定事件种类，归组按主机 + 进程更稳，
    # 否则同一批事件会并成一个 unknown 桶。非 Windows（Web / SSH / syslog）才按来源 IP 归组。
    if product == "windows":
        return True
    return category in HOST_CATEGORIES


def _has_event_id_guard(document: dict[str, Any]) -> bool:
    """规则是否用 `EventID` 把自己钉在特定事件上。

    `logsource` 认不出服务名时，这是唯一还能依赖的守卫：EVTX 解析器能读任意通道，
    但没有 EventID 约束的规则会跑到全部 EVTX 记录上，只能继续整条跳过。
    """

    detection = document.get("detection") or {}
    for name, block in detection.items():
        if name in {"condition", "timeframe"}:
            continue
        items = [block] if isinstance(block, dict) else block if isinstance(block, list) else []
        for item in items:
            if not isinstance(item, dict):
                continue
            if any(
                str(key).split("|")[0].strip().lower() in {"eventid", "event_id"}
                for key in item
            ):
                return True
    return False


def _logsource(document: dict[str, Any]) -> dict[str, object]:
    logsource = document.get("logsource") or {}
    category = str(logsource.get("category") or "").lower()
    product = str(logsource.get("product") or "").lower()
    service = str(logsource.get("service") or "").lower()
    if product == "windows" and service == "security":
        return dict(LOGSOURCE_MAP["windows-security"])
    # windows/builtin：service 是通道名，本项目统一由 windows_evtx 承载
    if product == "windows" and service in WINDOWS_SERVICES:
        return dict(LOGSOURCE_MAP["process_creation"])
    # Sysmon 分类：`SYSMON_EVENT_IDS` 已给出对应的 EventID 守卫，按同一组日志类型承载。
    # 原先只认 LOGSOURCE_MAP 里那 9 个分类，而守卫表里有 23 个——同一个事实写在两张表里，
    # 漏掉的那 14 个分类（image_load / pipe_created / create_remote_thread …）白丢。
    if category in SYSMON_EVENT_IDS:
        return dict(LOGSOURCE_MAP["process_creation"])
    if category in LOGSOURCE_MAP:
        return dict(LOGSOURCE_MAP[category])
    # 认不出的 Windows 服务（applocker / codeintegrity-operational / bits-client …）：
    # 只有规则自己用 `EventID` 钉住事件时才放行，否则会跑到全部 EVTX 记录上。
    if product == "windows" and service and _has_event_id_guard(document):
        return dict(LOGSOURCE_MAP["process_creation"])
    raise ConversionError(
        f"logsource 无法映射：product={product or '-'} category={category or '-'} service={service or '-'}"
    )


def normalize_tags(tags: Any) -> list[str]:
    normalized: list[str] = []
    for tag in tags or []:
        text = str(tag)
        match = re.fullmatch(r"attack\.t(\d{4}(?:\.\d{3})?)", text, re.IGNORECASE)
        normalized.append(f"attack.T{match.group(1)}" if match else text)
    return normalized


def convert_rule(document: dict[str, Any]) -> dict[str, Any]:
    """把一条 Sigma 规则转换成项目内部的声明式规则；失败时抛出 ConversionError。"""

    title = str(document.get("title") or "").strip()
    if not title:
        raise ConversionError("缺少 title")
    rule_id = str(document.get("id") or "").strip()
    if not rule_id:
        raise ConversionError("缺少 id")
    detection = document.get("detection")
    if not isinstance(detection, dict):
        raise ConversionError("缺少 detection")
    condition = detection.get("condition")
    if not condition:
        raise ConversionError("缺少 condition")

    selections = _selections(detection)
    node = parse_condition(str(condition))
    groups = to_dnf(node, selections)
    logsource = _logsource(document)
    level = LEVEL_MAP.get(str(document.get("level") or "info").lower(), "info")

    where: list[dict[str, Any]] = []
    any_of: list[list[dict[str, Any]]] = []
    if len(groups) == 1:
        where = [_predicate_dict(predicate) for predicate in groups[0]]
    else:
        any_of = [
            [_predicate_dict(predicate) for predicate in group] for group in groups
        ]

    # 必要条件（guards）：① 分类蕴含的 Sysmon EventID ② 单字段非取反谓词涉及的字段必须存在。
    # 两者都是「原规则隐含成立」的条件，加上去不改变判定结果，但能让规则索引跳过大量无关记录
    # （没有这一步，500 条导入规则会退化成「每条记录跑全部规则」，实测规则耗时从 2s 涨到 48s）。
    # 只在 where 是纯 AND 结构（单一 DNF 组）时才能补 exists：多组是 OR 语义，
    # 某个字段只在其中一组出现，补成必要条件会砍掉其它分支。
    guards: list[dict[str, Any]] = []
    logsource_document = document.get("logsource") or {}
    category = str(logsource_document.get("category") or "").lower()
    service = str(logsource_document.get("service") or "").lower()
    event_ids = SYSMON_EVENT_IDS.get(category, ())
    if event_ids and service in ("", "sysmon"):
        guards.append(
            {"field": "status", "op": "equals", "value": event_ids[0]}
            if len(event_ids) == 1
            else {"field": "status", "op": "in_set", "values": list(event_ids)}
        )
    if len(groups) == 1:
        guard_fields: list[str] = []
        for predicate in groups[0]:
            if predicate.negate or len(predicate.fields) != 1:
                continue
            spec = predicate.fields[0]
            if spec.transform != "none" or spec.default or spec.field == "status":
                continue
            if spec.field not in guard_fields:
                guard_fields.append(spec.field)
        guards.extend({"field": name, "op": "exists"} for name in guard_fields)
    where = guards + where

    event_type = f"sigma_{slug(title)}"
    # 终端行为类规则没有来源 IP，用「主机 + 进程」归组，否则同一批事件会并成一个 unknown 桶，
    # 也避免多个主机的事件被合并成一条。网络类规则保持按来源 IP 归组。
    if _is_host_category(document):
        group_by: list[Any] = [
            {"field": "target_asset", "default": "unknown"},
            {"field": "process_image", "default": "unknown"},
        ]
        summary = (
            f"{{asset}} 上社区规则「{title}」命中 {{count}} 次，示例：{{sample}}"
        )
    else:
        group_by = [{"field": "source_ip", "default": "unknown"}]
        summary = (
            f"社区规则「{title}」命中 {{count}} 条记录（来源 {{ip}}），示例：{{sample}}"
        )
    rule: dict[str, Any] = {
        "id": f"sigma.{rule_id}",
        "enabled_env": f"RULE_{slug(title).upper()}_ENABLED",
        "title": title,
        "description": str(document.get("description") or "来自 Sigma 社区规则").strip(),
        "level": level,
        "logsource": logsource,
        "detection": {
            "where": where,
            # Sigma 规则本身是「逐条匹配」语义，反复命中会逐条刷事件。
            # 这里统一加轻量聚合兜底：同组 + 同时间窗合并为一条，保留计数与示例证据。
            "aggregate": {"group_by": group_by, "bucket": True},
        },
        "event": {
            "type": event_type,
            "name": f"[Sigma] {title}",
            "level": level,
            "summary": summary,
        },
        "tags": normalize_tags(document.get("tags")),
        "source": "sigma",
    }
    if any_of:
        rule["detection"]["any"] = any_of
    author = str(document.get("author") or "").strip()
    if author:
        rule["author"] = author
    references = sigma_references(document.get("references"))
    if references:
        rule["references"] = references
    return rule


def sigma_references(raw: Any) -> list[str]:
    """取源规则的参考链接，只保留 http(s) URL。

    字段语义是「参考链接」，因此 `Internal Research` 这类非链接的占位文本不写入
    （SigmaHQ 的 Windows 规则里有 107 条是这种）——但**不静默丢弃**：
    导入脚本会把条数写进报告（见 `scripts/import_sigma_community.py`）。
    """

    values = raw if isinstance(raw, (list, tuple)) else ([raw] if raw else [])
    return [
        text
        for text in (str(item).strip() for item in values)
        if text.startswith(("http://", "https://"))
    ]


def convert_documents(
    documents: list[tuple[Path, dict[str, Any]]]
) -> SigmaImportReport:
    converted: list[SigmaConvertedRule] = []
    skipped: list[SigmaSkippedRule] = []
    for path, document in documents:
        try:
            rule = convert_rule(document)
        except ConversionError as exc:
            skipped.append(
                SigmaSkippedRule(
                    path=path.name,
                    title=str(document.get("title") or path.stem),
                    reason=str(exc),
                )
            )
            continue
        converted.append(
            SigmaConvertedRule(
                id=str(rule["id"]),
                title=str(rule["title"]),
                level=str(rule["level"]),
                tags=list(rule["tags"]),
                path=path.name,
                rule=rule,
            )
        )
    return SigmaImportReport(
        total=len(documents),
        converted_count=len(converted),
        skipped_count=len(skipped),
        converted=converted,
        skipped=skipped,
    )


def convert_uploaded(filename: str, content: bytes) -> SigmaImportReport:
    """转换上传的 Sigma 规则内容（支持单文件多文档），供 API 预演使用。"""

    text = content.decode("utf-8", errors="replace")
    try:
        parsed_documents = [
            item for item in yaml.safe_load_all(text) if isinstance(item, dict)
        ]
    except Exception as exc:
        return SigmaImportReport(
            total=1,
            skipped_count=1,
            skipped=[
                SigmaSkippedRule(
                    path=filename, title=filename, reason=f"YAML 解析失败：{exc}"
                )
            ],
        )
    if not parsed_documents:
        return SigmaImportReport(
            total=1,
            skipped_count=1,
            skipped=[
                SigmaSkippedRule(
                    path=filename, title=filename, reason="文件中没有可解析的规则"
                )
            ],
        )
    return convert_documents([(Path(filename), item) for item in parsed_documents])


def load_documents(target: Path) -> list[tuple[Path, dict[str, Any]]]:
    paths: list[Path] = []
    if target.is_dir():
        paths = sorted(target.rglob("*.yml")) + sorted(target.rglob("*.yaml"))
    else:
        paths = [target]
    documents: list[tuple[Path, dict[str, Any]]] = []
    for path in paths:
        try:
            parsed = yaml.safe_load(path.read_text(encoding="utf-8"))
        except Exception as exc:  # 语法错误单独报告，不影响其它规则
            documents.append((path, {"title": f"（无法解析：{exc}）", "id": path.stem}))
            continue
        if isinstance(parsed, dict) and ("detection" in parsed or "logsource" in parsed):
            documents.append((path, parsed))
    return documents


def convert_path(target: Path) -> SigmaImportReport:
    return convert_documents(load_documents(target))


SIGMA_RULES_PATH = backend_root() / "rules" / "90-sigma.yaml"
SIGMA_HEADER = (
    "# 由 backend/scripts/import_sigma.py 生成的 Sigma 导入规则，请勿手工编辑。\n"
    "# 重新导入：cd backend && .venv\\Scripts\\python.exe scripts\\import_sigma.py --write\n\n"
)

#: Sigma 导入规则的**文档级**元数据：1608 条同源同许可，逐条重复只会让生成文件再膨胀。
#: 逐条 author / references 需要 SigmaHQ 检出目录才能取到真实值，此处**不编造**
#: （见路线图 P5-③ 导入溯源）。
SIGMA_METADATA: dict[str, Any] = {
    "author": "SigmaHQ contributors",
    "license": "DRL-1.1",
}


def render_rules_file(
    converted: list[dict[str, Any]],
    header: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> str:
    document: dict[str, Any] = {}
    if metadata:
        document["metadata"] = metadata
    document["rules"] = converted
    body = yaml.safe_dump(document, allow_unicode=True, sort_keys=False, width=1000)
    return (header if header is not None else SIGMA_HEADER) + body


def write_rules(
    rules: list[dict[str, Any]],
    path: Path | None = None,
    header: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> Path:
    target = path or SIGMA_RULES_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_rules_file(rules, header, metadata), encoding="utf-8")
    return target


def report_rules(report: SigmaImportReport) -> list[dict[str, Any]]:
    return [item.rule for item in report.converted]
