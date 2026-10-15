"""声明式规则引擎：YAML 规则 → 条件匹配 / 时间窗聚合 / 关联后续记录 → Event。

设计要点（详见 README「规则声明式表达」）：

- 规则是**数据**，不是代码；新增规则只需加一个 YAML 文件。
- 两类原语：`where`/`any` 描述记录级条件，`aggregate` 描述时间窗与聚合；
  `follow_up` 描述「失败聚集后出现成功」这类跨记录关联。
- 事件构造（证据、时间线、关联依据、编号）复用 `services/events.py`，
  与旧实现产出的 Event 结构完全一致，保证下游（分析器 / 报告 / AI / 前端）零改动。
- 阈值与开关沿用既有环境变量（`threshold_env` / `window_env` / `enabled_env`），
  因此 `.env` 里的既有配置继续生效。
"""

from __future__ import annotations

from collections import Counter

import os
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable
from urllib.parse import unquote, urlsplit

import yaml

from ..models import Event
from ..runtime_paths import backend_root
from .events import build_event, distinct_window, failure_window, record_time
from .rule_governance import apply_rule_overrides

RULES_DIR = backend_root() / "rules"
SIGMA_GLOBAL_ENV = "RULE_SIGMA_IMPORTED_ENABLED"

BOOL_TRUE = {"1", "true", "yes", "on", "enabled"}
BOOL_FALSE = {"0", "false", "no", "off", "disabled"}
EVENT_RECORD_LIMIT = 10


def bool_env(name: str | None, default: bool = True) -> bool:
    if not name:
        return default
    value = os.getenv(name)
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in BOOL_TRUE:
        return True
    if normalized in BOOL_FALSE:
        return False
    return default


def int_env(name: str | None, default: int) -> int:
    if not name:
        return default
    value = os.getenv(name)
    if value is None or not value.strip():
        return default
    try:
        return int(value.strip())
    except ValueError:
        return default


def _transform(value: str | None, name: str) -> str:
    if value is None:
        return ""
    if name == "none":
        return value
    if name == "lower":
        return value.lower()
    if name == "upper":
        return value.upper()
    if name == "url_decode":
        return unquote(unquote(value)).lower()
    if name == "url_path":
        decoded = unquote(unquote(value)).lower()
        path = urlsplit(decoded).path.rstrip("/") or "/"
        return path if path.startswith("/") else f"/{path}"
    raise ValueError(f"未知的字段变换：{name}")


@dataclass(frozen=True)
class FieldSpec:
    """字段引用：可带默认值与变换（例如把 url 归一化为路径后再分组）。"""

    field: str
    transform: str = "none"
    default: str = ""

    def read(self, record: dict[str, str | None]) -> str:
        raw = record.get(self.field)
        if raw is None or raw == "":
            return self.default
        # 绝大多数谓词不带变换，没必要为它绕一次函数调用
        if self.transform == "none":
            return raw
        return _transform(raw, self.transform)


def _compile_any(op: str, values: tuple[str, ...]) -> re.Pattern[str] | None:
    """把多值匹配合并成一次正则扫描。

    「逐值 in / startswith」是规则匹配的主要热点（单条规则十几个值 × 每条记录），
    合并后由 C 层一次扫完。用 `re.escape` 保证与字面量匹配完全等价——
    这里不能图快手写字符类，否则含 `.` `*` 的词表会静默变成正则。
    """

    if not values:
        return None
    alternation = "|".join(re.escape(value) for value in values)
    if op == "any_contains":
        return re.compile(alternation)
    if op == "any_startswith":
        return re.compile(f"^(?:{alternation})")
    if op == "any_endswith":
        return re.compile(f"(?:{alternation})$")
    if op == "any_path_prefix":
        return re.compile(f"^(?:{alternation})(?:/|$)")
    return None


def _field_reader(spec: FieldSpec) -> Callable[[dict[str, str | None]], str]:
    """字段读取器：把「取值 → 判空 → 变换 → 兜底默认值」固化成闭包。

    逐记录匹配是规则引擎的最大热点（单次分析可达百万次调用），因此这里不再走
    `FieldSpec.read`，省掉每层一帧的调用开销。
    """

    name = spec.field
    default = spec.default
    transform = spec.transform
    if transform == "none":
        if not default:
            return lambda record: record.get(name) or ""
        return lambda record: record.get(name) or default

    def read(record: dict[str, str | None]) -> str:
        raw = record.get(name)
        if raw is None or raw == "":
            return default
        return _transform(raw, transform)

    return read


def _single_field_matcher(
    read: Callable[[dict[str, str | None]], str], predicate: "Predicate"
) -> Callable[[dict[str, str | None]], bool]:
    """按操作符生成单字段匹配函数：构建期把取值与分支定死，匹配时只做比较。

    只取决于规则本身的量（归一化取值、集合、正则、大小写策略）都在这里取出，
    避免逐记录重复访问 `self.*` 属性。
    """

    op = predicate.op
    if op == "exists":
        # exists 只看字段有没有值，不做大小写归一
        return lambda record: bool(read(record))

    sequence = predicate.normalized
    allowed = predicate.normalized_set
    pattern = predicate.compiled
    fold = str.lower if predicate.ignore_case else None
    target = sequence[0] if sequence else ""
    regex_pattern = predicate.values[0] if predicate.values else ""
    regex_flags = re.IGNORECASE if predicate.ignore_case else 0

    if op in ("any_contains", "any_startswith", "any_endswith", "any_path_prefix"):
        if pattern is None:
            # 未给出取值时不匹配（与既有语义一致）
            return lambda record: False

    def match(record: dict[str, str | None]) -> bool:
        value = read(record)
        # 空值一律不匹配：缺失字段不参与判定
        if not value:
            return False
        if op == "regex":
            # 正则用原始值，大小写由编译标志控制，不能先归一
            return re.search(regex_pattern, value, regex_flags) is not None
        candidate = fold(value) if fold else value
        if op == "equals":
            return candidate == target
        if op == "in_set":
            return candidate in allowed
        if op == "any_contains":
            return pattern.search(candidate) is not None
        if op == "contains":
            return target in candidate
        if op == "startswith":
            return candidate.startswith(target)
        if op == "any_startswith":
            return pattern.match(candidate) is not None
        if op == "endswith":
            return candidate.endswith(target)
        if op == "any_endswith":
            return pattern.search(candidate) is not None
        if op == "any_path_prefix":
            return pattern.match(candidate) is not None
        raise ValueError(f"未知的匹配操作：{op}")

    return match


@dataclass(frozen=True)
class Predicate:
    fields: tuple[FieldSpec, ...]
    op: str
    values: tuple[str, ...]
    ignore_case: bool = True
    negate: bool = False
    # 归一化只取决于规则本身，构造时算一次；逐记录匹配时不再重复计算
    normalized: tuple[str, ...] = ()
    normalized_set: frozenset[str] = frozenset()
    # 多值匹配合并成的单个正则，同样只取决于规则本身
    compiled: re.Pattern[str] | None = None
    # 逐记录匹配函数；参与比较会影响 dataclass 相等性，故排除
    matcher: Callable[[dict[str, str | None]], bool] | None = field(
        default=None, compare=False, repr=False
    )

    def __post_init__(self) -> None:
        normalized = tuple(
            value.lower() if self.ignore_case else value for value in self.values
        )
        object.__setattr__(self, "normalized", normalized)
        object.__setattr__(self, "normalized_set", frozenset(normalized))
        object.__setattr__(self, "compiled", _compile_any(self.op, normalized))

        # 多字段谓词是 any 语义：任一字段命中即成立
        matchers = tuple(
            _single_field_matcher(_field_reader(spec), self) for spec in self.fields
        )
        if len(matchers) == 1:
            core = matchers[0]
        else:

            def core(record: dict[str, str | None]) -> bool:
                for matcher in matchers:
                    if matcher(record):
                        return True
                return False

        object.__setattr__(
            self,
            "matcher",
            (lambda record: not core(record)) if self.negate else core,
        )

    def matches(self, record: dict[str, str | None]) -> bool:
        """对外入口；热路径（`Rule.covers`）直接调用 `matcher`，不再多绕一层。"""

        return bool(self.matcher(record)) if self.matcher else False


@dataclass(frozen=True)
class FollowUp:
    where: tuple[Predicate, ...]
    within_seconds: int


@dataclass(frozen=True)
class Aggregate:
    group_by: tuple[FieldSpec, ...]
    window_seconds: int
    count_gte: int | None = None
    distinct_field: FieldSpec | None = None
    distinct_gte: int | None = None
    bucket: bool = False
    follow_up: FollowUp | None = None


@dataclass(frozen=True)
class EventSpec:
    type: str
    name: str
    summary: str
    level: str
    notes: dict[str, Any] = field(default_factory=dict)
    count_policy: str = "window"
    time_policy: str = "window"
    evidence_policy: str = "window_head"
    evidence_head: int = EVENT_RECORD_LIMIT
    follow_up_head: int = 2


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    description: str
    level: str
    event: EventSpec
    where: tuple[Predicate, ...] = ()
    any_of: tuple[tuple[Predicate, ...], ...] = ()
    aggregate: Aggregate | None = None
    log_types: tuple[str, ...] = ()
    exclude_log_types: tuple[str, ...] = ()
    display_log_types: tuple[str, ...] = ()
    enabled: bool = True
    threshold: int | None = None
    window_seconds: int | None = None
    tags: tuple[str, ...] = ()
    source: str = "builtin"
    author: str | None = None
    version: str | None = None
    license: str | None = None
    references: tuple[str, ...] = ()
    validation_status: str = "unverified"
    suppresses: tuple[str, ...] = ()
    upgrade_rule: str | None = None

    def logsource_ok(self, record: dict[str, str | None]) -> bool:
        log_type = record.get("log_type") or ""
        if self.exclude_log_types and log_type in self.exclude_log_types:
            return False
        return not self.log_types or log_type in self.log_types

    def covers(self, record: dict[str, str | None]) -> bool:
        if not self.logsource_ok(record):
            return False
        # 直接调用预编译的 matcher：这是全流程最热的循环，少一层调用就少百万次开销
        for predicate in self.where:
            if not predicate.matcher(record):
                return False
        if not self.any_of:
            return True
        # 逐个条件组短路；单谓词组同样走快路径
        for group in self.any_of:
            if len(group) == 1:
                if group[0].matcher(record):
                    return True
            elif all(predicate.matcher(record) for predicate in group):
                return True
        return False


def _field_spec(raw: Any) -> FieldSpec:
    if isinstance(raw, str):
        return FieldSpec(raw)
    return FieldSpec(
        field=str(raw.get("field")),
        transform=str(raw.get("transform") or "none"),
        default=str(raw.get("default") or ""),
    )


def _predicate(raw: dict[str, Any]) -> Predicate:
    fields = raw.get("field")
    if isinstance(fields, list):
        specs = tuple(_field_spec(item) for item in fields)
    else:
        specs = (
            FieldSpec(
                field=str(fields),
                transform=str(raw.get("transform") or "none"),
                default=str(raw.get("default") or ""),
            ),
        )
    values = raw.get("values")
    if values is None:
        values = [] if raw.get("value") is None else [raw["value"]]
    return Predicate(
        fields=specs,
        op=str(raw.get("op") or "equals"),
        values=tuple(str(item) for item in values),
        ignore_case=bool(raw.get("ignore_case", True)),
        negate=bool(raw.get("negate", False)),
    )


def _predicates(raw: Any) -> tuple[Predicate, ...]:
    return tuple(_predicate(item) for item in (raw or []))


def _aggregate(raw: dict[str, Any], threshold: int | None, window: int | None) -> Aggregate:
    distinct = raw.get("distinct_field")
    follow_up = raw.get("follow_up")
    return Aggregate(
        group_by=tuple(_field_spec(item) for item in raw.get("group_by", [])),
        window_seconds=int(window if window is not None else raw.get("window_seconds", 300)),
        count_gte=int(threshold if threshold is not None else raw.get("count_gte", 0))
        if raw.get("count_gte") is not None or threshold is not None
        else None,
        distinct_field=_field_spec(distinct) if distinct else None,
        distinct_gte=int(raw["distinct_gte"]) if raw.get("distinct_gte") is not None else None,
        bucket=bool(raw.get("bucket", False)),
        follow_up=FollowUp(
            where=_predicates(follow_up.get("where")),
            within_seconds=int(follow_up.get("within_seconds", 1800)),
        )
        if follow_up
        else None,
    )


def _event_spec(raw: dict[str, Any], level: str) -> EventSpec:
    return EventSpec(
        type=str(raw.get("type")),
        name=str(raw.get("name")),
        summary=str(raw.get("summary") or ""),
        level=str(raw.get("level") or level),
        notes=dict(raw.get("notes") or {}),
        count_policy=str(raw.get("count") or "window"),
        time_policy=str(raw.get("time") or "window"),
        evidence_policy=str(raw.get("evidence") or "window_head"),
        evidence_head=int(raw.get("evidence_head", EVENT_RECORD_LIMIT)),
        follow_up_head=int(raw.get("follow_up_head", 2)),
    )


def build_rule(
    raw: dict[str, Any],
    source: str,
    defaults: dict[str, Any] | None = None,
) -> Rule:
    """把一条 YAML 规则转成 `Rule`。

    `defaults` 是**文档级**元数据（`metadata` 块）：同一文件里的规则元数据往往一致
    （内置规则作者/许可相同、1608 条 Sigma 导入规则同源同版本），逐条重复既让
    3.85 MB 的导入文件再膨胀，也让「改一处要改一千处」。取值优先级：
    **规则级 → 文档级 → 内置默认**。
    """

    def meta(key: str) -> Any:
        value = raw.get(key)
        if value in (None, ""):
            value = (defaults or {}).get(key)
        return value

    enabled = bool_env(raw.get("enabled_env"))
    if source == "sigma":
        # 社区导入规则额外受全局开关控制，便于一键停用全部外部规则
        enabled = enabled and bool_env(SIGMA_GLOBAL_ENV)
    threshold = int_env(raw.get("threshold_env"), int(raw.get("threshold", 0))) or None
    window = int_env(raw.get("window_env"), int(raw.get("window_seconds", 0))) or None
    detection = raw.get("detection") or {}
    logsource = raw.get("logsource") or {}
    aggregate = detection.get("aggregate")
    author = meta("author")
    version = meta("version")
    license_name = meta("license")
    validation = meta("validation_status")
    return Rule(
        id=str(raw["id"]),
        title=str(raw.get("title") or raw["id"]),
        description=str(raw.get("description") or ""),
        level=str(raw.get("level") or "info"),
        event=_event_spec(raw.get("event") or {}, str(raw.get("level") or "info")),
        where=_predicates(detection.get("where")),
        any_of=tuple(_predicates(group) for group in detection.get("any", [])),
        aggregate=_aggregate(aggregate, threshold, window) if aggregate else None,
        log_types=tuple(logsource.get("log_types") or ()),
        exclude_log_types=tuple(logsource.get("exclude_log_types") or ()),
        display_log_types=tuple(logsource.get("display_log_types") or ()),
        enabled=enabled,
        threshold=threshold,
        window_seconds=window,
        tags=tuple(raw.get("tags") or ()),
        source=source,
        author=str(author) if author else None,
        version=str(version) if version else None,
        license=str(license_name) if license_name else None,
        references=tuple(str(item) for item in (meta("references") or ())),
        validation_status=str(validation or "unverified"),
        suppresses=tuple(raw.get("suppresses") or ()),
        upgrade_rule=str(raw["upgrade_rule"]) if raw.get("upgrade_rule") else None,
    )


def load_rules(directory: Path | None = None) -> list[Rule]:
    """加载规则目录下的全部 YAML；规则按文件内声明顺序执行。

    YAML 解析结果按文件 mtime 缓存（避免每次分析读盘），但 Rule 对象每次重建，
    因此环境变量（开关 / 阈值 / 窗口）的改动立即生效。
    """

    rules: list[Rule] = []
    for path, document in _documents(directory or RULES_DIR):
        default_source = str(document.get("source") or path.stem)
        defaults = document.get("metadata") or {}
        for raw in document.get("rules", []):
            rules.append(
                build_rule(
                    raw,
                    source=str(raw.get("source") or default_source),
                    defaults=defaults,
                )
            )
    return apply_rule_overrides(rules)


_DOCUMENT_CACHE: dict[Path, dict[str, Any]] = {}


def _documents(directory: Path) -> list[tuple[Path, dict[str, Any]]]:
    documents: list[tuple[Path, dict[str, Any]]] = []
    for path in sorted(directory.glob("*.yaml")):
        try:
            modified = path.stat().st_mtime
        except OSError:
            continue
        cached = _DOCUMENT_CACHE.get(path)
        if cached is None or cached["mtime"] != modified:
            cached = {
                "mtime": modified,
                "document": yaml.safe_load(path.read_text(encoding="utf-8")) or {},
            }
            _DOCUMENT_CACHE[path] = cached
        documents.append((path, cached["document"]))
    return documents


def _group_key(record: dict[str, str | None], group_by: tuple[FieldSpec, ...]) -> tuple[str, ...]:
    return tuple(spec.read(record) for spec in group_by)


def _render(template: str, context: dict[str, Any]) -> str:
    def replace(match: re.Match[str]) -> str:
        key = match.group(1)
        return str(context.get(key, ""))

    return re.sub(r"\{(\w+)\}", replace, template)


def _note(notes: dict[str, Any], name: str, state: str, context: dict[str, Any]) -> str:
    value = notes.get(name)
    if value is None:
        return ""
    if isinstance(value, dict):
        template = str(value.get(state) or "")
    else:
        template = str(value)
    return _render(template, context)


def _select_evidence(
    spec: EventSpec, window: list[dict[str, str | None]], follow_up: list[dict[str, str | None]]
) -> list[dict[str, str | None]]:
    if spec.evidence_policy == "single":
        return window[:1]
    if spec.evidence_policy == "window_follow_up":
        return window[:3] + follow_up[: spec.follow_up_head]
    return window[: spec.evidence_head]


def _single_events(rule: Rule, records: list[dict[str, str | None]]) -> list[Event]:
    events: list[Event] = []
    for record in records:
        context = {
            "ip": record.get("source_ip") or "",
            "asset": record.get("target_asset") or "",
            "image": record.get("process_image") or "",
            "parent": record.get("parent_image") or "",
            "file": record.get("target_filename") or "",
            "registry": record.get("registry_key") or "",
            "query": record.get("query_name") or "",
            "sample": record.get("url") or (record.get("raw") or "")[:120],
            "path": _transform(record.get("url"), "url_path"),
            "username": record.get("username") or "",
            "account": record.get("username") or "",
            "logon_hint": "，登录类型为 RDP（交互式远程）"
            if record.get("action") == "rdp_logon"
            else "",
            "count": 1,
            "success_count": 0,
            "success_note": "",
            "risk_level": record.get("risk_level") or "",
            "login_type": record.get("login_type") or "",
            "service_type": record.get("service_type") or "",
            "occurrence_count": record.get("occurrence_count") or "1",
            "vendor_event_id": record.get("vendor_event_id") or "",
            "first_seen": record.get("first_seen") or record.get("timestamp") or "",
            "last_seen": record.get("last_seen") or record.get("timestamp") or "",
        }
        events.append(
            build_event(
                rule.event.type,
                rule.event.name,
                rule.event.level,
                _render(rule.event.summary, context),
                source_ip=record.get("source_ip"),
                target_asset=record.get("target_asset"),
                first_seen=record.get("timestamp"),
                last_seen=record.get("timestamp"),
                count=1,
                records=[record],
                rule_id=rule.id,
            )
        )
    return events


def _aggregate_events(
    rule: Rule,
    selected: list[dict[str, str | None]],
    records: list[dict[str, str | None]],
    aggregate: Aggregate,
    enabled_ids: frozenset[str],
) -> list[Event]:
    """selected 参与窗口聚合；records 用于检索 follow_up 候选（成功记录不在 selected 内）。"""

    groups: dict[tuple[str, ...], list[dict[str, str | None]]] = {}
    for record in selected:
        groups.setdefault(_group_key(record, aggregate.group_by), []).append(record)

    events: list[Event] = []
    for key, items in groups.items():
        if aggregate.bucket:
            window = items
        elif aggregate.distinct_field is not None:
            window = distinct_window(
                items,
                aggregate.window_seconds,
                aggregate.distinct_field.field,
                aggregate.distinct_gte or 1,
            )
        else:
            window = failure_window(
                items, aggregate.window_seconds, aggregate.count_gte or 1
            )
        if not window:
            continue

        follow_up: list[dict[str, str | None]] = []
        if aggregate.follow_up:
            window_end = record_time(window[-1])
            follow_up = sorted(
                [
                    record
                    for record in records
                    if rule.logsource_ok(record)
                    and _group_key(record, aggregate.group_by) == key
                    and all(
                        predicate.matches(record)
                        for predicate in aggregate.follow_up.where
                    )
                    and _is_after(record, window_end, aggregate.follow_up.within_seconds)
                ],
                key=lambda record: record_time(record) or datetime.min,
            )

        usernames = {record.get("username") for record in window if record.get("username")}
        distinct_values = {
            record.get(aggregate.distinct_field.field)
            for record in window
            if aggregate.distinct_field and record.get(aggregate.distinct_field.field)
        }
        statuses = sorted({record.get("status") or "-" for record in window})
        rdp_attempts = sum(1 for record in window if record.get("action") == "rdp_logon")
        # 升级规则（声明 suppresses 且带 follow_up）只有在真正关联到后续记录时才成立
        if aggregate.follow_up and rule.suppresses and not follow_up:
            continue
        upgrade_enabled = bool(rule.upgrade_rule and rule.upgrade_rule in enabled_ids)
        follow_up_state = (
            "none" if not follow_up else ("found" if upgrade_enabled else "downgraded")
        )
        context: dict[str, Any] = {
            "ip": window[0].get("source_ip") or "",
            "asset": window[0].get("target_asset") or "",
            "image": window[0].get("process_image") or "",
            "parent": window[0].get("parent_image") or "",
            "file": window[0].get("target_filename") or "",
            "registry": window[0].get("registry_key") or "",
            "query": window[0].get("query_name") or "",
            "service": window[0].get("service_name") or "",
            "state": window[0].get("service_state") or "",
            "count": len(distinct_values) if distinct_values else len(window),
            "window": aggregate.window_seconds,
            "accounts": len(usernames),
            "success_count": len(follow_up),
            "rdp_attempts": rdp_attempts,
            "rdp_hint": f"其中 RDP（交互式远程）登录失败 {rdp_attempts} 次，" if rdp_attempts else "",
            "sample": window[0].get("url") or (window[0].get("raw") or "")[:120],
            "path": _transform(window[0].get("url"), "url_path"),
            "statuses": "/".join(statuses),
            "ports": len(distinct_values) if distinct_values else len(window),
            "destination": window[0].get("destination_ip") or "",
            "protocol": window[0].get("protocol") or "unknown",
            "username": (
                next(iter(usernames))
                if len(usernames) == 1
                else ("多个账户" if usernames else "未知账户")
            ),
            "logon_hint": "，登录类型为 RDP（交互式远程）"
            if window[0].get("action") == "rdp_logon"
            else "",
            "risk_level": window[0].get("risk_level") or "",
            "login_type": window[0].get("login_type") or "",
            "service_type": window[0].get("service_type") or "",
            "occurrence_count": sum(
                int(record.get("occurrence_count") or 0)
                for record in window
                if str(record.get("occurrence_count") or "").isdigit()
            ) or len(window),
            "vendor_event_id": window[0].get("vendor_event_id") or "",
            "first_seen": window[0].get("first_seen") or window[0].get("timestamp") or "",
            "last_seen": window[-1].get("last_seen") or window[-1].get("timestamp") or "",
        }
        context["success_note"] = _note(
            rule.event.notes, "success_note", follow_up_state, context
        )
        for name, value in rule.event.notes.items():
            if name == "success_note":
                continue
            context.setdefault(name, _note(rule.event.notes, name, follow_up_state, context))

        evidence = _select_evidence(rule.event, window, follow_up)
        end_record = follow_up[-1] if follow_up else window[-1]
        if rule.event.time_policy == "window":
            last_seen = window[-1].get("timestamp")
        else:
            last_seen = end_record.get("timestamp")
        events.append(
            build_event(
                rule.event.type,
                rule.event.name,
                rule.event.level,
                _render(rule.event.summary, context),
                source_ip=window[0].get("source_ip"),
                target_asset=window[0].get("target_asset"),
                first_seen=window[0].get("timestamp"),
                last_seen=last_seen,
                count=(
                    context["occurrence_count"]
                    if rule.event.count_policy == "occurrence_sum"
                    else
                    len(distinct_values)
                    if rule.event.count_policy == "distinct" and distinct_values
                    else len(window)
                ),
                records=evidence,
                rule_id=rule.id,
            )
        )
    return events


def _is_after(
    record: dict[str, str | None], window_end: datetime | None, within_seconds: int
) -> bool:
    if window_end is None:
        return True
    value = record_time(record)
    if value is None:
        return True
    if value < window_end:
        return False
    return (value - window_end).total_seconds() <= within_seconds


def evaluate_rule_with_coverage(
    rule: Rule,
    records: list[dict[str, str | None]],
    enabled_ids: frozenset[str] = frozenset(),
) -> tuple[list[Event], set[str]]:
    """执行单条规则，同时返回被它命中的记录 ID 集合。

    覆盖度统计与规则执行共用同一次字段匹配，避免为了统计再把所有规则跑一遍。
    """

    if not rule.enabled:
        return [], set()
    selected = [record for record in records if rule.covers(record)]
    if not selected:
        return [], set()
    covered = {record["record_id"] for record in selected if record.get("record_id")}
    if rule.aggregate is None:
        return _single_events(rule, selected), covered
    return (
        _aggregate_events(rule, selected, records, rule.aggregate, enabled_ids),
        covered,
    )


def evaluate_rule(
    rule: Rule,
    records: list[dict[str, str | None]],
    enabled_ids: frozenset[str] = frozenset(),
) -> list[Event]:
    return evaluate_rule_with_coverage(rule, records, enabled_ids)[0]


#: 允许用作索引键的字段变换：必须是**纯函数**，且索引侧能对记录做同一个变换。
#: `url_path` 取路径、`url_decode` 解码、`lower/upper` 改大小写，都是确定且无副作用的。
KEY_TRANSFORMS = frozenset({"none", "lower", "upper", "url_decode", "url_path"})


def _index_keys(rule: "Rule") -> list[tuple[str, str, Any, str]]:
    """可作为索引键的谓词，返回 (kind, field, value)。

    只有「单字段、无变换、无默认值、非 negate」的 `equals` / `exists` 才等价于对
    `record.get(字段)` 的简单判断。带变换、默认值或多字段的谓词都不能当必要条件用——
    拿它们做索引会静默漏掉本该命中的记录。
    """

    if rule.aggregate is not None and rule.aggregate.follow_up is not None:
        # follow_up 是在**完整**记录集里检索后续记录（典型是「失败之后出现成功」），
        # 这些后续记录本身不满足主 where，一旦按索引裁剪就会丢失关联。
        return []

    keys: list[tuple[str, str, Any, str]] = []
    for predicate in rule.where:
        if predicate.negate or len(predicate.fields) != 1:
            continue
        spec = predicate.fields[0]
        if spec.default:
            continue
        if predicate.op == "exists":
            keys.append(("exists", spec.field, "", spec.transform))
        elif predicate.op == "in_set" and predicate.normalized and spec.transform in KEY_TRANSFORMS:
            # `status in_set ["12","13","14"]` 是导入规则最常见的必要条件守卫。
            # 以前它不被认作索引键 → 106 条规则彻底没有键 → 每条记录都要跑一遍
            # （实测 11 MB 日志里 6.4M 次无效记录访问、约 11 秒）。
            # 值集合整体作为一个键：记录字段值落在集合内即为候选，语义与谓词完全一致。
            keys.append(
                (
                    "in_set",
                    spec.field,
                    tuple(predicate.normalized),  # type: ignore[arg-type]
                    spec.transform,
                )
            )
        elif (
            predicate.op == "equals"
            and predicate.ignore_case
            and predicate.normalized
            and spec.transform in KEY_TRANSFORMS
        ):
            # 带变换的 equals 同样能当必要条件：比较的是「变换后的值」，
            # 索引侧对记录做同一个变换再比即可，语义不变（`_transform` 是纯函数）。
            # 这解决了 web 规则的大头——URL 谓词本来是 `url` + `url_decode`，
            # 以前因为「带变换」被排除在索引外，只能退回 `exists` 弱键。
            keys.append(("equals", spec.field, predicate.normalized[0], spec.transform))
    return keys


class RuleIndex:
    """规则索引：把 `where` 里的一个必要条件提成分桶，跳过不可能匹配的规则。

    `where` 是 AND 语义，其中任一谓词不成立时规则必然不匹配，因此按它分桶
    **不改变任何判定结果**，只是把「每条记录跑全部规则」收敛成「只跑可能命中的规则」。

    键的优先级：`equals`（按值精确，区分度最高）> `exists`（只按字段有无）。
    同类键之间选**在本批规则中要求次数最少**的，要求越少越有区分度
    （例如 `url` 比 `source_ip` 稀有得多）。
    """

    def __init__(self, rules: list[Rule], uniform_log_type: str | None = None) -> None:
        # 单文件上传时整批记录类型一致，这时「规则是否适用于该类型」只需判一次，
        # 不必对着每条记录重复走 logsource_ok
        self._uniform_log_type = uniform_log_type
        candidates: dict[str, list[tuple[str, str, Any, str]]] = {}
        frequency: Counter[tuple[str, str, Any, str]] = Counter()
        for rule in rules:
            keys = _index_keys(rule)
            candidates[rule.id] = keys
            frequency.update(set(keys))

        self.key_of: dict[str, tuple[str, str, Any, str]] = {}
        for rule in rules:
            keys = candidates[rule.id]
            if not keys:
                continue
            exact = [key for key in keys if key[0] in ("equals", "in_set")]
            pool = exact or keys
            self.key_of[rule.id] = min(pool, key=lambda key: (frequency[key], key))
        self._cache: dict[tuple[str, str, Any, str], list[dict[str, str | None]]] = {}

    def records_for(
        self, rule: Rule, records: list[dict[str, str | None]]
    ) -> list[dict[str, str | None]]:
        """该规则需要检查的记录子集（同一个键只过滤一次）。"""

        if self._uniform_log_type is not None and not rule.logsource_ok(
            {"log_type": self._uniform_log_type}
        ):
            return []

        key = self.key_of.get(rule.id)
        if key is None:
            return records
        cached = self._cache.get(key)
        if cached is None:
            kind, name, value, transform = key
            if kind == "in_set":
                allowed = set(value)
                if transform == "none":
                    cached = [
                        record
                        for record in records
                        if (record.get(name) or "").lower() in allowed
                    ]
                else:
                    cached = [
                        record
                        for record in records
                        if _transform(record.get(name), transform).lower() in allowed
                    ]
            elif kind == "equals":
                if transform == "none":
                    cached = [
                        record
                        for record in records
                        if (record.get(name) or "").lower() == value
                    ]
                else:
                    # 与谓词侧用同一个变换，比较的是变换后的值（必要条件的语义不变）
                    cached = [
                        record
                        for record in records
                        if _transform(record.get(name), transform).lower() == value
                    ]
            else:
                cached = [record for record in records if record.get(name)]
            self._cache[key] = cached
        return cached


def evaluate_rules_with_coverage(
    records: list[dict[str, str | None]], rules: list[Rule] | None = None
) -> tuple[list[Event], set[str]]:
    """按规则声明顺序执行；返回（事件列表, 被任一启用规则命中的记录 ID 集合）。

    被 `suppresses` 声明的规则在同源事件成立时不再输出，但仍计入覆盖度——
    它确实对这一批记录做过判定。
    """

    active_rules = rules if rules is not None else load_rules()
    enabled_ids = frozenset(rule.id for rule in active_rules if rule.enabled)
    log_types = {record.get("log_type") or "" for record in records}
    uniform_log_type = log_types.pop() if len(log_types) == 1 else None
    index = RuleIndex(active_rules, uniform_log_type)
    events: list[Event] = []
    covered_ids: set[str] = set()
    suppressed: set[tuple[str, str]] = set()
    results: list[tuple[Rule, list[Event]]] = []
    for rule in active_rules:
        rule_events, rule_covered = evaluate_rule_with_coverage(
            rule, index.records_for(rule, records), enabled_ids
        )
        covered_ids |= rule_covered
        results.append((rule, rule_events))
        for event in rule_events:
            for target in rule.suppresses:
                suppressed.add((target, event.source_ip or ""))

    for rule, rule_events in results:
        for event in rule_events:
            if (rule.id, event.source_ip or "") in suppressed:
                continue
            events.append(event)
    return events, covered_ids


def evaluate_rules(
    records: list[dict[str, str | None]], rules: list[Rule] | None = None
) -> list[Event]:
    """按规则声明顺序执行；被 `suppresses` 声明的规则在同源事件成立时不再输出。"""

    return evaluate_rules_with_coverage(records, rules)[0]
