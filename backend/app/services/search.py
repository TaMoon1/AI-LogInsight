"""搜索语法：一句话里组合「字段:值 + 排除 + 全文」，一次定位到相关记录与事件。

参考 Zircolite 的搜索框（形如 `host:DC01 -EventID:4634 powershell`），适配本项目字段。

语法（全部大小写不敏感）：
- `字段:值`       —— 字段包含该值；支持 `source_ip:10.0.0.8`、`username:root`
- `-字段:值`      —— 排除（支持 `-powershell` 这种纯排除词）
- `"多词短语"`     —— 引号内按整体短语匹配，不会被拆成两个词
- `裸词`          —— 跨字段全文包含匹配

**刻意不做 SQL**：那是数据库客户端的形态，而本项目是「对一份日志做研判」的只读工作台。
真需要复杂聚合时，正确的扩展方向是加结构化接口（像 `/dashboard`、`/detections`），
而不是把任意 SQL 交给前端。

容错原则：**认不出的字段名不静默忽略**，而是记进 `warnings` 并退回「按全文匹配」——
静默忽略会让用户以为「查过了，没有」，实际是查询根本没生效。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..models import AnalysisResult, Event, LogRecord, SearchResult, SearchTerm

#: 可搜索字段（键为小写别名，值为记录里的真实键）
FIELD_ALIASES: dict[str, str] = {
    "source_ip": "source_ip",
    "src": "source_ip",
    "来源ip": "source_ip",
    "destination_ip": "destination_ip",
    "dst": "destination_ip",
    "目的ip": "destination_ip",
    "username": "username",
    "user": "username",
    "account": "username",
    "账号": "username",
    "status": "status",
    "状态码": "status",
    "action": "action",
    "动作": "action",
    "result": "result",
    "url": "url",
    "path": "url",
    "路径": "url",
    "query_name": "query_name",
    "dns": "query_name",
    "domain": "query_name",
    "域名": "query_name",
    "process": "process_image",
    "process_image": "process_image",
    "进程": "process_image",
    "command_line": "command_line",
    "cmd": "command_line",
    "命令行": "command_line",
    "target": "target_asset",
    "target_asset": "target_asset",
    "host": "target_asset",
    "hostname": "target_asset",
    "主机": "target_asset",
    "event_id": "event_id",
    "eventid": "event_id",
    "log_type": "log_type",
    "type": "log_type",
    "source_file": "source_file",
    "file": "source_file",
    "raw": "raw",
    "原文": "raw",
}

#: 全文匹配时拼接的字段（不含 raw：原文单独兜底，避免把整段原文复制进拼接串）
TEXT_FIELDS = (
    "source_ip", "destination_ip", "username", "action", "result", "status",
    "url", "destination_port", "protocol", "process_image", "command_line",
    "parent_image", "target_filename", "service_name", "registry_key",
    "query_name", "query_results", "target_asset", "event_id", "log_type",
    "source_file",
)

MAX_TERMS = 12
MAX_QUERY_LENGTH = 300


@dataclass
class ParsedQuery:
    terms: list[SearchTerm] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def parse_query(query: str) -> ParsedQuery:
    """把查询串拆成词项。空查询返回空词项（调用方据此提示「请输入查询条件」）。"""

    parsed = ParsedQuery()
    text = (query or "").strip()[:MAX_QUERY_LENGTH]
    if not text:
        return parsed

    for raw_token in _tokenize(text):
        token = raw_token.strip()
        if not token:
            continue
        if len(parsed.terms) >= MAX_TERMS:
            parsed.warnings.append(f"查询词过多，只取前 {MAX_TERMS} 个")
            break
        negated = token.startswith("-")
        if negated:
            token = token[1:].strip()
            if not token:
                continue
        field_name: str | None = None
        value = token
        if ":" in token:
            candidate, remainder = token.split(":", 1)
            key = candidate.strip().lower()
            if key in FIELD_ALIASES:
                field_name = FIELD_ALIASES[key]
                value = remainder.strip()
            else:
                # 认不出字段时退回「按值全文匹配」而不是拿整串去比：
                # 用户写 `sourceip:10.0.0.8` 的意图是查这个 IP，不是查字面量 "sourceip:10.0.0.8"。
                parsed.warnings.append(
                    f"认不出字段「{candidate}」，已按全文匹配「{remainder.strip() or token}」"
                )
                value = remainder.strip() or token
        value = value.strip().strip('"').strip("'")
        if not value:
            continue
        parsed.terms.append(
            SearchTerm(field=field_name, value=value, negated=negated)
        )
    return parsed


def _tokenize(text: str) -> list[str]:
    """按空格切词，但引号内的空格不切（`"failed password"` 是一个词项）。"""

    tokens: list[str] = []
    current: list[str] = []
    in_quotes = False
    for char in text:
        if char == '"':
            in_quotes = not in_quotes
            current.append(char)
            continue
        if char.isspace() and not in_quotes:
            if current:
                tokens.append("".join(current))
                current = []
            continue
        current.append(char)
    if current:
        tokens.append("".join(current))
    return tokens


def _field_text(record: dict[str, str | None], field_name: str) -> str:
    return str(record.get(field_name) or "")


def record_matches(record: dict[str, str | None], terms: list[SearchTerm]) -> bool:
    """所有词项都满足才算命中（词项之间是 AND，词项内的取反是 NOT）。"""

    for term in terms:
        if term.field:
            haystack = _field_text(record, term.field)
        else:
            haystack = " ".join(
                str(record.get(name) or "") for name in TEXT_FIELDS
            )
            haystack = f"{haystack} {str(record.get('raw') or '')}"
        hit = term.value.lower() in haystack.lower()
        if term.negated:
            hit = not hit
        if not hit:
            return False
    return True


def _event_text(event: Event) -> str:
    parts = [
        event.name,
        event.summary,
        event.rule_id or "",
        event.type,
        event.source_ip or "",
        event.target_asset or "",
        " ".join(event.source_files),
        " ".join(event.evidence),
    ]
    return " ".join(parts)


def event_matches(event: Event, terms: list[SearchTerm]) -> bool:
    haystack = _event_text(event)
    for term in terms:
        hit = term.value.lower() in haystack.lower()
        if term.negated:
            hit = not hit
        if not hit:
            return False
    return True


def search(
    analysis_id: str,
    result: AnalysisResult,
    records: list[dict[str, str | None]] | None,
    query: str,
    page: int = 1,
    page_size: int = 50,
) -> SearchResult:
    """在记录与事件上执行查询，返回分页结果与真实总数。

    结果同时给「匹配的记录」与「匹配的事件」：记录是原始事实，事件是规则结论，
    两者单位不同，各自给总数，不混成一个数字。
    """

    parsed = parse_query(query)
    all_records = records or []
    if not parsed.terms:
        return SearchResult(
            analysis_id=analysis_id,
            query=query,
            terms=parsed.terms,
            warnings=parsed.warnings + (["请输入查询条件"] if not query.strip() else []),
            records=[],
            records_total=0,
            events=[],
            events_total=0,
            page=page,
            page_size=page_size,
        )

    matched_records = [item for item in all_records if record_matches(item, parsed.terms)]
    total = len(matched_records)
    page_size = max(1, min(page_size, 200))
    start = (max(1, page) - 1) * page_size
    window = matched_records[start : start + page_size]

    matched_events = [item for item in result.events if event_matches(item, parsed.terms)]
    return SearchResult(
        analysis_id=analysis_id,
        query=query,
        terms=parsed.terms,
        warnings=parsed.warnings,
        records=[LogRecord(**item) for item in window],
        records_total=total,
        events=matched_events[:50],
        events_total=len(matched_events),
        page=max(1, page),
        page_size=page_size,
    )
