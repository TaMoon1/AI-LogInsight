from __future__ import annotations

import re


_SENSITIVE_HEADER = re.compile(
    r"(?i)\b(authorization|proxy-authorization|cookie|set-cookie|x-api-key|api-key)"
    r"(\s*[:=]\s*)([^\s,;]+(?:\s+[^\s,;]+)?)"
)
_SENSITIVE_FIELD = re.compile(
    r"(?i)\b(password|passwd|pwd|token|access_token|refresh_token|api_key|secret|session)"
    r"(\s*[:=]\s*)([^\s,;&]+)"
)
_BEARER = re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._~+/=-]+")


def sanitize_text(value: str) -> str:
    """Redact common credential and session values before an AI request."""
    sanitized = _SENSITIVE_HEADER.sub(r"\1\2[REDACTED]", value)
    sanitized = _SENSITIVE_FIELD.sub(r"\1\2[REDACTED]", sanitized)
    return _BEARER.sub(r"\1 [REDACTED]", sanitized)


# 发给模型的记录样本字段白名单。记录本身有十几个字段，但单条样本真正有判定价值的
# 只有下面这些；空字段与「仅供本地排序/展示」的派生字段不进上下文。
# 需要「保留哪些信息」以日志类型区分，避免把 Sysmon 的进程/命令行等关键字段裁掉。
_RECORD_BASE_FIELDS = (
    "record_id",
    "evidence_id",
    "timestamp",
    "source_ip",
    "destination_ip",
    "destination_port",
    "source_port",
    "username",
    "target_asset",
    "hostname",
    "action",
    "result",
    "status",
    "url",
    "user_agent",
    "protocol",
    "event_id",
    "whitelisted_by",
)

# 终端 / Windows 事件类日志的专属字段（Sysmon、Windows Security 等）
_RECORD_TERMINAL_FIELDS = (
    "process",
    "process_id",
    "process_image",
    "command_line",
    "parent_image",
    "parent_process_id",
    "target_filename",
    "registry_key",
    "query_name",
    "hashes",
    "service_name",
    "service_file",
    "logon_type",
)

# 数据库日志的专属字段
_RECORD_DB_FIELDS = (
    "database",
    "db_user",
    "query",
    "client_ip",
    "error_code",
)

# 始终保留：原始日志原文是权威证据
_RECORD_RAW_FIELDS = ("raw", "message", "detail")

# 明确不带进上下文的字段：派生值（timestamp_iso 与 timestamp 同源）或超大且无判定价值
_RECORD_DROPPED_FIELDS = ("timestamp_iso", "correlation_basis")


def record_sample_fields(log_type: str | None) -> tuple[str, ...]:
    """按日志类型挑选样本字段白名单（顺序即输出顺序）。"""

    fields = list(_RECORD_BASE_FIELDS)
    if log_type in {"windows_evtx", "windows", "rdp", "windows_auth_export"}:
        fields.extend(_RECORD_TERMINAL_FIELDS)
    elif log_type in {"mysql", "postgres", "mongodb", "redis", "sqlserver", "oracle", "database"}:
        fields.extend(_RECORD_DB_FIELDS)
    else:
        # 类型未知或混合：终端与数据库字段都保留，宁可多一点也不要漏掉关键证据
        fields.extend(_RECORD_TERMINAL_FIELDS)
        fields.extend(_RECORD_DB_FIELDS)
    fields.extend(_RECORD_RAW_FIELDS)
    return tuple(fields)


def slim_records(
    records: list[dict[str, str | None]], log_type: str | None = None
) -> list[dict[str, str | None]]:
    """按白名单裁剪记录样本，并顺手脱敏。

    两个动作合并到一次遍历里完成：原先 `sanitize_records` 会为**全部**字段建新字典
    （包括空字段与派生字段），既是体积浪费也是复制开销。
    """

    allowed = record_sample_fields(log_type)
    dropped = set(_RECORD_DROPPED_FIELDS)
    slimmed: list[dict[str, str | None]] = []
    for record in records:
        item: dict[str, str | None] = {}
        for key in allowed:
            value = record.get(key)
            if value in (None, ""):
                continue
            if isinstance(value, str) and key in {"raw", "url", "message", "detail"}:
                value = sanitize_text(value)
            item[key] = value
        # 白名单外的自定义字段（解析器后续可能新增）仍保留，避免静默丢证据；
        # 只剔除明确无价值的派生字段。
        for key, value in record.items():
            if key in dropped or key in item or key in allowed:
                continue
            if value in (None, ""):
                continue
            item[key] = sanitize_text(value) if isinstance(value, str) else value
        slimmed.append(item)
    return slimmed


def sanitize_records(records: list[dict[str, str | None]]) -> list[dict[str, str | None]]:
    """向后兼容入口：只脱敏、不裁剪（保留原有语义）。"""

    return [
        {
            key: sanitize_text(value) if isinstance(value, str) and key in {"raw", "url", "message"} else value
            for key, value in record.items()
        }
        for record in records
    ]
