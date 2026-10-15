from __future__ import annotations

import bz2
import csv
import gzip
import io
import json
import re
import threading
import zipfile
import xml.etree.ElementTree as ET
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime

from . import evtx as evtx_service
from .evtx import EvtxUnavailableError
from .templates import mine_templates

SSH_FAILURE = re.compile(
    r"(?P<timestamp>^[A-Z][a-z]{2}\s+\d+\s+\S+).*?Failed password for "
    r"(?:invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)
SSH_SUCCESS = re.compile(
    r"(?P<timestamp>^[A-Z][a-z]{2}\s+\d+\s+\S+).*?Accepted \S+ for "
    r"(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)
# sshd 标准行头：`Mon DD HH:MM:SS 主机 程序[PID]:`（此前只取了时间戳，主机与程序被丢掉）
SSH_HEADER = re.compile(
    r"^[A-Z][a-z]{2}\s+\d+\s+\S+\s+(?P<host>\S+)\s+(?P<program>[A-Za-z0-9_.\-]+)"
    r"(?:\[(?P<pid>\d+)\])?:"
)
# 认证行尾部的来源端口：`... from 1.2.3.4 port 56789 ssh2`
SSH_PORT = re.compile(r"\bport (?P<port>\d+)\b")
WEB_PREFIX = re.compile(
    r"^(?P<ip>\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7})\s+"
    r"(?P<ident>\S+)\s+(?P<remote_user>\S+)\s+"
    r"\[(?P<timestamp>[^\]]+)\]\s*(?P<tail>.*)$"
)
# 访问日志的「无时间戳」变体：请求行紧跟 IP，时间由外层提供（syslog / 容器日志前缀）
WEB_PREFIX_NO_TIME = re.compile(
    r"^(?P<ip>\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7})\s+"
    r"(?P<ident>\S+)\s+(?P<remote_user>\S+)\s+"
    r"(?P<tail>\"[^\"]*\".*)$"
)
# combined 格式的状态行：`状态码 响应字节数 "Referer" "User-Agent"`
WEB_COMBINED_TAIL = re.compile(
    r"(?P<status>\d{3})\s+(?P<body_bytes_sent>\d+)\s+\"(?P<http_referer>[^\"]*)\""
)
# syslog / 容器日志前缀：ISO 时间戳 + 级别 + 主机 + 程序[PID]:
SYSLOG_PREFIX = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?"
    r"(?:Z|[+-]\d{2}:?\d{2})?)\s+(?P<level>[A-Z]+)\s+(?P<host>\S+)\s+"
    r"(?P<program>[A-Za-z0-9_.\-]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$"
)
# 应用日志消息内的键值字段映射（复用 FIREWALL_KEY_VALUE 提取）
SYSLOG_SOURCE_IP_KEYS = ("src_ip", "source_ip", "src", "client_ip")
SYSLOG_USERNAME_KEYS = ("user_id", "user", "username", "account")
SYSLOG_RESULT_KEYS = ("result", "outcome")
SYSLOG_URL_KEYS = ("endpoint", "url", "request", "uri")
# 进程与落地文件字段：syslog 内层消息与 Windows 事件键值导出共用。
# 这两类日志的"行为"往往就写在 Process= / ServiceFile= 里，不映射就等于没解析。
PROCESS_IMAGE_KEYS = ("process", "image", "processname", "process_name", "process_path")
PROCESS_ID_KEYS = ("pid", "processid", "process_id")
TARGET_FILENAME_KEYS = (
    "servicefile",
    "service_file",
    "targetfilename",
    "target_filename",
    "imagepath",
)
# 服务名与服务状态（Windows 事件 7036 / 7045）：防御规避类判据就写在这两个键上，
# 若不映射，「关键防护服务被停止」这类规则就没有任何可匹配的字段
SERVICE_NAME_KEYS = ("service", "servicename", "service_name", "servicedisplayname")
SERVICE_STATE_KEYS = ("state", "servicestate", "service_state")
# 应用层动词 → 统一动作语义。未列出的动词不映射成 action，避免把业务动作当成安全动作
SYSLOG_ACTION_VERBS = {
    "user_login": "login",
    "user_logout": "logout",
    "authentication_failure": "login",
    "authentication_success": "login",
}
WEB_VERSION = re.compile(r"^HTTP/?\d(?:\.\d)?$")
WEB_STATUS = re.compile(r"(?<![\w.])(?P<status>\d{3})(?![\w])")
WEB_TIMESTAMP_TOKENS = re.compile(
    r"(?P<day>\d{2})(?P<month>[A-Za-z]{3})(?P<year>\d{4})"
    r"(?P<hour>\d{2})(?P<minute>\d{2})(?P<second>\d{2})"
)

# Firewall / WAF 常见 syslog 键值格式，例如 SRC=10.0.0.8 DST=10.0.0.5
FIREWALL_KEY_VALUE = re.compile(
    r"\b(?P<key>[A-Za-z][A-Za-z0-9_-]*)=(?P<value>\"[^\"]*\"|\S+)"
)
# 事件查看器文本导出（`Log Name:` / `Event ID:` / `Account Name:` 分块）的 `键: 值` 行
COLON_KEY_VALUE = re.compile(
    r"^\s*(?P<key>[^:\n]{1,60}?)\s*:\s*(?P<value>.+?)\s*$", re.MULTILINE
)
FIREWALL_MARKERS = ("src=", "dst=", "proto=", "dpt=", "action=", "verdict=")

# ---------- 数据库日志（MySQL / PostgreSQL / MongoDB / Redis） ----------
# MySQL general log：`2026-09-17T10:00:00.000000Z\t1 Query\tSELECT ...`
MYSQL_GENERAL = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z)?)\s+"
    r"(?P<thread>\d+)\s+(?P<cmd>Query|Connect|Quit|Prepare|Execute|Close stmt|Init DB)\t"
    r"(?P<arg>.*)$",
    re.IGNORECASE,
)
MYSQL_ACCESS_DENIED = re.compile(
    r"Access denied for user '(?P<user>[^']+)'@'(?P<host>[^']+)'", re.IGNORECASE
)
MYSQL_ERR_TS = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?)Z?\s")

# PostgreSQL stderr 日志：`2026-09-17 10:00:00.123 CST [12345] [54321] LEVEL:  message`
PG_LOG = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?) \S+"
    r"(?: \[(?P<pid>\d+)\])?(?: \[(?P<conn>\d+)\])? (?P<level>[A-Z]+):\s*(?P<msg>.*)$"
)
PG_AUTH_FAIL = re.compile(
    r'password authentication failed for user "(?P<user>[^"]+)"', re.IGNORECASE
)
PG_STATEMENT = re.compile(r"statement:\s*(?P<sql>.*)$", re.IGNORECASE)

# Redis 日志：`1234:M 17 Sep 2026 10:00:00.123 * message`（日期在前，同 syslog）
REDIS_LOG = re.compile(
    r"^(?P<pid>\d+):(?P<role>[CSM]) (?P<ts>\d{1,2} [A-Z][a-z]{2} \d{4} "
    r"\d{2}:\d{2}:\d{2}\.\d+) (?P<level>[.*#-]) (?P<msg>.*)$"
)
REDIS_AUTH_FAIL = re.compile(r"Invalid (?:username|password)", re.IGNORECASE)

# MongoDB 明文 mongod 日志：`2026-09-17T10:00:00.123+0800 I ACCESS   [conn1] message`
MONGO_PLAIN = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?[+-]\d{4}) "
    r"(?P<sev>[IWEDF]) (?P<comp>[A-Z]+)\s+(?:\[(?P<ctx>[^\]]+)\] )?(?P<msg>.*)$"
)
MONGO_AUTH_FAIL = re.compile(r"[Ff]ailed to authenticate (\S+)@", re.IGNORECASE)
MONGO_AUTH_OK = re.compile(r"[Ss]uccessfully authenticated (\S+)@", re.IGNORECASE)

# SQL Server errorlog：`2026-09-17 10:00:00.00 Logon   Login failed for user 'sa' ... [CLIENT: 10.0.0.8]`
SQLSERVER_TS = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{2})\s+(?P<src>\S+)\s+(?P<msg>.*)$"
)
SQLSERVER_LOGIN_FAILED = re.compile(r"Login failed for user '(?P<user>[^']+)'", re.IGNORECASE)
SQLSERVER_LOGIN_SUCCESS = re.compile(r"Login succeeded for user '(?P<user>[^']+)'", re.IGNORECASE)
SQLSERVER_CLIENT = re.compile(r"\[CLIENT:\s*(?P<ip>[^\]]+)\]", re.IGNORECASE)
SQLSERVER_ERROR_18456 = re.compile(r"Error:\s*18456", re.IGNORECASE)

# Oracle alert.log：`Thu Sep 17 10:00:00 2026` + `ORA-01017: invalid username/password; logon denied`
ORACLE_TS = re.compile(
    r"^(?P<day>[A-Z][a-z]{2}) (?P<mon>[A-Z][a-z]{2}) (?P<d>\d{1,2}) "
    r"(?P<h>\d{2}):(?P<m>\d{2}):(?P<s>\d{2}) (?P<y>\d{4})$"
)
ORACLE_ERR = re.compile(r"ORA-(?P<code>\d{5})")

DB_TS_FORMATS = ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S")

# IIS（W3C 扩展日志格式）
IIS_FIELDS = re.compile(r"^#Fields:\s*(?P<fields>.+)$", re.IGNORECASE)
IIS_SOFTWARE_MARKERS = ("internet information services", "iis")
DEFAULT_IIS_FIELDS = (
    "date",
    "time",
    "s-ip",
    "cs-method",
    "cs-uri-stem",
    "cs-uri-query",
    "s-port",
    "cs-username",
    "c-ip",
    "cs(User-Agent)",
    "cs(Referer)",
    "sc-status",
    "sc-substatus",
    "sc-win32-status",
    "time-taken",
)

# Windows Security / RDP（事件查看器或 wevtutil 文本导出，字段可能带缩进）
WINDOWS_EVENT_ID = re.compile(r"Event ID[:：]\s*(?P<id>\d{3,5})", re.IGNORECASE)
WINDOWS_DATE = re.compile(
    r"^\s*(?:Date|Logged|日期|记录时间)[:：]\s*(?P<value>.+?)\s*$", re.MULTILINE
)
WINDOWS_ACCOUNT = re.compile(
    r"^\s*(?:Account Name|账户名|帐户名|New Logon:?\s*Account Name)[:：]\s*(?P<value>.+?)\s*$",
    re.MULTILINE,
)
WINDOWS_SOURCE_IP = re.compile(
    r"^\s*(?:Source Network Address|源网络地址)[:：]\s*(?P<value>.+?)\s*$", re.MULTILINE
)
WINDOWS_LOGON_TYPE = re.compile(
    r"^\s*(?:Logon Type|登录类型)[:：]\s*(?P<value>\d{1,2})", re.MULTILINE
)
WINDOWS_MARKERS = ("microsoft-windows-security-auditing", "event id:")
# Windows 事件日志的「键值化导出」：`时间 级别 主机 提供程序 EventID=N 键=值`
WINDOWS_EVENT_KV = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?"
    r"(?:Z|[+-]\d{2}:?\d{2})?)\s+(?P<level>[A-Z]+)\s+(?P<host>\S+)\s+"
    r"(?P<provider>[A-Za-z][A-Za-z0-9_.-]*)\s+EventID=(?P<event_id>\d{3,5})\b(?P<tail>.*)$"
)
# 只有时间戳、级别与残缺主机名（导出文件被截断的典型形态）
WINDOWS_TRUNCATED_PREFIX = re.compile(
    r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?"
    r"\s+[A-Z]+\s+\S*\s*$"
)
# EVTX XML 导出（事件查看器「另存为 XML」或 wevtutil 导出）
EVTX_XML_EVENT = re.compile(r"<Event\b.*?</Event>", re.DOTALL)
EVTX_XML_MARKERS = ("<eventid>", "<eventid ", "schemas.microsoft.com/win/2004/08/events")
WINDOWS_FAILURE_EVENT_IDS = {"4625"}
WINDOWS_SUCCESS_EVENT_IDS = {"4624"}
# 7 = 解锁/RemoteDesktop，10 = RemoteInteractive（RDP）
RDP_LOGON_TYPES = {"7", "10"}

_TIMESTAMP_FORMATS = (
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
    "%Y/%m/%d %H:%M:%S",
    "%m/%d/%Y %I:%M:%S %p",
    "%m/%d/%Y %H:%M:%S",
)

# 通用 JSON / CSV 事件：字段别名与取值归一化
STRUCTURED_LOG_TYPES = ("json", "csv")
STRUCTURED_CONTAINER_KEYS = ("events", "records", "logs", "items", "data", "results")
FIELD_ALIASES: dict[str, tuple[str, ...]] = {
    "timestamp": (
        "timestamp",
        "time",
        "@timestamp",
        "datetime",
        "date_time",
        "event_time",
        "eventtime",
        "ts",
        "时间",
    ),
    "source_ip": (
        "source_ip",
        "src_ip",
        "srcip",
        "src",
        "client_ip",
        "clientip",
        "remote_ip",
        "ip",
        "ip_address",
        "ipaddress",
        "source_address",
        "sourceaddress",
        "来源ip",
        "源ip",
        "源地址",
    ),
    "destination_ip": (
        "destination_ip",
        "dst_ip",
        "dstip",
        "dst",
        "dest_ip",
        "server_ip",
        "目的ip",
        "目的地址",
    ),
    "username": ("username", "user_name", "user", "account", "account_name", "账户", "用户名"),
    "action": ("action", "method", "event", "event_type", "eventtype", "operation", "动作"),
    "result": ("result", "outcome", "disposition", "结果"),
    "status": ("status", "status_code", "statuscode", "http_status", "code", "状态码"),
    "url": ("url", "uri", "path", "request", "request_uri", "requesturl", "路径"),
    "raw": ("raw", "message", "msg", "log", "原始日志"),
}
_ALIAS_LOOKUP = {
    alias: canonical for canonical, aliases in FIELD_ALIASES.items() for alias in aliases
}
SUCCESS_VALUES = {
    "success",
    "succeeded",
    "successful",
    "accepted",
    "accept",
    "allow",
    "allowed",
    "ok",
    "pass",
    "passed",
    "成功",
    "通过",
}
FAILURE_VALUES = {
    "failure",
    "failed",
    "fail",
    "deny",
    "denied",
    "drop",
    "dropped",
    "block",
    "blocked",
    "invalid",
    "reject",
    "rejected",
    "失败",
    "拒绝",
    "拦截",
}
LOGIN_ACTIONS = {"signin", "sign_in", "sign-in"}
AUTH_ACTIONS = {"login", "logon"}

# 值去重：同一份日志里 IP / User-Agent / URL / 状态码会反复出现，逐条新建字符串对象
# 会让内存随记录数线性放大（实测 2 MB / 1 万条时，这类重复值占记录内存近一半）。
# 让重复值共享同一个对象即可；只处理结构性字段，不含 raw / command_line 这类近乎唯一的正文。
POOLED_FIELDS = (
    "log_type",
    "source_file",
    "timestamp",
    "timestamp_iso",
    "source_ip",
    "destination_ip",
    "destination_port",
    "protocol",
    "target_asset",
    "username",
    "action",
    "result",
    "status",
    "url",
    "user_agent",
    "process_image",
    "process_id",
    "parent_image",
    "parent_process_id",
    "event_id",
    "service_name",
    "service_state",
)
# 单个字段的去重上限：取值种类过多时（如全唯一的 URL）去重表本身会变成新的负担
VALUE_POOL_LIMIT = 4096
_POOL_STATE = threading.local()


def reset_value_pool() -> None:
    """每次解析开始前重置去重表，避免上一次分析的字符串被滞留。"""

    _POOL_STATE.pools = None


def _share(record: dict[str, str | None]) -> dict[str, str | None]:
    """把记录里的结构性字段换成共享对象，就地在原字典上改并原样返回。

    必须在**构造时**调用（各解析分支建记录的那一行）：事后统一去重不影响峰值内存。
    """

    pools: dict[str, dict[str, str] | None] | None = getattr(_POOL_STATE, "pools", None)
    if pools is None:
        pools = {name: {} for name in POOLED_FIELDS}
        _POOL_STATE.pools = pools
    for name in POOLED_FIELDS:
        value = record.get(name)
        if not value:
            continue
        pool = pools[name]
        if pool is None:
            continue
        shared = pool.get(value)
        if shared is None:
            if len(pool) >= VALUE_POOL_LIMIT:
                pools[name] = None
                continue
            pool[value] = value
        elif shared is not value:
            record[name] = shared
    return record


def _named_fields(fields: dict[str, str | None]) -> dict[str, str]:
    """按日志格式**自带的字段名**原样收下全部取值（只保留有值的）。

    键值导出（`Key=Value` / `Key: Value`）、JSON / CSV、IIS W3C 的 `#Fields:` 这类格式
    自己就声明了字段名，把它们原样落进记录，规则才能按日志里的字段名做判据。
    只挑几个已知字段映射成规范字段、其余静默丢掉，等于把「模型外的字段」变成
    「不存在的字段」——规则要么被跳过、要么落成永远不命中的判据。
    """

    carried: dict[str, str] = {}
    for name, value in fields.items():
        cleaned = _clean_value(value)
        if cleaned is not None:
            carried[str(name)] = cleaned
    return carried


@dataclass
class ParsedLog:
    log_type: str
    confidence: float
    total_lines: int
    parsed_lines: int
    records: list[dict[str, str | None]]
    templates: list[dict[str, object]] = field(default_factory=list)
    # 未能解析的内容计数（行或事件条数）：用于在结论里如实说明检测覆盖不完整，
    # 避免把「没解析出来」当成「没有异常」。
    parse_failures: int = 0
    parse_errors: int = 0
    retention_drops: int = 0
    parse_error_details: list[dict[str, str | int | None]] = field(default_factory=list)


def detect_log_type(lines: list[str], text: str | None = None) -> tuple[str, float]:
    sample = "\n".join(lines[:100])
    full_text = text if text is not None else sample
    lowered = sample.lower()
    if (
        "#fields:" in lowered
        and ("cs-uri-stem" in lowered or "cs-method" in lowered)
    ) or ("s-ip" in lowered and any(marker in lowered for marker in IIS_SOFTWARE_MARKERS)):
        return "iis", 0.95
    if any(marker in lowered for marker in EVTX_XML_MARKERS) and "<event" in lowered:
        return "windows_evtx", 0.92
    if WINDOWS_EVENT_ID.search(sample) or any(
        marker in lowered for marker in WINDOWS_MARKERS
    ):
        return "windows_rdp", 0.9
    # 数据库日志（须在通用 JSON 之前：MongoDB 为结构化 JSON，需用专属特征区分）
    if _looks_like_mongodb(sample):
        return "mongodb", 0.92
    if _looks_like_mysql(sample):
        return "mysql", 0.9
    if _looks_like_postgres(sample):
        return "postgresql", 0.9
    if _looks_like_redis(sample):
        return "redis", 0.9
    if _looks_like_sqlserver(sample):
        return "sqlserver", 0.9
    if _looks_like_oracle(sample):
        return "oracle", 0.9
    # JSON 需要完整文本才能解析（缩进格式常超过前 100 行）
    if full_text.strip()[:1] in {"{", "["} and _looks_like_json(full_text):
        return "json", 0.88
    if _looks_like_csv(sample):
        return "csv", 0.85
    if _looks_like_firewall(sample):
        return "firewall_waf", 0.86
    if "Failed password" in sample or "Accepted password" in sample:
        return "ssh", 0.98
    # 放在 firewall / ssh 之后：带 ISO 前缀的防火墙日志仍按防火墙处理
    if _looks_like_windows_event(lines):
        return "windows_event", 0.9
    if _looks_like_syslog(lines):
        return "syslog", 0.9
    if any(_parse_web_line(line) for line in lines[:20]):
        return "nginx_apache", 0.9
    # 通用 XML 放最后：EVTX XML 已在上面按 windows_evtx 识别，这里只收其余可解析的 XML
    if full_text.lstrip()[:1] == "<" and _looks_like_xml(full_text):
        return "xml", 0.85
    return "generic", 0.35


# ---------- 数据库日志识别与解析 ----------

IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


def _db_ts(value: str | None) -> str | None:
    if not value:
        return None
    cleaned = value.strip().rstrip("Z")
    for fmt in DB_TS_FORMATS:
        try:
            return datetime.strptime(cleaned, fmt).isoformat()
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(value.strip().replace("Z", "+00:00")).isoformat()
    except ValueError:
        return None


def _extract_ip(value: str | None) -> str | None:
    if not value:
        return None
    match = IP_RE.search(value)
    return match.group(0) if match else value.strip()


def _parse_redis_timestamp(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return datetime.strptime(value, "%d %b %Y %H:%M:%S.%f").isoformat()
    except ValueError:
        return None


def _looks_like_mysql(sample: str) -> bool:
    for line in sample.splitlines():
        if MYSQL_GENERAL.match(line.strip()):
            return True
    return bool(MYSQL_ACCESS_DENIED.search(sample))


def _looks_like_postgres(sample: str) -> bool:
    hits = 0
    for line in sample.splitlines()[:40]:
        match = PG_LOG.match(line.strip())
        if match and match.group("level") in {"LOG", "FATAL", "ERROR", "STATEMENT", "WARNING", "DETAIL", "HINT"}:
            hits += 1
    return hits >= 1 and (
        "password authentication failed" in sample.lower()
        or hits >= 2
        or "statement:" in sample.lower()
    )


def _looks_like_mongodb(sample: str) -> bool:
    # JSON 结构化格式（mongod 4.4+ 默认）
    for line in sample.splitlines():
        stripped = line.strip()
        if not (stripped.startswith("{") and stripped.endswith("}")):
            continue
        try:
            obj = json.loads(stripped)
        except ValueError:
            continue
        if isinstance(obj, dict) and {"t", "s", "c", "msg"} <= obj.keys():
            return True
    # 明文 mongod 格式（旧版本 / 文本导出）
    hits = sum(1 for line in sample.splitlines()[:40] if MONGO_PLAIN.match(line.strip()))
    return hits >= 1


def _looks_like_redis(sample: str) -> bool:
    hits = 0
    for line in sample.splitlines()[:40]:
        if REDIS_LOG.match(line.strip()):
            hits += 1
    return hits >= 1


def _looks_like_sqlserver(sample: str) -> bool:
    lowered = sample.lower()
    if (
        "login failed for user" in lowered
        or "login succeeded for user" in lowered
        or "error: 18456" in lowered
    ):
        return True
    for line in sample.splitlines()[:40]:
        if SQLSERVER_TS.match(line.strip()):
            return True
    return False


def _looks_like_oracle(sample: str) -> bool:
    lowered = sample.lower()
    if "ora-" not in lowered:
        return False
    for line in sample.splitlines()[:40]:
        if ORACLE_TS.match(line.strip()):
            return True
    return False


def _parse_mysql_lines(lines: list[str]) -> list[dict[str, str | None]]:
    records: list[dict[str, str | None]] = []
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        general = MYSQL_GENERAL.match(stripped)
        if general:
            raw_cmd = general.group("cmd").lower()
            arg = general.group("arg").strip() or None
            ts = general.group("ts")
            action_map = {
                "query": "query",
                "prepare": "query",
                "execute": "query",
                "connect": "login",
                "quit": "quit",
                "init db": "connect",
                "close stmt": "event",
            }
            cmd = action_map.get(raw_cmd, "event")
            record: dict[str, str | None] = _share({
                "timestamp": ts,
                "timestamp_iso": _db_ts(ts),
                "source_ip": None,
                "destination_ip": None,
                "username": None,
                "action": cmd,
                "result": None,
                "status": None,
                "url": arg if cmd == "query" else None,
                "raw": stripped,
            })
            # 通用查询日志的 `线程号` 与 `命令` 是格式自带字段
            record.update(
                _named_fields(
                    {"thread": general.group("thread"), "command": general.group("cmd")}
                )
            )
            if raw_cmd == "connect" and arg:
                # `root@10.0.0.8 on db` → user / host
                host_part = arg.split(" on ", 1)[0].strip()
                if "@" in host_part:
                    user, host = host_part.split("@", 1)
                    record["username"] = _clean_value(user)
                    record["source_ip"] = _extract_ip(host)
                record["result"] = "success"
            records.append(record)
            continue

        denied = MYSQL_ACCESS_DENIED.search(stripped)
        if denied:
            ts_match = MYSQL_ERR_TS.search(stripped)
            ts = ts_match.group("ts") if ts_match else None
            records.append(
                _share({
                    "timestamp": ts,
                    "timestamp_iso": _db_ts(ts),
                    "source_ip": _extract_ip(denied.group("host")),
                    "destination_ip": None,
                    "username": _clean_value(denied.group("user")),
                    "action": "login",
                    "result": "failure",
                    "status": "Access denied",
                    "url": None,
                    "raw": stripped,
                })
            )
    return records


def _parse_postgres_lines(lines: list[str]) -> list[dict[str, str | None]]:
    records: list[dict[str, str | None]] = []
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        match = PG_LOG.match(stripped)
        if not match:
            continue
        ts = match.group("ts")
        level = match.group("level")
        msg = match.group("msg")
        record: dict[str, str | None] = _share({
            "timestamp": ts,
            "timestamp_iso": _db_ts(ts),
            "source_ip": None,
            "destination_ip": None,
            "username": None,
            "action": "event",
            "result": None,
            "status": level,
            "url": None,
            "raw": stripped,
        })
        # stderr 前缀里的 `[pid]` / `[连接号]` 是格式自带字段
        record.update(
            _named_fields({"pid": match.group("pid"), "connection_id": match.group("conn")})
        )
        auth_fail = PG_AUTH_FAIL.search(msg)
        statement = PG_STATEMENT.search(msg)
        if auth_fail:
            record["action"] = "login"
            record["result"] = "failure"
            record["username"] = _clean_value(auth_fail.group("user"))
        elif "connection authorized" in msg.lower():
            record["action"] = "login"
            record["result"] = "success"
            user_match = re.search(r"user=(\S+)", msg)
            if user_match:
                record["username"] = _clean_value(user_match.group(1))
            host_match = re.search(r"host=(\S+)", msg)
            if host_match:
                record["source_ip"] = _extract_ip(host_match.group(1))
        elif statement and statement.group("sql"):
            record["action"] = "query"
            record["url"] = _clean_value(statement.group("sql"))
        elif "connection received" in msg.lower():
            record["action"] = "connect"
        elif level in {"FATAL", "ERROR"}:
            record["action"] = "error"
        records.append(record)
    return records


def _mongo_plain_record(match: re.Match) -> dict[str, str | None] | None:
    """把明文 mongod 行映射为统一记录（ACCESS=认证、NETWORK=连接、其余=事件）。"""

    ts = match.group("ts")
    msg = match.group("msg")
    component = match.group("comp")
    record: dict[str, str | None] = _share({
        "timestamp": ts,
        "timestamp_iso": _db_ts(ts),
        "source_ip": None,
        "destination_ip": None,
        "username": None,
        "action": "event",
        "result": None,
        "status": match.group("sev"),
        "url": None,
        "raw": match.group(0).strip(),
    })
    if component == "ACCESS" or "authenticate" in msg.lower():
        record["action"] = "login"
        failed = MONGO_AUTH_FAIL.search(msg)
        ok = MONGO_AUTH_OK.search(msg)
        if failed:
            record["result"] = "failure"
            record["username"] = _clean_value(failed.group(1).split("@", 1)[0])
        elif ok:
            record["result"] = "success"
            record["username"] = _clean_value(ok.group(1).split("@", 1)[0])
        elif "failed" in msg.lower():
            record["result"] = "failure"
    elif component == "NETWORK" or "connection accepted from" in msg.lower():
        record["action"] = "connect"
        accepted = re.search(r"connection accepted from (\S+)", msg, re.IGNORECASE)
        if accepted:
            record["source_ip"] = _extract_ip(accepted.group(1))
    return record


def _parse_mongodb_lines(lines: list[str]) -> list[dict[str, str | None]]:
    """兼容两种 mongod 日志：结构化 JSON（4.4+）与明文（ISO 时间 + 严重级别 + 组件）。"""

    records: list[dict[str, str | None]] = []
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        plain = MONGO_PLAIN.match(stripped)
        if plain is not None:
            record = _mongo_plain_record(plain)
            if record:
                records.append(record)
            continue
        try:
            obj = json.loads(stripped)
        except ValueError:
            continue
        if not isinstance(obj, dict) or not {"t", "s", "c", "msg"} <= obj.keys():
            continue
        ts = obj["t"].get("$date") if isinstance(obj["t"], dict) else None
        msg = str(obj.get("msg") or "")
        attr = obj.get("attr") if isinstance(obj.get("attr"), dict) else {}
        username = attr.get("user") or attr.get("principalName")
        remote = attr.get("remote") or attr.get("ip")
        source_ip = _extract_ip(str(remote)) if remote else _extract_ip(msg)
        action = "event"
        result: str | None = None
        url: str | None = None
        structured: dict[str, str | None] = {
            key: value if isinstance(value, str) else None for key, value in obj.items()
        }
        structured.update({str(key): str(value) for key, value in attr.items()})
        lowered_msg = msg.lower()
        if "authentication" in lowered_msg or "authenticate" in lowered_msg:
            action = "login"
            if "succeeded" in lowered_msg or "successful" in lowered_msg:
                result = "success"
            elif "failed" in lowered_msg or "unsuccessful" in lowered_msg:
                result = "failure"
        elif "command" in lowered_msg or "operation" in lowered_msg:
            action = "query"
            command = attr.get("command") or attr.get("ns")
            url = str(command) if command else msg
        records.append(
            _share({
                "timestamp": ts,
                "timestamp_iso": _db_ts(ts),
                "source_ip": source_ip,
                "destination_ip": None,
                "username": _clean_value(str(username)) if username else None,
                "action": action,
                "result": result,
                "status": str(obj.get("s") or "") or None,
                "url": url,
                # mongod 4.4+ 结构化日志：顶层字段与 `attr` 都自带字段名
                **_named_fields(structured),
                "raw": stripped,
            })
        )
    return records


def _parse_redis_lines(lines: list[str]) -> list[dict[str, str | None]]:
    records: list[dict[str, str | None]] = []
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        match = REDIS_LOG.match(stripped)
        if not match:
            continue
        ts = match.group("ts")
        level = match.group("level")
        msg = match.group("msg")
        record: dict[str, str | None] = _share({
            "timestamp": ts,
            "timestamp_iso": _parse_redis_timestamp(ts),
            "source_ip": None,
            "destination_ip": None,
            "username": None,
            "action": "event",
            "result": None,
            "status": level,
            "url": None,
            "raw": stripped,
        })
        # 日志前缀里的 `pid:角色` 是格式自带字段
        record.update(_named_fields({"pid": match.group("pid"), "role": match.group("role")}))
        if REDIS_AUTH_FAIL.search(msg):
            record["action"] = "login"
            record["result"] = "failure"
            user_match = re.search(r"user '([^']+)'", msg, re.IGNORECASE)
            if user_match:
                record["username"] = user_match.group(1)
        elif "authenticated" in msg.lower() or "ready to accept" in msg.lower():
            record["action"] = "connect"
        records.append(record)
    return records


def _parse_sqlserver_lines(lines: list[str]) -> list[dict[str, str | None]]:
    records: list[dict[str, str | None]] = []
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        match = SQLSERVER_TS.match(stripped)
        if not match:
            continue
        ts = match.group("ts")
        msg = match.group("msg")
        record: dict[str, str | None] = _share({
            "timestamp": ts,
            "timestamp_iso": _db_ts(ts),
            "source_ip": None,
            "destination_ip": None,
            "username": None,
            "action": "event",
            "result": None,
            "status": None,
            "url": None,
            # SQL Server 错误日志前缀里的来源（`Server` / `Login`）是格式自带字段
            **_named_fields({"source": match.group("src")}),
            "raw": stripped,
        })
        client = SQLSERVER_CLIENT.search(msg)
        if client:
            record["source_ip"] = _extract_ip(client.group("ip"))
        failed = SQLSERVER_LOGIN_FAILED.search(msg)
        success = SQLSERVER_LOGIN_SUCCESS.search(msg)
        if failed:
            record["action"] = "login"
            record["result"] = "failure"
            record["username"] = _clean_value(failed.group("user"))
            record["status"] = "18456"
        elif success:
            record["action"] = "login"
            record["result"] = "success"
            record["username"] = _clean_value(success.group("user"))
        elif SQLSERVER_ERROR_18456.search(msg):
            record["action"] = "login"
            record["result"] = "failure"
            record["status"] = "18456"
        records.append(record)
    return records


def _parse_oracle_lines(lines: list[str]) -> list[dict[str, str | None]]:
    """Oracle alert.log：时间戳行后跟若干消息行，ORA-xxxxx 为错误码。"""

    records: list[dict[str, str | None]] = []
    current_ts: str | None = None
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        ts_match = ORACLE_TS.match(stripped)
        if ts_match:
            current_ts = f"{ts_match.group('mon')} {ts_match.group('d')} {ts_match.group('h')}:{ts_match.group('m')}:{ts_match.group('s')}"
            continue
        err = ORACLE_ERR.search(stripped)
        if not err:
            continue
        code = err.group("code")
        record: dict[str, str | None] = _share({
            "timestamp": current_ts,
            "timestamp_iso": _parse_ssh_timestamp(current_ts),
            "source_ip": None,
            "destination_ip": None,
            "username": None,
            "action": "event",
            "result": None,
            "status": f"ORA-{code}",
            "url": None,
            "raw": stripped,
        })
        if code in {"01017", "28000", "01005"}:
            record["action"] = "login"
            record["result"] = "failure"
        elif code in {"00600", "07445", "03113"}:
            record["action"] = "error"
        records.append(record)
    return records


def _parse_ssh_timestamp(value: str) -> str | None:
    try:
        parsed = datetime.strptime(
            f"{datetime.now().year} {value}", "%Y %b %d %H:%M:%S"
        )
    except ValueError:
        return None
    return parsed.isoformat()


def _parse_web_timestamp(value: str) -> str | None:
    """兼容 `16/Sep/2026:09:01:12 +0800` 与被剥离 `/` `:` 的 `16Sep2026090112 +0800`。"""

    token = value.split()[0] if value else ""
    match = WEB_TIMESTAMP_TOKENS.fullmatch(re.sub(r"[/:]", "", token))
    if not match:
        return None
    try:
        parsed = datetime.strptime(
            f"{match.group('day')} {match.group('month')} {match.group('year')} "
            f"{match.group('hour')}:{match.group('minute')}:{match.group('second')}",
            "%d %b %Y %H:%M:%S",
        )
    except ValueError:
        return None
    return parsed.isoformat()


def _parse_flexible_timestamp(value: str | None) -> str | None:
    if not value:
        return None
    cleaned = " ".join(value.split())
    for fmt in _TIMESTAMP_FORMATS:
        try:
            return datetime.strptime(cleaned, fmt).isoformat()
        except ValueError:
            continue
    try:
        # 兼容 JSON 事件常见的 ISO 8601（含时区）
        return datetime.fromisoformat(cleaned.replace("Z", "+00:00")).isoformat()
    except ValueError:
        return None


XLSX_MAIN_NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
AUTH_EXPORT_HEADERS = (
    "首次发现时间",
    "最近发现时间",
    "风险等级",
    "登录类型",
    "源IP",
    "登录用户",
    "服务类型",
    "影响资产",
    "资产状态",
    "发生次数",
    "处置状态",
    "处置方式",
    "事件ID",
)
# 缺这些列就不是「异常登录列表」，不能按同一套列名硬解
AUTH_EXPORT_REQUIRED_HEADERS = frozenset({"首次发现时间", "源IP", "影响资产"})


def _is_xlsx(content: bytes) -> bool:
    """只识别包含工作表的 OOXML 文件，不把任意 ZIP 当作 Excel。"""

    if not content.startswith(b"PK"):
        return False
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            names = set(archive.namelist())
            return "xl/workbook.xml" in names and "xl/worksheets/sheet1.xml" in names
    except (OSError, zipfile.BadZipFile):
        return False


def _xlsx_cell_value(cell: ET.Element, shared_strings: list[str]) -> str:
    cell_type = cell.attrib.get("t")
    if cell_type == "inlineStr":
        inline = cell.find(f"{{{XLSX_MAIN_NS}}}is")
        return "".join(inline.itertext()).strip() if inline is not None else ""
    value = cell.find(f"{{{XLSX_MAIN_NS}}}v")
    text = value.text if value is not None and value.text is not None else ""
    if cell_type == "s" and text.isdigit():
        index = int(text)
        return shared_strings[index] if index < len(shared_strings) else ""
    return text.strip()


def _xlsx_column(cell_ref: str) -> int:
    letters = re.match(r"[A-Za-z]+", cell_ref or "")
    if not letters:
        return 0
    value = 0
    for char in letters.group(0).upper():
        value = value * 26 + ord(char) - ord("A") + 1
    return value - 1


def _parse_windows_auth_export(
    content: bytes,
) -> tuple[list[dict[str, str | None]], int, list[dict[str, str | int | None]], int, bool]:
    """解析安全平台导出的域控异常登录列表 XLSX。

    这类文件是检测结果导出，不是原始 Windows 事件日志；因此保留
    `异常IP` / `异常时间` 标签，但不把它们强行转换成认证成功或失败。
    """

    details: list[dict[str, str | int | None]] = []
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            shared_strings: list[str] = []
            if "xl/sharedStrings.xml" in archive.namelist():
                root = ET.fromstring(archive.read("xl/sharedStrings.xml"))
                shared_strings = [
                    "".join(item.itertext()).strip()
                    for item in root.findall(f"{{{XLSX_MAIN_NS}}}si")
                ]
            sheet = ET.fromstring(archive.read("xl/worksheets/sheet1.xml"))
    except (OSError, zipfile.BadZipFile, ET.ParseError, KeyError) as exc:
        return [], 0, [{"line_number": 1, "reason": f"XLSX 解析失败：{exc}"}], 1, False

    rows = sheet.findall(f".//{{{XLSX_MAIN_NS}}}sheetData/{{{XLSX_MAIN_NS}}}row")
    row_values: list[tuple[int, dict[int, str]]] = []
    for row in rows:
        values = {
            _xlsx_column(cell.attrib.get("r", "")): _xlsx_cell_value(cell, shared_strings)
            for cell in row.findall(f"{{{XLSX_MAIN_NS}}}c")
        }
        row_values.append((int(row.attrib.get("r", "0") or 0), values))

    header_index = None
    header_map: dict[int, str] = {}
    known_headers = set(AUTH_EXPORT_HEADERS)
    for index, (row_number, values) in enumerate(row_values[:50]):
        matches = {column: value for column, value in values.items() if value in known_headers}
        # 只数「认识几列」是不够的：同一安全平台的其它导出（如安全事件总览）能对上
        # 首次发现时间 / 风险等级 / 影响资产 等 9 列，却没有「源IP」「登录用户」，
        # 于是表头判定通过、随后每一行都因缺列失败（实测 3.6 万条全灭）。
        # 这里要求必需列齐全，宁可判定为「不支持的表格」，也不要逐行报假失败。
        if len(matches) >= 5 and AUTH_EXPORT_REQUIRED_HEADERS.issubset(matches.values()):
            header_index = index
            header_map = matches
            break
    if header_index is None:
        return [], len(row_values), [{
            "line_number": 1,
            "reason": (
                "未找到域控异常登录列表表头：需要同时包含"
                + "、".join(AUTH_EXPORT_REQUIRED_HEADERS)
                + " 等列；请确认导出的是「异常登录列表」而不是其它报表"
            ),
        }], len(row_values), False

    records: list[dict[str, str | None]] = []
    failures = 0
    for row_number, values in row_values[header_index + 1 :]:
        if not any(value.strip() for value in values.values()):
            continue
        row = {header_map[column]: value.strip() for column, value in values.items() if column in header_map}
        first_seen = _clean_value(row.get("首次发现时间"))
        source_ip = _clean_value(row.get("源IP"))
        target_asset = _clean_value(row.get("影响资产"))
        if not first_seen or not source_ip or not target_asset:
            failures += 1
            if len(details) < 50:
                details.append({
                    "line_number": row_number,
                    "reason": "缺少首次发现时间、源IP或影响资产",
                    "raw_preview": " | ".join(f"{key}={value}" for key, value in row.items())[:240],
                })
            continue
        raw = " | ".join(f"{key}={row.get(key) or '-'}" for key in AUTH_EXPORT_HEADERS)
        records.append(_share({
            "timestamp": first_seen,
            "timestamp_iso": _parse_flexible_timestamp(first_seen),
            "source_ip": source_ip,
            "destination_ip": None,
            "username": _clean_account(row.get("登录用户")),
            "action": "auth_anomaly",
            "result": None,
            "status": None,
            "url": None,
            "target_asset": target_asset,
            "risk_level": _clean_value(row.get("风险等级")),
            "login_type": _clean_value(row.get("登录类型")),
            "service_type": _clean_value(row.get("服务类型")),
            "asset_status": _clean_value(row.get("资产状态")),
            "occurrence_count": _clean_value(row.get("发生次数")),
            "disposal_status": _clean_value(row.get("处置状态")),
            "disposal_method": _clean_value(row.get("处置方式")),
            "first_seen": first_seen,
            "last_seen": _clean_value(row.get("最近发现时间")),
            "vendor_event_id": _clean_value(row.get("事件ID")),
            "event_id": _clean_value(row.get("事件ID")),
            "raw": raw,
        }))
    return records, len(row_values) - header_index - 1, details, failures, True


def _match_field(name: str) -> str | None:
    normalized = name.strip().lstrip("\ufeff").lower().replace(" ", "_")
    return _ALIAS_LOOKUP.get(normalized)


def _normalize_result(value: str | None) -> str | None:
    cleaned = _clean_value(value)
    if cleaned is None:
        return None
    lowered = cleaned.lower()
    if lowered in SUCCESS_VALUES:
        return "success"
    if lowered in FAILURE_VALUES:
        return "failure"
    return cleaned


def _normalize_action(value: str | None) -> str | None:
    cleaned = _clean_value(value)
    if cleaned is None:
        return None
    lowered = cleaned.lower()
    if lowered in LOGIN_ACTIONS:
        return "login"
    if lowered in AUTH_ACTIONS:
        return lowered
    return cleaned


def _clean_value(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    if not stripped or stripped in {"-", "N/A", "n/a", "无"}:
        return None
    return stripped


def _clean_account(value: str | None) -> str | None:
    cleaned = _clean_value(value)
    if cleaned is None:
        return None
    if "\\" in cleaned:
        cleaned = cleaned.split("\\", 1)[1].strip()
    return cleaned or None


def _split_windows_blocks(lines: list[str]) -> list[list[str]]:
    """按空行切分事件块；事件内部存在空行时并入上一块，避免正文与事件头被拆开。"""

    raw_blocks: list[list[str]] = []
    current: list[str] = []
    for line in lines:
        if line.strip():
            current.append(line)
            continue
        if current:
            raw_blocks.append(current)
            current = []
    if current:
        raw_blocks.append(current)

    merged: list[list[str]] = []
    for block in raw_blocks:
        if merged and not WINDOWS_EVENT_ID.search("\n".join(block)):
            merged[-1].extend(block)
        else:
            merged.append(list(block))
    return merged


_WINDOWS_ACCOUNT_SECTIONS = (
    "Account For Which Logon Failed",
    "New Logon",
    "账户登录失败",
    "新登录",
)


def _windows_account(text: str) -> str | None:
    for marker in _WINDOWS_ACCOUNT_SECTIONS:
        position = re.search(marker, text, re.IGNORECASE)
        if not position:
            continue
        matches = WINDOWS_ACCOUNT.findall(text[position.end():])
        if matches:
            cleaned = _clean_account(matches[0])
            if cleaned:
                return cleaned
    matches = WINDOWS_ACCOUNT.findall(text)
    return _clean_account(matches[-1]) if matches else None


def _windows_source_ip(text: str) -> str | None:
    matches = WINDOWS_SOURCE_IP.findall(text)
    return _clean_value(matches[-1]) if matches else None


def _parse_iis_lines(lines: list[str]) -> list[dict[str, str | None]]:
    fields: tuple[str, ...] | None = None
    records: list[dict[str, str | None]] = []
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            fields_match = IIS_FIELDS.match(stripped)
            if fields_match:
                fields = tuple(fields_match.group("fields").split())
            continue

        columns = fields or DEFAULT_IIS_FIELDS
        parts = stripped.split()
        if len(parts) < len(columns):
            parts = parts + [None] * (len(columns) - len(parts))  # type: ignore[list-item]
        row = dict(zip(columns, parts))

        date = _clean_value(row.get("date"))
        time_value = _clean_value(row.get("time"))
        if not date or not time_value:
            continue

        status = _clean_value(row.get("sc-status"))
        if status and not status.isdigit():
            status = None

        url = _clean_value(row.get("cs-uri-stem")) or ""
        query = _clean_value(row.get("cs-uri-query"))
        if query:
            url = f"{url}?{query}"

        timestamp = f"{date} {time_value}"
        records.append(
            _share({
                # W3C 的 `#Fields:` 自己声明了列名，全部原样收下
                **_named_fields(row),
                "timestamp": timestamp,
                "timestamp_iso": _parse_flexible_timestamp(timestamp),
                "source_ip": _clean_value(row.get("c-ip")),
                "destination_ip": _clean_value(row.get("s-ip")),
                "username": _clean_account(row.get("cs-username")),
                "action": _clean_value(row.get("cs-method")),
                "result": None,
                "status": status,
                "url": url or None,
                "raw": stripped,
            })
        )
    return records


def _parse_evtx_xml(
    text: str,
) -> tuple[list[dict[str, str | None]], int, list[dict[str, str | int | None]]]:
    """解析事件查看器 / wevtutil 导出的 EVTX XML（纯文本，无二进制依赖）。

    返回（记录, 未能映射的事件条数, 失败详情）。无法映射的事件按条计数而不是静默
    丢弃，否则「日志里有攻击行为但没解析出来」会表现得和「没有异常」完全一样。
    """

    records: list[dict[str, str | None]] = []
    failures = 0
    details: list[dict[str, str | int | None]] = []
    for event_number, match in enumerate(EVTX_XML_EVENT.finditer(text), start=1):
        mapped = evtx_service.event_to_record(match.group(0))
        if mapped is None:
            failures += 1
            if len(details) < 50:
                details.append(
                    {
                        "line_number": event_number,
                        "reason": "XML 事件缺少 EventID 或无法映射",
                        "raw_preview": " ".join(match.group(0).split())[:240],
                    }
                )
            continue
        record, _is_auth = mapped
        records.append(record)
    return records, failures, details


def _parse_windows_blocks(lines: list[str]) -> list[dict[str, str | None]]:
    records: list[dict[str, str | None]] = []
    for block in _split_windows_blocks(lines):
        text = "\n".join(block)
        event_match = WINDOWS_EVENT_ID.search(text)
        if not event_match:
            continue
        event_id = event_match.group("id")
        if event_id in WINDOWS_FAILURE_EVENT_IDS:
            result = "failure"
        elif event_id in WINDOWS_SUCCESS_EVENT_IDS:
            result = "success"
        else:
            # 非认证事件（如 4825 远程桌面访问被拒）同样保留为明细记录：
            # 与 EVTX 路径保持一致，供 EventID 类规则与人工取证使用；
            # result 为空，因此不会进入认证成功 / 失败统计。
            result = None

        logon_type_match = WINDOWS_LOGON_TYPE.search(text)
        logon_type = logon_type_match.group("value") if logon_type_match else None
        if result is None:
            action = "event"
        else:
            action = "rdp_logon" if logon_type in RDP_LOGON_TYPES else "logon"
        date_match = WINDOWS_DATE.search(text)
        timestamp = _clean_value(date_match.group("value")) if date_match else None

        records.append(
            _share({
                # 事件查看器文本导出自带 `键: 值` 字段名（`Account Name` / `Logon Type` /
                # `Source Network Address` / `Process Name` …），全部原样收下
                **_named_fields(_colon_fields(text)),
                "timestamp": timestamp,
                "timestamp_iso": _parse_flexible_timestamp(timestamp),
                "source_ip": _windows_source_ip(text),
                "destination_ip": None,
                "username": _windows_account(text),
                "action": action,
                "result": result,
                "status": event_id,
                "url": None,
                "event_id": event_id,
                "raw": " | ".join(line.strip() for line in block if line.strip()),
            })
        )
    return records


def _parse_structured_records(
    payload: object, raw_fallback: str
) -> list[dict[str, str | None]]:
    """把 JSON / CSV 行对象映射到统一记录结构。"""

    if not isinstance(payload, dict):
        return []
    fields = {str(key): None if value is None else str(value) for key, value in payload.items()}
    record: dict[str, str | None] = {
        # 先收下 JSON / CSV 自带的全部字段名，再用规范字段覆盖同名键
        **_named_fields(fields),
        "timestamp": None,
        "timestamp_iso": None,
        "source_ip": None,
        "destination_ip": None,
        "username": None,
        "action": None,
        "result": None,
        "status": None,
        "url": None,
    }
    raw = raw_fallback
    matched = False
    for key, value in fields.items():
        canonical = _match_field(key)
        if canonical is None:
            continue
        if canonical == "raw":
            if _clean_value(value):
                raw = _clean_value(value) or raw
            continue
        cleaned = _clean_value(value)
        if cleaned is None:
            continue
        record[canonical] = cleaned
        matched = True
    if not matched:
        return []
    timestamp = record.get("timestamp")
    record["timestamp_iso"] = _parse_flexible_timestamp(timestamp)
    record["result"] = _normalize_result(record.get("result"))
    record["action"] = _normalize_action(record.get("action"))
    record["raw"] = raw or json.dumps(payload, ensure_ascii=False)
    return [record]


def _extract_json_events(text: str) -> list[dict] | None:
    stripped = text.strip()
    if not stripped:
        return None
    try:
        payload = json.loads(stripped)
    except ValueError:
        payload = None
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        for key in STRUCTURED_CONTAINER_KEYS:
            container = payload.get(key)
            if isinstance(container, list):
                return [item for item in container if isinstance(item, dict)]
        return [payload]

    # NDJSON：每行一个 JSON 对象
    events: list[dict] = []
    for line in stripped.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except ValueError:
            return None
        if not isinstance(item, dict):
            return None
        events.append(item)
    return events or None


def _looks_like_json(text: str) -> bool:
    stripped = text.strip()
    if not stripped or stripped[0] not in "{[":
        return False
    return _extract_json_events(stripped) is not None


def _parse_json_events(text: str) -> list[dict[str, str | None]]:
    events = _extract_json_events(text) or []
    records: list[dict[str, str | None]] = []
    for event in events:
        records.extend(
            _parse_structured_records(event, json.dumps(event, ensure_ascii=False))
        )
    return records


def _detect_delimiter(header: str) -> str | None:
    best: str | None = None
    best_score = 0
    for candidate in (",", ";", "\t", "|"):
        fields = [field.strip() for field in header.split(candidate)]
        if len(fields) < 2:
            continue
        score = sum(1 for field in fields if _match_field(field))
        if score >= 2 and score > best_score:
            best, best_score = candidate, score
    return best


def _csv_header_line(lines: list[str]) -> tuple[str, int] | None:
    for index, line in enumerate(lines[:20]):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        delimiter = _detect_delimiter(stripped)
        if delimiter:
            return delimiter, index
    return None


def _looks_like_csv(text: str) -> bool:
    lines = text.splitlines()
    return _csv_header_line(lines) is not None


def _parse_delimited_rows(text: str) -> list[dict[str, str | None]]:
    lines = text.splitlines()
    header_info = _csv_header_line(lines)
    if not header_info:
        return []
    delimiter, header_index = header_info
    reader = csv.reader(io.StringIO("\n".join(lines[header_index:])), delimiter=delimiter)
    rows = list(reader)
    if len(rows) < 2:
        return []
    headers = [header.lstrip("\ufeff").strip() for header in rows[0]]
    records: list[dict[str, str | None]] = []
    for row in rows[1:]:
        if not any(cell.strip() for cell in row):
            continue
        padded = row + [""] * (len(headers) - len(row))
        payload = {headers[index]: padded[index] for index in range(len(headers))}
        records.extend(_parse_structured_records(payload, delimiter.join(row)))
    return records


def _looks_like_xml(text: str) -> bool:
    """可被 ElementTree 完整解析才算 XML；只认开头不猜编码。"""

    try:
        ET.fromstring(text.strip())
    except ET.ParseError:
        return False
    return True


def _flatten_xml(elem: ET.Element, prefix: str = "", depth: int = 0):
    """把元素摊平成 (路径, 值)：叶子取文本、属性取键值、更深结构用 `父.子` 点路径。

    超过 3 层的嵌套不再下钻——通用 XML 没有标准结构，摊平过深只会产出没人引用的字段。
    """

    for key, value in elem.attrib.items():
        yield prefix + key, value.strip() or None
    for child in elem:
        path = f"{prefix}{child.tag}"
        if len(child) == 0:
            yield path, (child.text or "").strip() or None
        elif depth < 3:
            yield from _flatten_xml(child, path + ".", depth + 1)


def _parse_xml_events(
    text: str,
) -> tuple[list[dict[str, str | None]], int, list[dict[str, str | int | None]]]:
    """通用 XML：重复元素 = 记录，字段映射复用 `_parse_structured_records`。

    记录容器的选择：沿「唯一子元素」下钻到重复标签层（`<Log><Events><Event/>…` ）；
    找不到重复标签时，顶层每个子元素各成一条记录。识别阶段已确保文档可解析，
    这里只处理「解析成功但没有可识别字段」的记录——计入失败，不静默丢弃。
    """

    root = ET.fromstring(text.strip())
    container = root
    while len(container) == 1:
        container = container[0]
    tag_counts = Counter(child.tag for child in container)
    if tag_counts and tag_counts.most_common(1)[0][1] > 1:
        dominant = tag_counts.most_common(1)[0][0]
        record_elems = [child for child in container if child.tag == dominant]
    else:
        record_elems = list(container) or [container]

    records: list[dict[str, str | None]] = []
    failures = 0
    details: list[dict[str, str | int | None]] = []
    for index, elem in enumerate(record_elems, start=1):
        fields = dict(_flatten_xml(elem))
        parsed = _parse_structured_records(fields, ET.tostring(elem, encoding="unicode"))
        if parsed:
            records.extend(parsed)
        else:
            failures += 1
            details.append({"line": index, "error": "XML 记录缺少可识别字段"})
    return records, failures, details


def _firewall_fields(line: str) -> dict[str, str]:
    return {
        match.group("key").lower(): match.group("value").strip('"')
        for match in FIREWALL_KEY_VALUE.finditer(line)
    }


def _colon_fields(text: str) -> dict[str, str]:
    """取 `键: 值` 形态的字段（事件查看器文本导出 / 通用键值块）。"""

    return {
        match.group("key").strip(): match.group("value")
        for match in COLON_KEY_VALUE.finditer(text)
    }


def _looks_like_firewall(text: str) -> bool:
    for line in text.splitlines()[:100]:
        lowered = line.lower()
        fields = _firewall_fields(line)
        if {"src", "dst", "proto"} <= fields.keys():
            return True
        if sum(marker in lowered for marker in FIREWALL_MARKERS) >= 3:
            return True
    return False


def _parse_firewall_lines(lines: list[str]) -> list[dict[str, str | None]]:
    records: list[dict[str, str | None]] = []
    for line in lines:
        fields = _firewall_fields(line)
        source_ip = fields.get("src") or fields.get("src_ip")
        destination_ip = fields.get("dst") or fields.get("dst_ip")
        protocol = fields.get("proto") or fields.get("protocol")
        destination_port = fields.get("dpt") or fields.get("dst_port")
        if not source_ip or not destination_ip or not protocol or not destination_port:
            continue
        timestamp_match = re.match(r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\S+)", line)
        timestamp = timestamp_match.group("timestamp") if timestamp_match else None
        verdict = fields.get("action") or fields.get("verdict") or fields.get("decision")
        records.append(
            _share({
                # 防火墙/IPS 的键值对自带字段名（`src=` / `dpt=` / `rule=` / `verdict=` …），全部收下
                **_named_fields(fields),
                "timestamp": timestamp,
                "timestamp_iso": _parse_ssh_timestamp(timestamp) if timestamp else None,
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "username": None,
                "action": "network_connection",
                "result": _normalize_result(verdict),
                "status": verdict,
                "url": fields.get("url") or fields.get("request"),
                "destination_port": destination_port,
                "protocol": protocol.upper(),
                "raw": line,
            })
        )
    return records


def _looks_like_windows_event(lines: list[str]) -> bool:
    """Windows 事件日志的键值化导出：`时间 级别 主机 提供程序 EventID=N ...`。

    与 syslog 判定同样的自适应阈值：样本多时要求至少 3 行命中，样本很少时按实际行数要求。
    """

    sample = [line for line in lines[:50] if line.strip()]
    if not sample:
        return False
    matched = sum(1 for line in sample if WINDOWS_EVENT_KV.match(line))
    return matched >= min(3, len(sample))


def _windows_event_kv_reason(line: str) -> str:
    """区分「文件被截断」和「根本不是这个格式」——否则用户无从判断该修哪一头。"""

    if WINDOWS_TRUNCATED_PREFIX.match(line.strip()):
        return (
            "内容疑似被截断：只有时间戳、级别与部分主机名，"
            "缺少提供程序与 EventID（请确认导出文件是否完整）"
        )
    return "缺少 Windows 事件键值前缀（时间 级别 主机 提供程序 EventID=N）"


def _parse_windows_event_lines(
    lines: list[str],
) -> tuple[list[dict[str, str | None]], int, list[dict[str, str | int | None]]]:
    """解析 Windows 事件日志的键值化导出（`时间 级别 主机 提供程序 EventID=N 键=值`）。

    与「事件查看器文本导出」（`Log Name:` / `Event ID:` 分块）是两种形态，字段映射保持一致：
    4625 → 失败、4624 → 成功，其余事件的 result 留空（动作记为 `event`），
    因此不会混进「认证失败 / 成功」统计。
    """

    records: list[dict[str, str | None]] = []
    failures = 0
    details: list[dict[str, str | int | None]] = []
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        match = WINDOWS_EVENT_KV.match(line)
        if not match:
            failures += 1
            if len(details) < 50:
                details.append(
                    {
                        "line_number": line_number,
                        "reason": _windows_event_kv_reason(line),
                        "raw_preview": line.strip()[:240],
                    }
                )
            continue
        fields = _firewall_fields(line)
        event_id = match.group("event_id")
        if event_id in WINDOWS_FAILURE_EVENT_IDS:
            result: str | None = "failure"
        elif event_id in WINDOWS_SUCCESS_EVENT_IDS:
            result = "success"
        else:
            result = None
        logon_type = fields.get("logontype")
        timestamp = match.group("timestamp")
        records.append(
            _share({
                # 键值导出的每个 `键=值` 都自带字段名（`Process=` / `ServiceFile=` / `TargetUser=` …），全部收下
                **_named_fields(fields),
                "timestamp": timestamp,
                "timestamp_iso": _parse_flexible_timestamp(timestamp),
                "source_ip": _extract_ip(
                    fields.get("sourceaddress") or fields.get("ipaddress")
                ),
                "destination_ip": None,
                "username": fields.get("account"),
                "action": "event"
                if result is None
                else ("rdp_logon" if logon_type in RDP_LOGON_TYPES else "logon"),
                "result": result,
                "status": event_id,
                "url": None,
                # 行为字段：这两类键值导出把"谁做了什么"写在 Process= / ServiceFile= 里，
                # 只映射认证字段会让大量记录被判成「没有判据」
                "process_image": _syslog_field(fields, PROCESS_IMAGE_KEYS),
                "process_id": _syslog_field(fields, PROCESS_ID_KEYS),
                "target_filename": _syslog_field(fields, TARGET_FILENAME_KEYS),
                # 服务名与状态：7036 的"哪个服务被停了"是防御规避判据
                "service_name": _syslog_field(fields, SERVICE_NAME_KEYS),
                "service_state": _syslog_field(fields, SERVICE_STATE_KEYS),
                "event_id": event_id,
                "target_asset": match.group("host"),
                "raw": line,
            })
        )
    return records, failures, details


def _looks_like_syslog(lines: list[str]) -> bool:
    """ISO 时间戳 + 级别 + 主机 + 程序[PID]: 的 syslog / 容器前缀。

    样本多时要求至少 3 行命中（避免单行误判），样本很少时按实际行数要求，
    否则只有一两行的导出片段会被判成 generic。
    """

    sample = [line for line in lines[:50] if line.strip()]
    if not sample:
        return False
    matched = sum(1 for line in sample if SYSLOG_PREFIX.match(line))
    return matched >= min(3, len(sample))


def _syslog_field(fields: dict[str, str], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        value = fields.get(key)
        if value:
            return value
    return None


def _syslog_message_record(
    host: str, timestamp: str | None, timestamp_iso: str | None, message: str, raw: str
) -> dict[str, str | None]:
    """把应用层键值消息映射成统一记录；动词只映射已知的安全语义动作。"""

    fields = _firewall_fields(message)
    tokens = message.split()
    verb = tokens[0].lower() if tokens else ""
    return _share({
        # 应用层消息里的键值对自带字段名（`user=` / `service=` / `endpoint=` …），全部收下
        **_named_fields(fields),
        "timestamp": timestamp,
        "timestamp_iso": timestamp_iso,
        "source_ip": _syslog_field(fields, SYSLOG_SOURCE_IP_KEYS),
        "username": _syslog_field(fields, SYSLOG_USERNAME_KEYS),
        "action": SYSLOG_ACTION_VERBS.get(verb) or _normalize_action(fields.get("action")),
        "result": _normalize_result(_syslog_field(fields, SYSLOG_RESULT_KEYS)),
        "status": None,
        "url": _syslog_field(fields, SYSLOG_URL_KEYS),
        "process_image": _syslog_field(fields, PROCESS_IMAGE_KEYS),
        "process_id": _syslog_field(fields, PROCESS_ID_KEYS),
        "target_filename": _syslog_field(fields, TARGET_FILENAME_KEYS),
        "service_name": _syslog_field(fields, SERVICE_NAME_KEYS),
        "service_state": _syslog_field(fields, SERVICE_STATE_KEYS),
        "target_asset": host,
        "raw": raw,
    })


def _parse_syslog_lines(
    lines: list[str],
) -> tuple[list[dict[str, str | None]], int, list[dict[str, str | int | None]]]:
    """解析带 syslog / 容器前缀的日志：剥掉前缀后按内层内容分派。

    - 内层是访问日志 → 复用 Web 行解析（时间戳取自前缀），主机记为 `target_asset`；
    - 内层是键值消息（应用 / 认证 / 安全程序）→ 提取来源 IP、账户、结果与请求路径；
    - 前缀匹配成功即算解析成功：即使没有可判定字段也如实计入覆盖度，与「解析失败」区分开。

    只支持 ISO 时间戳前缀。经典 `Mon DD HH:MM:SS 主机 程序[PID]:` 形式的认证日志
    已由 SSH 解析处理，不在这里重复。
    """

    records: list[dict[str, str | None]] = []
    failures = 0
    details: list[dict[str, str | int | None]] = []
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        prefix = SYSLOG_PREFIX.match(line)
        if not prefix:
            failures += 1
            if len(details) < 50:
                details.append(
                    {
                        "line_number": line_number,
                        "reason": "缺少 syslog 前缀（时间 级别 主机 程序[PID]:）",
                        "raw_preview": line.strip()[:240],
                    }
                )
            continue
        timestamp = prefix.group("timestamp")
        timestamp_iso = _parse_flexible_timestamp(timestamp)
        message = prefix.group("message").strip()
        # 程序名与 PID 是 syslog 前缀自带的字段，随记录一起收下（否则只有主机名与消息）
        prefix_fields = _named_fields(
            {"program": prefix.group("program"), "pid": prefix.group("pid")}
        )
        web_record = _parse_web_line(message, timestamp, timestamp_iso)
        if web_record is not None:
            web_record["target_asset"] = prefix.group("host")
            web_record.update(prefix_fields)
            records.append(web_record)
            continue
        record = _syslog_message_record(
            prefix.group("host"), timestamp, timestamp_iso, message, line
        )
        record.update(prefix_fields)
        records.append(record)
    return records, failures, details


def parse_log(text: str) -> ParsedLog:
    reset_value_pool()
    lines = text.splitlines()
    log_type, confidence = detect_log_type(lines, text)
    parse_failures = 0
    parse_error_details: list[dict[str, str | int | None]] = []

    if log_type == "iis":
        records = _parse_iis_lines(lines)
    elif log_type == "windows_rdp":
        records = _parse_windows_blocks(lines)
    elif log_type == "windows_evtx":
        records, parse_failures, parse_error_details = _parse_evtx_xml(text)
    elif log_type == "mysql":
        records = _parse_mysql_lines(lines)
    elif log_type == "postgresql":
        records = _parse_postgres_lines(lines)
    elif log_type == "mongodb":
        records = _parse_mongodb_lines(lines)
    elif log_type == "redis":
        records = _parse_redis_lines(lines)
    elif log_type == "sqlserver":
        records = _parse_sqlserver_lines(lines)
    elif log_type == "oracle":
        records = _parse_oracle_lines(lines)
    elif log_type == "json":
        records = _parse_json_events(text)
    elif log_type == "csv":
        records = _parse_delimited_rows(text)
    elif log_type == "xml":
        records, parse_failures, parse_error_details = _parse_xml_events(text)
    elif log_type == "firewall_waf":
        records = _parse_firewall_lines(lines)
    elif log_type == "syslog":
        records, parse_failures, parse_error_details = _parse_syslog_lines(lines)
    elif log_type == "windows_event":
        records, parse_failures, parse_error_details = _parse_windows_event_lines(lines)
    else:
        records, parse_failures, parse_error_details = _parse_generic_lines(lines)

    return ParsedLog(
        log_type=log_type,
        confidence=confidence,
        total_lines=len(lines),
        parsed_lines=len(records),
        records=records,
        templates=mine_templates(text) if log_type == "generic" else [],
        parse_failures=parse_failures,
        # 文本日志没有单次保留上限，未纳入的记录一律是解析失败
        parse_errors=parse_failures,
        parse_error_details=parse_error_details,
    )


WEB_TRAILING_QUOTED = re.compile(r'"([^"]*)"\s*$')


def _web_user_agent(remainder: str) -> str | None:
    """取行尾最后一个引号字段作为 User-Agent（combined 格式里 UA 约定在最后）。

    用户白名单需要按 UA 放过可信扫描器 / 探针；此前项目不保留 UA，只能靠 raw 模糊匹配。
    """

    match = WEB_TRAILING_QUOTED.search(remainder)
    if not match:
        return None
    return match.group(1).strip() or None


def _parse_web_line(
    line: str,
    timestamp: str | None = None,
    timestamp_iso: str | None = None,
) -> dict[str, str | None] | None:
    """解析 Web 访问日志行；兼容标准 combined 格式、无引号格式和被剥离 `/` `:` 的脱敏格式。

    行内没有 `[时间]` 字段时（时间由外层 syslog / 容器前缀提供），用调用方传入的
    `timestamp` / `timestamp_iso` 补上。
    """

    stripped = line.strip()
    prefix = WEB_PREFIX.match(stripped)
    if prefix:
        timestamp = prefix.group("timestamp")
        timestamp_iso = _parse_web_timestamp(timestamp)
    else:
        prefix = WEB_PREFIX_NO_TIME.match(stripped)
        if not prefix:
            return None
    tail = prefix.group("tail").strip()
    if not tail:
        return None

    if tail.startswith('"'):
        closing = tail.find('"', 1)
        request = tail[1:closing] if closing != -1 else tail[1:]
        remainder = tail[closing + 1:] if closing != -1 else ""
    else:
        tokens = tail.split()
        version_index = next(
            (index for index, token in enumerate(tokens) if WEB_VERSION.match(token)),
            None,
        )
        request_end = version_index if version_index is not None else min(len(tokens), 3)
        request = " ".join(tokens[:request_end])
        remainder = " ".join(tokens[request_end:])

    request_tokens = request.split()
    if not request_tokens:
        return None
    method = request_tokens[0]
    version_index = next(
        (index for index, token in enumerate(request_tokens) if WEB_VERSION.match(token)),
        None,
    )
    url_tokens = (
        request_tokens[1:] if version_index is None else request_tokens[1:version_index]
    )
    url = " ".join(url_tokens).strip() or None
    status_match = WEB_STATUS.search(remainder)
    # combined 格式的状态行：补上标准里的响应字节数与 Referer
    combined = WEB_COMBINED_TAIL.search(remainder)

    return _share({
        "timestamp": timestamp,
        "timestamp_iso": timestamp_iso,
        "source_ip": prefix.group("ip"),
        "username": None,
        "action": method,
        "result": None,
        "status": status_match.group("status") if status_match else None,
        "url": url,
        "user_agent": _web_user_agent(remainder),
        # combined 格式自带、但此前没落进记录的字段（`-` 表示无值）
        "remote_user": _clean_value(prefix.group("remote_user")),
        "body_bytes_sent": combined.group("body_bytes_sent") if combined else None,
        "http_referer": _clean_value(combined.group("http_referer")) if combined else None,
        "raw": line,
    })


def _decode_text(content: bytes) -> str:
    try:
        return content.decode("utf-8")
    except UnicodeDecodeError:
        return content.decode("utf-8", errors="replace")


#: 压缩包支持的嵌套层数与解压后总大小上限（zip 炸弹防护）
ARCHIVE_MAX_DEPTH = 3
ARCHIVE_DECOMPRESSED_LIMIT = 256 * 1024 * 1024


def parse_upload(content: bytes) -> ParsedLog:
    """统一入口：支持压缩包（zip / gzip / bzip2）、EVTX、域控异常登录 XLSX、通用 XML 与文本日志。"""

    reset_value_pool()
    return _parse_upload_content(content, depth=0)


def _read_limited(reader, limit: int) -> bytes:
    """流式读取并强制大小上限，超限抛 ValueError（不把炸弹读进内存）。"""

    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = reader.read(1024 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > limit:
            raise ValueError("解压后超过大小上限")
        chunks.append(chunk)
    return b"".join(chunks)


def _decompress(content: bytes, factory) -> bytes:
    with factory(io.BytesIO(content)) as stream:
        return _read_limited(stream, ARCHIVE_DECOMPRESSED_LIMIT)


def _gzip_reader(fileobj):
    return gzip.GzipFile(fileobj=fileobj, mode="rb")


def _bzip2_reader(fileobj):
    return bz2.BZ2File(fileobj, mode="rb")


def _parse_upload_content(content: bytes, depth: int) -> ParsedLog:
    # XLSX 本质是 OOXML（ZIP 容器）：必须先按结构识别为 Excel，再考虑通用解压，
    # 否则会被当成「成员日志的压缩包」拆开
    if _is_xlsx(content):
        return _parse_upload_single(content)
    if depth < ARCHIVE_MAX_DEPTH and content[:2] == b"\x1f\x8b":
        try:
            return _parse_upload_content(_decompress(content, _gzip_reader), depth + 1)
        except (OSError, ValueError, EOFError):
            pass  # 魔数命中但解压失败：按文本走下面的兜底，让失败如实暴露
    if depth < ARCHIVE_MAX_DEPTH and content[:3] == b"BZh" and len(content) > 4:
        try:
            return _parse_upload_content(_decompress(content, _bzip2_reader), depth + 1)
        except (OSError, ValueError, EOFError):
            pass
    if (
        depth < ARCHIVE_MAX_DEPTH
        and content[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
    ):
        try:
            return _parse_zip(content, depth)
        except zipfile.BadZipFile:
            pass  # 同上：结构损坏按文本兜底
    return _parse_upload_single(content)


def _parse_upload_single(content: bytes) -> ParsedLog:
    if evtx_service.is_evtx(content):
        parse_error_details: list[dict[str, str | int | None]] = []
        try:
            records, total_events, parse_failures, retention_drops = (
                evtx_service.parse_evtx_records_detailed(
                    content, error_details=parse_error_details
                )
            )
        except TypeError as exc:
            # 兼容旧的测试替身和第三方调用方：旧签名仍可返回计数。
            if "error_details" not in str(exc):
                raise
            records, total_events, parse_failures, retention_drops = (
                evtx_service.parse_evtx_records_detailed(content)
            )
        return ParsedLog(
            log_type="windows_evtx",
            confidence=0.95,
            total_lines=total_events,
            parsed_lines=len(records),
            records=records,
            parse_failures=parse_failures + retention_drops,
            parse_errors=parse_failures,
            retention_drops=retention_drops,
            parse_error_details=parse_error_details,
        )
    if _is_xlsx(content):
        records, total_rows, details, failures, recognized = _parse_windows_auth_export(content)
        # 表头对不上时不能报「域控异常登录列表 0.97」——那是把不认识的表格硬套列名，
        # 会同时骗过用户（以为识别成功了）和覆盖度（以为只是内容有问题）。
        # 判定依据是**表头是否识别成功**，而不是「有没有解析出记录」：
        # 表头正确但数据行为空，仍属已识别格式。

        return ParsedLog(
            log_type="windows_auth_export" if recognized else "unsupported_xlsx",
            confidence=0.97 if recognized else 0.2,
            total_lines=total_rows,
            parsed_lines=len(records),
            records=records,
            parse_failures=failures,
            parse_errors=failures,
            parse_error_details=details,
        )
    return parse_log(_decode_text(content))


def _parse_zip(content: bytes, depth: int) -> ParsedLog:
    """zip 包：逐成员递归解析后合并；单个成员失败不拖垮整个包，但计入失败数。"""

    parsed: list[ParsedLog] = []
    member_names: list[str] = []
    skipped: list[str] = []
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            name = info.filename
            base = name.rsplit("/", 1)[-1]
            # 跳过 macOS 元数据目录与隐藏文件：它们不是日志，也不该计入失败
            if "__MACOSX" in name or base.startswith("."):
                continue
            try:
                with archive.open(info) as member:
                    data = _read_limited(member, ARCHIVE_DECOMPRESSED_LIMIT)
            except (zipfile.BadZipFile, ValueError, OSError, RuntimeError):
                skipped.append(name)
                continue
            if not data:
                continue
            try:
                parsed.append(_parse_upload_content(data, depth + 1))
                member_names.append(name)
            except EvtxUnavailableError:
                raise  # 与顶层行为一致：EVTX 支持缺失必须让用户知道，而不是吞进失败数
            except Exception:  # noqa: BLE001 - 成员级失败只计账，不影响其它成员
                skipped.append(name)
    # 多成员时给失败明细标注来源文件，否则「哪条失败」无从定位
    if len(parsed) > 1:
        for name, item in zip(member_names, parsed):
            for detail in item.parse_error_details:
                detail.setdefault("source", name)
    if not parsed:
        # 没有任何成员解析成功：按整个包的文本兜底，让失败如实暴露
        result = parse_log(_decode_text(content))
        result.parse_failures += len(skipped)
        result.parse_errors += len(skipped)
        result.parse_error_details.extend(
            {"line": None, "error": f"压缩包成员 {name} 未能解析"} for name in skipped
        )
        return result
    return _merge_parsed(parsed, skipped)


def _merge_parsed(parsed: list[ParsedLog], skipped: list[str]) -> ParsedLog:
    """多成员合并：记录拼接；类型取记录数最多的成员（并列取先出现者），
    confidence 取最低——如实反映「混合语料」的确定度。"""

    if len(parsed) == 1:
        merged = parsed[0]
    else:
        dominant_index = max(
            range(len(parsed)), key=lambda index: (len(parsed[index].records), -index)
        )
        head = parsed[dominant_index]
        merged = ParsedLog(
            log_type=head.log_type,
            confidence=min(item.confidence for item in parsed),
            total_lines=sum(item.total_lines for item in parsed),
            parsed_lines=sum(item.parsed_lines for item in parsed),
            records=[record for item in parsed for record in item.records],
            parse_failures=sum(item.parse_failures for item in parsed),
            parse_errors=sum(item.parse_errors for item in parsed),
            retention_drops=sum(item.retention_drops for item in parsed),
            parse_error_details=[
                detail for item in parsed for detail in item.parse_error_details
            ],
        )
    if skipped:
        merged.parse_failures += len(skipped)
        merged.parse_errors += len(skipped)
        merged.parse_error_details.extend(
            {"line": None, "error": f"压缩包成员 {name} 未能解析"} for name in skipped
        )
    return merged


def _parse_generic_lines(
    lines: list[str],
) -> tuple[list[dict[str, str | None]], int, list[dict[str, str | int | None]]]:
    """通用文本兜底：先按 SSH、再按 Web 行解析；返回（记录, 未能解析的非空行数）。"""

    records: list[dict[str, str | None]] = []
    failures = 0
    details: list[dict[str, str | int | None]] = []
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        match = SSH_FAILURE.search(line) or SSH_SUCCESS.search(line)
        if match:
            is_success = bool(SSH_SUCCESS.search(line))
            header = SSH_HEADER.match(line)
            sshd = _named_fields(
                {
                    "host": header.group("host") if header else None,
                    "program": header.group("program") if header else None,
                    "pid": header.group("pid") if header else None,
                }
            )
            port = SSH_PORT.search(line)
            if port:
                sshd["port"] = port.group("port")
            records.append(
                _share({
                    **sshd,
                    "timestamp": match.group("timestamp"),
                    "timestamp_iso": _parse_ssh_timestamp(match.group("timestamp")),
                    "source_ip": match.group("ip"),
                    "username": match.group("user"),
                    "action": "login",
                    "result": "success" if is_success else "failure",
                    "status": None,
                    "raw": line,
                })
            )
            continue

        web_record = _parse_web_line(line)
        if web_record:
            records.append(web_record)
        else:
            failures += 1
            if len(details) < 50:
                details.append(
                    {
                        "line_number": line_number,
                        "reason": "无法识别为已支持的日志记录",
                        "raw_preview": line.strip()[:240],
                    }
                )
    return records, failures, details


def count_values(
    records: list[dict[str, str | None]], field: str
) -> list[dict[str, int | str]]:
    values = Counter(record[field] for record in records if record.get(field))
    return [{"value": value, "count": count} for value, count in values.most_common(10)]
