"""威胁情报富化：把研判中的公网指标（IP / 域名）送到公开情报库比对。

定位与硬约束（与 IOA 行为偏离同一条纪律）：
1. **独立展示，不进判定链**——查询结果不写入 `events`、不改变风险等级、不进入 AI 上下文。
   情报库的收录口径与日志证据是两回事，混进判定链会把第三方数据当成日志事实。
2. **默认关闭**——查询会把指标发送到外部服务，本地优先的工具必须由用户显式开启
   （`THREAT_INTEL_ENABLED=true`）。
3. **「未收录」不等于安全**——所有 not_listed 结果只表示「该库没有这条记录」，
   界面与报告都必须带这句话。
4. 只查**公网**指标：内网 IP / 常见域名后缀不外发（复用 IOA 层 2 白名单的口径）。

情报源：
- ThreatFox（abuse.ch，无需 key，支持 IP 与域名）
- URLhaus（abuse.ch，无需 key，支持主机名）
- AbuseIPDB（可选，需 `ABUSEIPDB_API_KEY`，仅 IP）
"""

from __future__ import annotations

import ipaddress
import json
import os
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable
from urllib import error, parse, request

from ..database import DATABASE_PATH
from ..models import AnalysisResult, sort_events_by_risk
from ..runtime_paths import env_files
from ..models import (
    ThreatIntelFinding,
    ThreatIntelReport,
    ThreatIntelSourceResult,
)
from .behavior_baseline import (
    COMMON_DOMAIN_SUFFIXES,
    NON_PUBLIC_SUFFIXES,
    PRIVATE_NETWORKS,
)

# ---------- 配置默认值（均可用 .env 覆盖） ----------
DEFAULT_MAX_INDICATORS = 15
DEFAULT_REQUEST_TIMEOUT = 6
DEFAULT_BUDGET_SECONDS = 30
DEFAULT_CACHE_TTL_HOURS = 24
DEFAULT_MAX_WORKERS = 6

_TRUE_VALUES = {"1", "true", "yes", "on"}

THREATFOX_URL = "https://threatfox.abuse.ch/api/v1/"
URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/host/"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
# AbuseIPDB 的恶意判定阈值：评分 0~100，30 以下只作为参考信息展示
ABUSEIPDB_HIT_SCORE = 30

# abuse.ch 系 API 要求带可识别的 User-Agent，否则可能被拒
_USER_AGENT = "AI-LogInsight/1.0 (local log analysis workbench)"


def _setting(name: str, default: str = "") -> str:
    """读取配置：环境变量优先，其次项目 .env（与 ai.py 同一套口径）。"""

    value = os.getenv(name)
    if value:
        return value
    for env_path in env_files():
        if not env_path.exists():
            continue
        for line in env_path.read_text(encoding="utf-8").splitlines():
            if line.strip().startswith(f"{name}="):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    return default


def _int_setting(name: str, default: int) -> int:
    try:
        value = int(_setting(name, str(default)).strip())
    except ValueError:
        return default
    return value if value > 0 else default


def is_enabled() -> bool:
    return _setting("THREAT_INTEL_ENABLED", "").strip().lower() in _TRUE_VALUES


# ---------- 指标提取 ----------


def _is_public_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    return not any(address in network for network in PRIVATE_NETWORKS)


def _is_queryable_domain(value: str) -> bool:
    """可外发查询的域名：有点号、非内网后缀、非常见厂商域名、不是 IP（公网/私网都不是域名）。"""

    domain = value.strip().lower().rstrip(".")
    if (
        not domain
        or len(domain) > 253
        or "." not in domain
        or domain.endswith(NON_PUBLIC_SUFFIXES)
    ):
        return False
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        pass
    else:
        return False
    if any(
        domain == suffix or domain.endswith(f".{suffix}")
        for suffix in COMMON_DOMAIN_SUFFIXES
    ):
        return False
    return all(char.isalnum() or char in "-._" for char in domain)


@dataclass
class Indicator:
    indicator_type: str  # "ip" | "domain"
    value: str
    origins: set[str] = field(default_factory=set)
    related_events: int = 0

    def key(self) -> tuple[str, str]:
        return (self.indicator_type, self.value)


def extract_indicators(
    result: AnalysisResult,
    records: list[dict[str, str | None]] | None = None,
    limit: int = DEFAULT_MAX_INDICATORS,
) -> list[Indicator]:
    """从分析结果提取可外发查询的公网指标。

    优先级：事件（按风险从高到低）→ 实体画像 → 原始记录。
    事件上的指标最有价值——它们已经是被规则标记过的线索；
    原始记录只补充事件之外的高频外联与 DNS 查询。
    超出上限时如实保留 `total`，由调用方写进报告（截断纪律：裁剪处必须给出总数）。
    """

    indicators: dict[tuple[str, str], Indicator] = {}

    def add(indicator_type: str, value: str | None, origin: str) -> None:
        if not value:
            return
        cleaned = value.strip()
        if indicator_type == "ip" and not _is_public_ip(cleaned):
            return
        if indicator_type == "domain" and not _is_queryable_domain(cleaned):
            return
        key = (indicator_type, cleaned)
        if key not in indicators:
            indicators[key] = Indicator(indicator_type, cleaned)
        entry = indicators[key]
        entry.origins.add(origin)

    # ① 事件：source_ip + 形如公网 IP 的 target_asset（主机侧日志没有来源 IP）
    for event in sort_events_by_risk(list(result.events)):
        add("ip", event.source_ip, "event")
        if event.target_asset:
            add("ip", event.target_asset, "event")
        if event.source_ip or event.target_asset:
            for key in (("ip", event.source_ip), ("ip", event.target_asset)):
                if key[1] and key in indicators:
                    indicators[key].related_events += 1

    # ② 实体画像：来源 / 目标 IP
    for entity in result.entities:
        if entity.kind in ("source_ip", "destination_ip"):
            add("ip", entity.value, "entity")

    # ③ 原始记录：目的 IP 与 DNS 查询（只补充事件之外的部分）
    for record in records or []:
        add("ip", record.get("destination_ip"), "record")
        add("domain", record.get("query_name"), "record")

    # 域名补充事件关联计数：事件证据里的 DNS 记录已由 query_name 覆盖，这里不重复统计

    ordered = sorted(
        indicators.values(),
        key=lambda item: (
            -item.related_events,  # 事件关联多的优先
            0 if "event" in item.origins else 1,  # 事件来源优先于实体 / 记录
            -len(item.origins),  # 多处出现的优先
            item.value,  # 稳定排序，保证同一份日志结果逐字一致
        ),
    )
    return ordered[:limit]


def indicators_total(
    result: AnalysisResult,
    records: list[dict[str, str | None]] | None = None,
) -> int:
    """去重后的指标总数（不截断），用于「已查询 N / 共 M」口径。"""

    return len(extract_indicators(result, records, limit=10**9))


# ---------- 情报源查询 ----------


def _post_json(url: str, payload: dict[str, str], headers: dict[str, str]) -> dict[str, Any]:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    http_request = request.Request(url, data=body, headers=headers, method="POST")
    with request.urlopen(http_request, timeout=_request_timeout()) as response:
        raw = response.read().decode("utf-8")
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise ValueError("响应不是 JSON 对象")
    return parsed


def _post_form(url: str, payload: dict[str, str], headers: dict[str, str]) -> dict[str, Any]:
    body = parse.urlencode(payload).encode("utf-8")
    http_request = request.Request(url, data=body, headers=headers, method="POST")
    with request.urlopen(http_request, timeout=_request_timeout()) as response:
        raw = response.read().decode("utf-8")
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise ValueError("响应不是 JSON 对象")
    return parsed


def _get_json(url: str, headers: dict[str, str]) -> dict[str, Any]:
    http_request = request.Request(url, headers=headers, method="GET")
    with request.urlopen(http_request, timeout=_request_timeout()) as response:
        raw = response.read().decode("utf-8")
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise ValueError("响应不是 JSON 对象")
    return parsed


def _request_timeout() -> float:
    return float(_int_setting("THREAT_INTEL_REQUEST_TIMEOUT", DEFAULT_REQUEST_TIMEOUT))


def query_threatfox(value: str) -> ThreatIntelSourceResult:
    """ThreatFox：恶意 IOC 库（IP / 域名）。query_status 无匹配时是 no_result。"""

    try:
        body = _post_json(
            THREATFOX_URL,
            {"query": "search_ioc", "search_term": value},
            {"User-Agent": _USER_AGENT, "Content-Type": "application/json"},
        )
    except (error.URLError, TimeoutError, ValueError, json.JSONDecodeError) as exc:
        return ThreatIntelSourceResult(
            source="ThreatFox", status="error", detail=f"查询失败：{exc}"
        )
    status = str(body.get("query_status", "")).lower()
    data = body.get("data")
    if status == "ok" and isinstance(data, list) and data:
        first = data[0] if isinstance(data[0], dict) else {}
        malware = str(first.get("malware_printable") or "未标注恶意软件家族")
        return ThreatIntelSourceResult(
            source="ThreatFox",
            status="hit",
            confidence=0.9,
            detail=f"收录为恶意 IOC（{malware}）",
            link=f"https://threatfox.abuse.ch/browse/ioc/{value}/",
        )
    if status in ("no_result", "no_results") or (status == "ok" and not data):
        return ThreatIntelSourceResult(
            source="ThreatFox", status="not_listed", detail="库中未收录"
        )
    return ThreatIntelSourceResult(
        source="ThreatFox", status="error", detail=f"响应状态异常：{status or '空'}"
    )


def query_urlhaus(value: str) -> ThreatIntelSourceResult:
    """URLhaus：恶意 URL / 主机库（域名 / IP）。query_status 无匹配时是 no_results。"""

    try:
        body = _post_form(
            URLHAUS_URL,
            {"host": value},
            {"User-Agent": _USER_AGENT},
        )
    except (error.URLError, TimeoutError, ValueError, json.JSONDecodeError) as exc:
        return ThreatIntelSourceResult(
            source="URLhaus", status="error", detail=f"查询失败：{exc}"
        )
    status = str(body.get("query_status", "")).lower()
    if status == "ok":
        reference = body.get("urlhaus_reference")
        urls = body.get("urls")
        count = len(urls) if isinstance(urls, list) else 0
        return ThreatIntelSourceResult(
            source="URLhaus",
            status="hit",
            confidence=0.9,
            detail=f"收录为恶意主机（关联 {count} 条恶意 URL）",
            link=str(reference) if reference else None,
        )
    if status in ("no_result", "no_results"):
        return ThreatIntelSourceResult(
            source="URLhaus", status="not_listed", detail="库中未收录"
        )
    return ThreatIntelSourceResult(
        source="URLhaus", status="error", detail=f"响应状态异常：{status or '空'}"
    )


def query_abuseipdb(value: str) -> ThreatIntelSourceResult:
    """AbuseIPDB：IP 举报库（仅 IP，需 API key）。未配置 key 时返回 skipped。"""

    api_key = _setting("ABUSEIPDB_API_KEY").strip()
    if not api_key:
        return ThreatIntelSourceResult(
            source="AbuseIPDB", status="skipped", detail="未配置 ABUSEIPDB_API_KEY"
        )
    try:
        body = _get_json(
            f"{ABUSEIPDB_URL}?ipAddress={parse.quote(value)}&maxAgeInDays=90",
            {"Key": api_key, "Accept": "application/json", "User-Agent": _USER_AGENT},
        )
    except (error.URLError, TimeoutError, ValueError, json.JSONDecodeError) as exc:
        return ThreatIntelSourceResult(
            source="AbuseIPDB", status="error", detail=f"查询失败：{exc}"
        )
    data = body.get("data")
    if not isinstance(data, dict):
        return ThreatIntelSourceResult(
            source="AbuseIPDB", status="error", detail="响应缺少 data 字段"
        )
    score = data.get("abuseConfidenceScore")
    if not isinstance(score, (int, float)):
        return ThreatIntelSourceResult(
            source="AbuseIPDB", status="error", detail="响应缺少 abuseConfidenceScore"
        )
    score = max(0, min(100, int(score)))
    if score >= ABUSEIPDB_HIT_SCORE:
        return ThreatIntelSourceResult(
            source="AbuseIPDB",
            status="hit",
            confidence=round(score / 100, 2),
            detail=f"举报置信度 {score}/100（≥{ABUSEIPDB_HIT_SCORE} 视为恶意）",
            link=f"https://www.abuseipdb.com/check/{value}",
        )
    return ThreatIntelSourceResult(
        source="AbuseIPDB",
        status="not_listed",
        detail=f"举报置信度 {score}/100（低于阈值 {ABUSEIPDB_HIT_SCORE}）",
        link=f"https://www.abuseipdb.com/check/{value}",
    )


def _providers_for(indicator_type: str) -> list[Callable[[str], ThreatIntelSourceResult]]:
    providers: list[Callable[[str], ThreatIntelSourceResult]] = [
        query_threatfox,
        query_urlhaus,
    ]
    if indicator_type == "ip":
        providers.append(query_abuseipdb)
    return providers


# ---------- 结果缓存 ----------


class ThreatIntelRepository:
    """查询结果缓存（全局按指标，不按分析）：同一指标短时间重复查询直接复用。"""

    def __init__(self, database_path: Path = DATABASE_PATH) -> None:
        self.database_path = database_path
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self.initialize()

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        return connection

    def initialize(self) -> None:
        with self.connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS threat_intel_cache (
                    indicator_type TEXT NOT NULL,
                    indicator TEXT NOT NULL,
                    source TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    fetched_at TEXT NOT NULL,
                    PRIMARY KEY (indicator_type, indicator, source)
                )
                """
            )
            connection.commit()

    def get_cached(
        self, indicator_type: str, indicator: str, source: str, ttl_hours: int
    ) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT payload, fetched_at FROM threat_intel_cache "
                "WHERE indicator_type = ? AND indicator = ? AND source = ?",
                (indicator_type, indicator, source),
            ).fetchone()
        if row is None:
            return None
        try:
            fetched_at = datetime.fromisoformat(row["fetched_at"])
            age_hours = (datetime.now().astimezone() - fetched_at).total_seconds() / 3600
        except ValueError:
            return None
        if age_hours > ttl_hours:
            return None
        try:
            payload = json.loads(row["payload"])
        except json.JSONDecodeError:
            return None
        return payload if isinstance(payload, dict) else None

    def store(
        self,
        indicator_type: str,
        indicator: str,
        source: str,
        payload: dict[str, Any],
    ) -> None:
        with self.connect() as connection:
            connection.execute(
                "INSERT OR REPLACE INTO threat_intel_cache "
                "(indicator_type, indicator, source, payload, fetched_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    indicator_type,
                    indicator,
                    source,
                    json.dumps(payload, ensure_ascii=False),
                    datetime.now().astimezone().isoformat(timespec="seconds"),
                ),
            )
            connection.commit()


threat_intel_repository = ThreatIntelRepository()


#: 进入 AI 上下文的最多指标条数：情报是线索不是证据，十来个足够，多了纯烧 token。
AI_CONTEXT_INDICATOR_LIMIT = 10


def cached_report(
    analysis_id: str,
    result: AnalysisResult,
    records: list[dict[str, str | None]] | None = None,
    repository: ThreatIntelRepository = threat_intel_repository,
) -> ThreatIntelReport:
    """只用**缓存**组装报告，绝不发起外部请求。

    存在的理由：AI 研判过程中不能偷偷访问外部服务。用户在界面上点「AI 研判」时
    并不知道这会向第三方发送 IP——本地优先的工具不允许这种隐藏副作用。
    因此研判只读已缓存的结果（即用户此前确实查询过的那部分），没查过就如实说明。
    """

    generated_at = datetime.now().astimezone().isoformat(timespec="seconds")
    ttl_hours = _int_setting("THREAT_INTEL_CACHE_TTL_HOURS", DEFAULT_CACHE_TTL_HOURS)
    selected = extract_indicators(
        result, records, limit=_int_setting("THREAT_INTEL_MAX_INDICATORS", DEFAULT_MAX_INDICATORS)
    )
    findings: list[ThreatIntelFinding] = []
    for indicator in selected:
        source_results: list[ThreatIntelSourceResult] = []
        for provider in _providers_for(indicator.indicator_type):
            source_name = provider.__name__.replace("query_", "")
            cached = repository.get_cached(
                indicator.indicator_type, indicator.value, source_name, ttl_hours
            )
            if cached is not None:
                source_results.append(ThreatIntelSourceResult(**cached))
        if source_results:
            finding = ThreatIntelFinding(
                indicator_type=indicator.indicator_type,  # type: ignore[arg-type]
                value=indicator.value,
                origins=sorted(indicator.origins),
                related_events=indicator.related_events,
                sources=source_results,
            )
            finding.summary = _summarize(finding)
            findings.append(finding)
    return ThreatIntelReport(
        analysis_id=analysis_id,
        enabled=is_enabled(),
        generated_at=generated_at,
        indicators_total=len(selected),
        findings=findings,
        note=(
            "仅含此前查询过的缓存结果，研判过程不发起外部请求"
            if findings
            else "本次没有已缓存的威胁情报结果（未查询或已过期）"
        ),
    )


# ---------- 富化主流程 ----------


def _summarize(finding: ThreatIntelFinding) -> str:
    hits = [item for item in finding.sources if item.status == "hit"]
    errors = [item for item in finding.sources if item.status == "error"]
    if hits:
        names = "、".join(item.source for item in hits)
        return f"{len(hits)} 个情报源（{names}）收录为恶意"
    if errors and len(errors) == len(finding.sources):
        return "全部情报源查询失败，本次无结论"
    if errors:
        return f"已查询来源均未收录（{len(errors)} 个来源查询失败）"
    return "已查询来源均未收录（未收录不等于安全）"


def enrich(
    analysis_id: str,
    result: AnalysisResult,
    records: list[dict[str, str | None]] | None = None,
    refresh: bool = False,
    repository: ThreatIntelRepository = threat_intel_repository,
) -> ThreatIntelReport:
    """对一份分析结果执行情报富化。默认关闭时返回带说明的空报告（不发请求）。"""

    generated_at = datetime.now().astimezone().isoformat(timespec="seconds")
    if not is_enabled():
        return ThreatIntelReport(
            analysis_id=analysis_id,
            enabled=False,
            generated_at=generated_at,
            note=(
                "威胁情报富化未开启：查询会把公网 IP / 域名发送到外部情报服务，"
                "在 .env 设置 THREAT_INTEL_ENABLED=true 后可用。"
            ),
        )

    max_indicators = _int_setting("THREAT_INTEL_MAX_INDICATORS", DEFAULT_MAX_INDICATORS)
    ttl_hours = _int_setting("THREAT_INTEL_CACHE_TTL_HOURS", DEFAULT_CACHE_TTL_HOURS)
    budget = _int_setting("THREAT_INTEL_BUDGET_SECONDS", DEFAULT_BUDGET_SECONDS)
    workers = _int_setting("THREAT_INTEL_MAX_WORKERS", DEFAULT_MAX_WORKERS)

    total = indicators_total(result, records)
    selected = extract_indicators(result, records, limit=max_indicators)
    note_parts: list[str] = []
    if total > len(selected):
        note_parts.append(
            f"共提取 {total} 个公网指标，按事件关联度展示并查询前 {len(selected)} 个"
            f"（上限可用 THREAT_INTEL_MAX_INDICATORS 调整）"
        )
    note_parts.append("「未收录」只表示该库没有记录，不等于安全；结果不参与风险定级。")

    findings: list[ThreatIntelFinding] = []
    errors: list[str] = []
    if not selected:
        return ThreatIntelReport(
            analysis_id=analysis_id,
            enabled=True,
            generated_at=generated_at,
            indicators_total=0,
            findings=[],
            note="本批日志没有可外发查询的公网指标（内网 IP 与常见域名不外发）。",
        )

    deadline = time.monotonic() + budget
    lock = threading.Lock()
    cache_hits = 0

    def query_indicator(indicator: Indicator) -> ThreatIntelFinding:
        nonlocal cache_hits
        source_results: list[ThreatIntelSourceResult] = []
        for provider in _providers_for(indicator.indicator_type):
            source_name = provider.__name__.replace("query_", "")
            cached = None if refresh else repository.get_cached(
                indicator.indicator_type, indicator.value, source_name, ttl_hours
            )
            if cached is not None:
                with lock:
                    cache_hits += 1
                source_results.append(ThreatIntelSourceResult(**cached))
                continue
            if time.monotonic() > deadline:
                source_results.append(
                    ThreatIntelSourceResult(
                        source=source_name,
                        status="skipped",
                        detail="超过本次查询总时长预算，未查询",
                    )
                )
                continue
            try:
                outcome = provider(indicator.value)
            except Exception as exc:  # 单个来源异常不允许拖垮整份报告
                outcome = ThreatIntelSourceResult(
                    source=source_name, status="error", detail=f"查询异常：{exc}"
                )
            repository.store(
                indicator.indicator_type,
                indicator.value,
                source_name,
                outcome.model_dump(),
            )
            source_results.append(outcome)
        finding = ThreatIntelFinding(
            indicator_type=indicator.indicator_type,  # type: ignore[arg-type]
            value=indicator.value,
            origins=sorted(indicator.origins),
            related_events=indicator.related_events,
            sources=source_results,
        )
        finding.summary = _summarize(finding)
        return finding

    with ThreadPoolExecutor(max_workers=workers) as pool:
        findings = list(pool.map(query_indicator, selected))

    for finding in findings:
        for item in finding.sources:
            if item.status == "error":
                errors.append(f"{finding.value} · {item.source}：{item.detail}")
    if cache_hits:
        note_parts.append(
            f"{cache_hits} 条结果来自 {ttl_hours} 小时内的缓存（refresh=true 可强制重查）"
        )

    return ThreatIntelReport(
        analysis_id=analysis_id,
        enabled=True,
        generated_at=generated_at,
        indicators_total=total,
        findings=findings,
        errors=errors[:20],
        note="；".join(note_parts),
    )
