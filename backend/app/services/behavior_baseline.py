"""IOA 行为偏离：没有命中任何已知攻击特征时，用「行为偏离」给出判断。

只做层 1（同批次低频实体）+ 层 2（内置白名单），不依赖跨批次历史；
口径一律写明为「与本批次相比首次出现」，不得表述为历史首次。
输出与 `events` 严格分离、不改变风险等级——完整说明见 `docs/ioa-behavior-baseline.md`。
"""

from __future__ import annotations

import ipaddress
from collections import Counter
from datetime import datetime, timezone
from urllib.parse import unquote, urlsplit

from ..models import BehaviorDeviation

MAX_DEVIATIONS = 20
EVIDENCE_LIMIT = 3

# 层 2：私有 / 保留网段。内网互访天然「首次出现」，但不是信号。
PRIVATE_NETWORKS = tuple(
    ipaddress.ip_network(item)
    for item in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "100.64.0.0/10",
        "0.0.0.0/8",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    )
)

# 层 2：常用端口。避免把正常业务端口当成「异常外联」。
# 刻意不含 8000/8081/8888/9000 这类开发与旁路端口：它们在企业终端上出现
# 恰恰是需要核实的信号（真实样本中的 C2 回连就走 8000）。
COMMON_PORTS = frozenset(
    {
        "20", "21", "22", "23", "25", "53", "67", "68", "69", "80", "88",
        "110", "123", "135", "137", "138", "139", "143", "161", "162", "389",
        "443", "445", "464", "465", "514", "515", "587", "593", "636", "873",
        "993", "995", "1080", "1194", "1433", "1521", "1701", "1723", "1812",
        "1900", "2049", "3128", "3268", "3269", "3306", "3389", "3478", "3690",
        "4505", "4506", "5060", "5432", "5601", "5672", "5900", "5984", "5985",
        "5986", "6379", "6443", "8080", "8443", "9092", "9200", "9300",
        "11211", "15672", "27017",
    }
)

# 层 2：常用域名后缀（系统更新 / 主流 CDN / 浏览器厂商 / CA-OCSP / 国内主流站点）。
COMMON_DOMAIN_SUFFIXES = (
    "windowsupdate.com", "microsoft.com", "msftncsi.com", "msftconnecttest.com",
    "windows.com", "live.com", "office.com", "office365.com", "sharepoint.com",
    "azure.com", "azureedge.net", "windowsazure.com", "visualstudio.com",
    "google.com", "gstatic.com", "googleapis.com", "googleusercontent.com",
    "googlesyndication.com", "youtube.com", "android.com",
    "apple.com", "icloud.com", "mzstatic.com", "cdn-apple.com",
    "mozilla.org", "mozilla.com", "firefox.com", "mozilla.net",
    "amazonaws.com", "cloudfront.net", "akamai.net", "akamaiedge.net",
    "akamaitechnologies.com", "edgekey.net", "edgesuite.net", "fastly.net",
    "cloudflare.com", "cloudflare.net", "cdnjs.com", "jsdelivr.net",
    "bootstrapcdn.com", "unpkg.com", "gstatic.cn",
    "adobe.com", "oracle.com", "java.com", "digicert.com", "verisign.com",
    "sectigo.com", "letsencrypt.org", "globalsign.com", "entrust.net",
    "aliyun.com", "aliyuncs.com", "alibaba.com", "taobao.com", "tmall.com",
    "alipay.com", "alicdn.com", "qcloud.com", "myqcloud.com", "tencent.com",
    "qq.com", "weixin.qq.com", "baidu.com", "bdstatic.com", "jingdong.com",
    "360.cn", "360.com", "sogou.com", "netease.com", "163.com",
    "github.com", "githubusercontent.com", "docker.com", "docker.io", "pypi.org",
    "python.org", "npmjs.com", "npmjs.org", "golang.org",
)

# 非公网域名后缀：内网解析不是外联信号。
NON_PUBLIC_SUFFIXES = (".local", ".lan", ".internal", ".arpa", ".home", ".corp", ".localdomain")

# 静态资源后缀：罕见路径里的静态资源不携带行为信息。
STATIC_ASSET_SUFFIXES = (
    ".css", ".js", ".mjs", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".ico", ".webp", ".bmp", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".webm",
)


# ---------- 时间维度偏离 ----------
# 非工作时段取 23:00-06:00。区间刻意收窄：日志时间戳不一定与服务器时区一致，
# 区间越宽，越容易把其它时区的正常白天活动误判成深夜活动。
OFF_HOURS_START = 23
OFF_HOURS_END = 6
# 同源高频突发：同一来源在 60 秒窗口内达到这么多条记录
BURST_WINDOW_SECONDS = 60
BURST_MIN_RECORDS = 30
# 峰值须达到其余来源中位数的该倍数，才认定为「突发」而非「整体都忙」
BURST_DOMINANCE_RATIO = 3
# 周期心跳：至少这么多个间隔，且间隔极差不超过该秒数（C2 beacon 的典型特征）
HEARTBEAT_MIN_INTERVALS = 5
HEARTBEAT_MIN_GAP_SECONDS = 5
HEARTBEAT_MAX_JITTER_SECONDS = 2
# 同一账号 / 来源 IP 至少要同时出现在工作时段和非工作时段，才认为发生时段变化。
TIME_SHIFT_MIN_RECORDS = 2
# 时间维度最多报几条，避免刷屏
MAX_TIME_DEVIATIONS = 3


def _is_public_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    return not any(address in network for network in PRIVATE_NETWORKS)


def _is_common_domain(value: str) -> bool:
    domain = value.strip().lower().rstrip(".")
    if not domain or "." not in domain or domain.endswith(NON_PUBLIC_SUFFIXES):
        return True
    return any(
        domain == suffix or domain.endswith(f".{suffix}")
        for suffix in COMMON_DOMAIN_SUFFIXES
    )


def _url_path(url: str | None) -> str | None:
    if not url:
        return None
    path = urlsplit(unquote(url)).path
    return path or None


def _is_static_asset(path: str) -> bool:
    return path.lower().endswith(STATIC_ASSET_SUFFIXES)


def _is_successful(record: dict[str, str | None]) -> bool:
    return str(record.get("status") or "").startswith("2") or record.get("result") == "success"


def _evidence(record: dict[str, str | None]) -> list[str]:
    raw = record.get("raw")
    return [raw] if raw else []


def _rare_destination_ips(records: list[dict[str, str | None]]) -> list[BehaviorDeviation]:
    counts: Counter[str] = Counter()
    first: dict[str, dict[str, str | None]] = {}
    for record in records:
        value = record.get("destination_ip")
        if not value or not _is_public_ip(value):
            continue
        counts[value] += 1
        first.setdefault(value, record)
    deviations: list[BehaviorDeviation] = []
    for value, count in counts.items():
        if count != 1:
            continue
        record = first[value]
        port = (record.get("destination_port") or "").strip()
        deviations.append(
            BehaviorDeviation(
                kind="rare_destination_ip",
                name="本批次首次出现的目的地址",
                basis="与本批次全部记录相比仅出现 1 次",
                detail=(
                    f"目的地址 {value} 在本批次内仅出现 1 次"
                    + (f"（端口 {port}）" if port else "")
                    + "，该地址不属于内网网段，需核实是否为已知业务目标。"
                ),
                count=1,
                evidence=_evidence(record),
            )
        )
    return deviations


def _rare_domain_queries(records: list[dict[str, str | None]]) -> list[BehaviorDeviation]:
    counts: Counter[str] = Counter()
    first: dict[str, dict[str, str | None]] = {}
    for record in records:
        value = record.get("query_name")
        if not value or _is_common_domain(value):
            continue
        counts[value] += 1
        first.setdefault(value, record)
    return [
        BehaviorDeviation(
            kind="rare_domain_query",
            name="本批次首次出现的域名解析",
            basis="与本批次全部记录相比仅出现 1 次",
            detail=(
                f"域名 {value} 在本批次内仅出现 1 次，且不在常用域名表内，"
                "需核实发起进程与解析用途。"
            ),
            count=1,
            evidence=_evidence(first[value]),
        )
        for value, count in counts.items()
        if count == 1
    ]


def _unusual_outbound_ports(records: list[dict[str, str | None]]) -> list[BehaviorDeviation]:
    counts: Counter[tuple[str, str]] = Counter()
    first: dict[tuple[str, str], dict[str, str | None]] = {}
    for record in records:
        address = record.get("destination_ip")
        port = (record.get("destination_port") or "").strip()
        if not address or not port or not _is_public_ip(address) or port in COMMON_PORTS:
            continue
        key = (address, port)
        counts[key] += 1
        first.setdefault(key, record)
    deviations: list[BehaviorDeviation] = []
    for (address, port), count in counts.items():
        deviations.append(
            BehaviorDeviation(
                kind="unusual_outbound_port",
                name="非常用端口外联",
                basis="目的端口不在常用端口表内",
                detail=(
                    f"向 {address}:{port} 外联 {count} 次，该端口不属于常用端口，"
                    "需核实是否为业务约定端口。"
                ),
                count=count,
                evidence=_evidence(first[(address, port)]),
            )
        )
    return deviations


def _rare_source_ips(records: list[dict[str, str | None]]) -> list[BehaviorDeviation]:
    counts: Counter[str] = Counter()
    first: dict[str, dict[str, str | None]] = {}
    for record in records:
        value = record.get("source_ip")
        # 只统计公网来源：内网地址只出现一次属正常（不同终端/用户），不构成偏离
        if not value or not _is_public_ip(value):
            continue
        counts[value] += 1
        first.setdefault(value, record)
    deviations: list[BehaviorDeviation] = []
    for value, count in counts.items():
        record = first[value]
        # 只出现一次且没有成功结果，说明不了什么；要求有 2xx / 成功登录才算偏离
        if count != 1 or not _is_successful(record):
            continue
        deviations.append(
            BehaviorDeviation(
                kind="rare_source_ip",
                name="低频来源地址",
                basis="与本批次全部记录相比仅出现 1 次",
                detail=(
                    f"来源 {value} 在本批次内仅出现 1 次且带成功结果"
                    f"（{record.get('action') or '-'} {record.get('url') or record.get('username') or '-'}），"
                    "需核实是否为已知业务来源。"
                ),
                count=1,
                evidence=_evidence(record),
            )
        )
    return deviations


def _rare_url_paths(records: list[dict[str, str | None]]) -> list[BehaviorDeviation]:
    web = [(record, _url_path(record.get("url"))) for record in records if record.get("url")]
    web = [(record, path) for record, path in web if path]
    if not web:
        return []
    counts: Counter[str] = Counter(path for _, path in web if path)
    # 高基数日志（路径几乎都唯一）里「唯一」不携带信息 → 整体抑制，避免刷屏
    if len(counts) * 2 > len(web):
        return []
    deviations: list[BehaviorDeviation] = []
    for record, path in web:
        if not path or counts[path] != 1 or _is_static_asset(path) or not _is_successful(record):
            continue
        deviations.append(
            BehaviorDeviation(
                kind="rare_url_path",
                name="罕见访问路径",
                basis="与本批次全部记录相比仅出现 1 次",
                detail=(
                    f"路径 {path} 在本批次内仅出现 1 次且返回成功状态，"
                    "需核实是否为正常业务访问。"
                ),
                count=1,
                evidence=_evidence(record),
            )
        )
    return deviations


def _record_time(record: dict[str, str | None]) -> datetime | None:
    value = record.get("timestamp_iso") or ""
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _time_evidence(records: list[dict[str, str | None]], limit: int = EVIDENCE_LIMIT) -> list[str]:
    return [item for record in records[:limit] for item in _evidence(record)]


def _time_sort_key(moment: datetime) -> float:
    """允许带时区和不带时区的日志时间在合并分析时稳定排序。"""

    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.timestamp()


def _timed_by_source(
    records: list[dict[str, str | None]],
) -> dict[str, list[tuple[datetime, dict[str, str | None]]]]:
    grouped: dict[str, list[tuple[datetime, dict[str, str | None]]]] = {}
    for record in records:
        moment = _record_time(record)
        if moment is None:
            continue
        key = record.get("source_ip") or record.get("target_asset") or ""
        if key:
            grouped.setdefault(key, []).append((moment, record))
    for items in grouped.values():
        items.sort(key=lambda pair: pair[0])
    return grouped


def _off_hours_activity(records: list[dict[str, str | None]]) -> list[BehaviorDeviation]:
    """日志时间戳落在深夜时段（未校准时区，属低置信度信号）。"""

    hits = [
        record
        for record in records
        if (moment := _record_time(record))
        and (moment.hour >= OFF_HOURS_START or moment.hour < OFF_HOURS_END)
    ]
    if not hits:
        return []
    hours = sorted({moment.hour for record in hits if (moment := _record_time(record))})
    span = "、".join(f"{hour:02d}" for hour in hours)
    return [
        BehaviorDeviation(
            kind="off_hours_activity",
            name="非工作时段活动",
            basis=f"按日志自带时间戳判定，落在 {OFF_HOURS_START}:00–{OFF_HOURS_END}:00；未校准日志时区",
            detail=(
                f"本批次有 {len(hits)} 条记录发生在 {span} 时，"
                "需确认属于正常运维、跨时区业务，还是异常时段操作。"
            ),
            count=len(hits),
            evidence=_time_evidence(hits),
        )
    ]


def _entity_time_shift(records: list[dict[str, str | None]]) -> list[BehaviorDeviation]:
    """同一账号或来源 IP 在本批次内跨越工作 / 非工作时段。"""

    grouped: dict[tuple[str, str], list[tuple[datetime, dict[str, str | None], bool]]] = {}
    for record in records:
        moment = _record_time(record)
        if moment is None:
            continue
        off_hours = moment.hour >= OFF_HOURS_START or moment.hour < OFF_HOURS_END
        entities = []
        if record.get("username"):
            entities.append(("account", str(record["username"])))
        if record.get("source_ip"):
            entities.append(("source_ip", str(record["source_ip"])))
        for kind, value in entities:
            grouped.setdefault((kind, value), []).append((moment, record, off_hours))

    deviations: list[BehaviorDeviation] = []
    for (kind, value), items in grouped.items():
        if len(items) < TIME_SHIFT_MIN_RECORDS:
            continue
        working = [item for item in items if not item[2]]
        off_hours = [item for item in items if item[2]]
        if not working or not off_hours:
            continue
        ordered = sorted(items, key=lambda item: _time_sort_key(item[0]))
        first = ordered[0][0].isoformat()
        last = ordered[-1][0].isoformat()
        label = "账号" if kind == "account" else "来源 IP"
        deviations.append(
            BehaviorDeviation(
                kind="entity_time_shift",
                name=f"{label}活动时段变化",
                basis=(
                    f"同一{label}同时出现在工作时段和非工作时段；"
                    f"非工作时段定义为 {OFF_HOURS_START}:00–{OFF_HOURS_END}:00"
                ),
                detail=(
                    f"{label} {value} 在本批次内同时出现在工作时段和非工作时段，"
                    f"时间范围 {first} 至 {last}，共 {len(items)} 条记录；"
                    "需核实是否为正常轮班、跨时区业务或异常时段活动。"
                ),
                count=len(items),
                evidence=_time_evidence([record for _, record, _ in ordered]),
            )
        )
    deviations.sort(key=lambda item: -item.count)
    return deviations[:MAX_TIME_DEVIATIONS]


def _burst_activity(records: list[dict[str, str | None]]) -> list[BehaviorDeviation]:
    """同一来源在短窗口内的高频活动（压测、批量任务与暴力尝试都可能呈现此形态）。

    判据要求「有对照」：只有本批次存在多个来源、且某个来源的峰值显著高于其余来源时才算突发。
    单来源日志（批量导出、时间压缩的合成日志）没有比较基准，报出来只是噪声。
    """

    peaks: list[tuple[str, int, int, list[tuple[datetime, dict[str, str | None]]]]] = []
    for key, items in _timed_by_source(records).items():
        times = [moment for moment, _ in items]
        left = 0
        peak = 0
        peak_start = 0
        for right in range(len(times)):
            while (times[right] - times[left]).total_seconds() > BURST_WINDOW_SECONDS:
                left += 1
            if right - left + 1 > peak:
                peak = right - left + 1
                peak_start = left
        peaks.append((key, peak, peak_start, items))
    if len(peaks) < 2:
        return []

    ordered = sorted(peak for _, peak, _, _ in peaks)
    baseline = ordered[len(ordered) // 2]

    deviations: list[BehaviorDeviation] = []
    for key, peak, peak_start, items in peaks:
        if peak < BURST_MIN_RECORDS or peak < baseline * BURST_DOMINANCE_RATIO:
            continue
        window_records = [record for _, record in items[peak_start : peak_start + peak]]
        deviations.append(
            BehaviorDeviation(
                kind="burst_activity",
                name="同源高频突发",
                basis=(
                    f"同一来源在 {BURST_WINDOW_SECONDS} 秒滑窗内达到 {BURST_MIN_RECORDS} 条，"
                    f"且不低于其余来源中位数的 {BURST_DOMINANCE_RATIO} 倍"
                ),
                detail=(
                    f"来源 {key} 在 {BURST_WINDOW_SECONDS} 秒内出现 {peak} 条记录，"
                    "明显高于本批次其它来源，需核实是压测、批量任务还是异常高频行为。"
                ),
                count=peak,
                evidence=_time_evidence(window_records),
            )
        )
    deviations.sort(key=lambda item: -item.count)
    return deviations[:MAX_TIME_DEVIATIONS]


def _periodic_heartbeat(records: list[dict[str, str | None]]) -> list[BehaviorDeviation]:
    """间隔高度规整的周期性外联——C2 beacon 的典型特征，正常业务较少如此规整。"""

    deviations: list[BehaviorDeviation] = []
    for key, items in _timed_by_source(records).items():
        times = [moment for moment, _ in items]
        if len(times) < HEARTBEAT_MIN_INTERVALS + 1:
            continue
        gaps = [
            (current - previous).total_seconds()
            for previous, current in zip(times, times[1:])
        ]
        # 同秒内的密集记录不是心跳，是批量写入
        if min(gaps) < HEARTBEAT_MIN_GAP_SECONDS:
            continue
        if max(gaps) - min(gaps) > HEARTBEAT_MAX_JITTER_SECONDS:
            continue
        average = sum(gaps) / len(gaps)
        deviations.append(
            BehaviorDeviation(
                kind="periodic_heartbeat",
                name="周期性心跳外联",
                basis=(
                    f"同一来源连续 {len(gaps)} 个间隔的极差不超过 "
                    f"{HEARTBEAT_MAX_JITTER_SECONDS} 秒"
                ),
                detail=(
                    f"来源 {key} 的活动间隔高度规整（约 {average:.0f} 秒一次，共 {len(times)} 次），"
                    "这种规律性常见于心跳式外联，也可能是固定周期的采集任务，需结合实际业务核实。"
                ),
                count=len(times),
                evidence=_time_evidence([record for _, record in items]),
            )
        )
    deviations.sort(key=lambda item: -item.count)
    return deviations[:MAX_TIME_DEVIATIONS]


def build_behavior_deviations(
    records: list[dict[str, str | None]],
) -> list[BehaviorDeviation]:
    """按重要性顺序汇总行为偏离；上限 MAX_DEVIATIONS 防止刷屏。"""

    if not records:
        return []
    deviations: list[BehaviorDeviation] = []
    deviations += _rare_destination_ips(records)
    deviations += _rare_domain_queries(records)
    deviations += _unusual_outbound_ports(records)
    deviations += _rare_source_ips(records)
    deviations += _rare_url_paths(records)
    # 时间维度放在最后：它们是低置信度信号，不应挤掉实体类偏离
    deviations += _off_hours_activity(records)
    deviations += _entity_time_shift(records)
    deviations += _burst_activity(records)
    deviations += _periodic_heartbeat(records)
    for item in deviations:
        item.evidence = item.evidence[:EVIDENCE_LIMIT]
    return deviations[:MAX_DEVIATIONS]
