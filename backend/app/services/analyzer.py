from __future__ import annotations

from collections import Counter

from ..models import (
    RISK_ORDER,
    AnalysisResult,
    BehaviorDeviation,
    DetectionCoverage,
    LogMetadata,
    LogStatistics,
    sort_events_by_risk,
)
from .behavior_baseline import build_behavior_deviations
from .correlation import build_entity_profiles, build_terminal_evidence_chains, build_timeline
from .detector import detect_events_with_coverage
from .whitelist import WhitelistMatcher, whitelist_repository
from .risk_scoring import highest_level, score_events, scoring_enabled
from .parser import ParsedLog, count_values, parse_log

MAX_MERGED_TEMPLATES = 20
RARE_TEMPLATE_COUNT = 1

# 规则可消费的行为字段：任一字段非空即认为该记录「可判定」。
# raw 只作为证据兜底，不计入——否则「只解析出原文」会被误当成「已分析过」。
EVALUABLE_FIELDS = (
    "source_ip",
    "destination_ip",
    "destination_port",
    "protocol",
    "username",
    "result",
    "url",
    "process_image",
    "command_line",
    "target_filename",
    "service_name",
    "service_state",
    "registry_key",
    "query_name",
)
# 可判定记录占比低于该值时，结论降级为「无法确认」，不再输出「未发现异常」
EVALUABLE_RATIO_FLOOR = 0.5


def _is_evaluable(record: dict[str, str | None]) -> bool:
    return any(record.get(field) for field in EVALUABLE_FIELDS)


def _build_coverage(
    records: list[dict[str, str | None]],
    covered_ids: set[str],
    parse_failures: int,
    parse_errors: int = 0,
    retention_drops: int = 0,
    parse_error_details: list[dict[str, str | int | None]] | None = None,
    whitelisted_records: int = 0,
) -> DetectionCoverage:
    total = len(records)
    evaluable = sum(1 for record in records if _is_evaluable(record))
    limitations: list[str] = []
    if total == 0:
        limitations.append("未从日志中解析出任何可用记录")
    elif evaluable / total < EVALUABLE_RATIO_FLOOR:
        limitations.append(
            f"{total - evaluable}/{total} 条记录不含可用于判定的行为字段，"
            "现有规则没有判据"
        )
    if parse_failures:
        breakdown: list[str] = []
        if parse_errors:
            breakdown.append(f"解析失败 {parse_errors} 条")
        if retention_drops:
            breakdown.append(f"超出单次保留上限 {retention_drops} 条")
        limitations.append(
            f"{parse_failures} 条内容未纳入检测"
            f"（{'、'.join(breakdown) or '解析失败或超出单次保留上限'}）"
        )
    return DetectionCoverage(
        total_records=total,
        evaluable_records=evaluable,
        covered_records=len(covered_ids),
        uncovered_records=total - len(covered_ids),
        parse_failures=parse_failures,
        parse_errors=parse_errors,
        retention_drops=retention_drops,
        whitelisted_records=whitelisted_records,
        parse_error_details=parse_error_details or [],
        limitation="；".join(limitations) or None,
    )


def _build_judgement(
    events: list, coverage: DetectionCoverage, deviations: list[BehaviorDeviation]
) -> tuple[str, str, float]:
    """返回（风险等级, 结论, 置信度）。

    无事件时分三种：覆盖完整且无偏离 → 「未发现异常」；有行为偏离 → 「未发现明确
    攻击特征，但存在 N 项行为偏离」；覆盖不完整 → 「无法确认」。最后一种绝不能
    表述为没有异常，否则等于给出无法支撑的保证。
    """

    if not events:
        if coverage.limitation:
            return (
                "info",
                f"已解析日志，但检测覆盖不完整（{coverage.limitation}），"
                "当前无法确认是否存在异常。",
                0.2,
            )
        if deviations:
            return (
                "info",
                f"未发现明确攻击特征，但存在 {len(deviations)} 项行为偏离"
                "（低置信度），建议结合业务基线逐项核实。",
                0.35,
            )
        return "info", "当前没有发现当前规则覆盖范围内的明显异常。", 0.35
    risk = max(events, key=lambda event: RISK_ORDER.index(event.risk_level)).risk_level
    confidence_by_risk = {
        "critical": 0.95,
        "high": 0.88,
        "medium": 0.68,
        "low": 0.52,
        "info": 0.35,
    }
    conclusion_by_risk = {
        "critical": "发现严重风险行为，建议立即基于日志证据开展人工核查。",
        "high": "发现高风险可疑行为，建议优先核实相关来源和后续操作。",
        "medium": "发现需要关注的异常行为，但仅凭当前日志尚不能确认其为恶意行为。",
        "low": "发现低风险异常，建议结合业务基线进行确认。",
        "info": "当前没有发现明显异常。",
    }
    return risk, conclusion_by_risk[risk], confidence_by_risk[risk]


def _build_recommendations(
    log_type: str,
    events: list,
    coverage: DetectionCoverage,
    deviations: list[BehaviorDeviation],
) -> list[str]:
    # 检测覆盖不完整时优先说清「这次没法给结论」，而不是给泛泛的排查方向
    if not events and coverage.limitation:
        return [
            "方向：本次日志未能提供足够的可判定字段，无法据此判断是否存在可疑行为，需先补齐可识别的日志来源。",
            "方法：核实日志的导出方式、字段是否被裁剪或脱敏、编码是否正确；优先补充同时段的认证、进程创建、网络连接与应用日志后重新分析。",
        ]
    # 未命中攻击特征但有行为偏离：给出「逐项核实」的口径，避免把偏离当结论
    if not events and deviations:
        kinds = sorted({item.kind for item in deviations})
        return [
            f"方向：未命中已知攻击特征，但存在 {len(deviations)} 项行为偏离（{('、'.join(kinds))}），"
            "需确认这些地址 / 域名 / 端口是否属于已知业务；偏离本身不构成攻击结论。",
            "方法：按日志中出现的地址、域名、端口与时间范围，比对资产清单、业务白名单、DNS 解析记录与上网行为日志；"
            "重点核实首次出现的公网目的地址与外联端口的对应进程，确认无对应业务后按疑似失陷方向深入排查。",
        ]
    event_types = {event.type for event in events}
    recommendations: list[str] = []
    if {"ssh_bruteforce", "ssh_bruteforce_success"} & event_types:
        recommendations.extend(
            [
                "方向：确认来源 IP 是否属于可信管理地址，以及失败尝试是否来自正常运维。",
                "方法：按来源 IP 和用户名检索 sudo、audit 或 shell history 日志，核对成功登录后的命令、文件访问和权限变化。",
            ]
        )
    if {"auth_bruteforce", "auth_bruteforce_success"} & event_types:
        recommendations.extend(
            [
                "方向：确认该认证来源是否属于可信网段，失败尝试是否来自正常业务或运维。",
                "方法：按来源 IP、账户和时间范围回溯原始系统（VPN、堡垒机、应用或网络设备）日志，核对失败尝试与成功登录的对应关系及后续操作。",
            ]
        )
    if {"rdp_bruteforce", "rdp_bruteforce_success"} & event_types:
        recommendations.extend(
            [
                "方向：确认 Windows / RDP 暴露面来源，判断登录尝试是否来自可信管理网段。",
                "方法：核对来源 IP 归属与账户锁定策略，按 4624 / 4625 事件核查登录类型（3 网络登录 / 10 RDP）、来源主机名以及登录后的进程创建记录。",
            ]
        )
    if "privileged_login" in event_types:
        recommendations.extend(
            [
                "方向：核实高权限账户登录是否符合预期变更或运维窗口。",
                "方法：对照账号责任人、登录来源、登录时间和 MFA/堡垒机记录，确认该登录是否被授权。",
            ]
        )
    if "account_lockout" in event_types:
        recommendations.extend(
            [
                "方向：确认认证攻击的来源与影响范围，以及账户锁定是否由该攻击造成。",
                "方法：按来源 IP 与账户核对 4625（失败）与 4740（锁定）的对应关系，检查锁定期间是否仍出现登录尝试；"
                "同时确认锁定是否由正常用户误输密码引起，避免直接把业务误操作当成攻击。",
            ]
        )
    if "service_install" in event_types:
        recommendations.extend(
            [
                "方向：确认新安装的服务是否为预期变更，重点核实可执行文件路径与启动类型。",
                "方法：比对变更单与现有服务清单，核对 7045 记录的 ServiceName / ServiceFile 是否指向业务目录；"
                "若路径位于临时目录、用户目录或可写共享，按持久化方向排查该文件的来源、创建时间与后续外联记录。",
            ]
        )
    if "protection_service_stopped" in event_types:
        recommendations.extend(
            [
                "方向：先确认防护服务被停止是计划内运维，还是攻击者在削弱防御。",
                "方法：对照变更单与运维记录确认操作人；若非计划内，按时间顺序串联该主机的进程创建、登录与服务变更记录，"
                "重点判断是否构成「先停防护、再执行」的动作序列，并核查该主机是否同时出现新增服务、异常外联或凭据访问。",
            ]
        )
    if {
        "sensitive_path_access",
        "path_traversal_candidate",
        "web_scan_candidate",
        "sensitive_file_access",
        "sensitive_file_success",
    } & event_types:
        recommendations.extend(
            [
                "方向：判断同一来源是否持续探测、访问敏感资源或进一步利用；若已出现敏感文件成功读取，需优先确认泄露范围。",
                "方法：按来源 IP 和时间范围关联 Web、应用和 WAF 日志，检查后续 200、403、500 响应、上传请求和异常 User-Agent；对返回 2xx 的敏感文件路径，核实文件是否存在、内容敏感度与访问账号，并按需轮换相关密钥。",
            ]
        )
    if {
        "app_sensitive_path_probe",
        "app_restricted_resource_access",
    } & event_types:
        recommendations.extend(
            [
                "方向：应用侧已识别出扫描或越权访问并留下记录，需确认这些来源是否属于已知扫描器、安全测试或异常终端。",
                "方法：按来源 IP 与时间范围回溯应用访问日志与 WAF 记录，核对被探测路径的返回码以及是否属于业务公开范围；"
                "若来源不属于安全测试，按终端失陷方向检查该 IP 对应主机的进程创建与外联记录。",
            ]
        )
    if "app_auth_threshold_block" in event_types:
        recommendations.extend(
            [
                "方向：确认认证攻击的来源与影响范围，以及应用侧封禁是否已生效。",
                "方法：按来源 IP 统计认证失败与成功次数、涉及账户；核对封禁后是否出现成功登录，或改用其他来源继续尝试；"
                "对涉及账户确认是否需要强制改密并检查 MFA 记录。",
            ]
        )
    if "web_server_error_burst" in event_types:
        recommendations.extend(
            [
                "方向：区分 5xx 聚集是应用自身故障，还是由异常请求、资源耗尽或攻击特征触发。",
                "方法：按来源 IP、URL、状态码和时间范围关联应用错误日志、WAF 日志与部署变更记录；5xx 本身不能单独证明攻击。",
            ]
        )
    if {
        "sql_injection_attempt",
        "xss_attempt",
        "command_injection_attempt",
        "webshell_probe",
        "sensitive_interface_probe",
    } & event_types:
        recommendations.extend(
            [
                "方向：确认攻击特征请求是否被拦截（状态码 403/40x 通常为 WAF 或应用拦截），以及是否存在绕过后继续利用的迹象。",
                "方法：按来源 IP、User-Agent 和时间范围回溯 WAF / 应用日志，核对后续是否出现 200 响应、文件上传、命令回显或敏感接口数据返回。",
            ]
        )
    if {
        "web_authentication_failure_burst",
        "web_authentication_failure_success",
    } & event_types:
        recommendations.extend(
            [
                "方向：确认登录接口的失败来源是否为账号撞库或口令爆破，以及是否已出现成功登录。",
                "方法：按来源 IP、账号、User-Agent 和时间范围核对认证日志、账号锁定记录与登录会话，确认成功响应是否为同一来源触发。",
            ]
        )
    if "firewall_port_scan_candidate" in event_types:
        recommendations.extend(
            [
                "方向：确认来源 IP 是否为授权扫描器、运维探针或可信安全设备，并核对目标资产归属。",
                "方法：按来源 IP、目的 IP、协议和目的端口回溯防火墙/WAF 原始日志，结合连接结果和资产暴露清单判断是否为异常探测。",
            ]
        )
    if {
        "db_bruteforce",
        "db_bruteforce_success",
        "db_sql_injection",
        "db_destructive_query",
        "db_privilege_escalation",
        "db_data_exfiltration",
        "db_privileged_login",
    } & event_types:
        recommendations.extend(
            [
                "方向：核对数据库访问来源是否可信，判断异常语句是应用缺陷、误配置还是恶意操作。",
                "方法：按来源 IP、数据库账户、时间范围回溯数据库审计/慢查询日志与堡垒机记录，确认高风险语句的执行者、影响范围与是否已回滚；重点核实 GRANT/ALTER、DROP/TRUNCATE、INTO OUTFILE 等操作的授权依据。",
            ]
        )
    if {
        "lolbin_download",
        "suspicious_temp_execution",
        "archive_with_password",
        "masquerade_extension",
        "payload_cleanup",
        "credential_file_access",
        "certificate_store_modify",
        "suspicious_dns_query",
        "discovery_command",
        "payload_outbound_connection",
        "executable_drop_in_temp",
        "registry_bulk_write",
        "script_interpreter_encoded",
        "suspicious_command_shell",
    } & event_types:
        recommendations.extend(
            [
                "方向：确认落地程序的来源与下载渠道、凭据是否已泄露、以及数据打包后的去向，判断是钓鱼木马自动执行还是人为收集外传。",
                "方法：按主机、进程镜像、命令行与时间范围回溯 Sysmon 与终端日志，核对文件落地时间与哈希、父进程链、外联目的地址与端口，并核实压缩包内容、密码来源及是否已外传；若涉及凭据文件或被删除的落地程序，需按受影响账号范围执行凭据轮换。",
            ]
        )
    if not recommendations and log_type == "nginx_apache":
        recommendations.append(
            "方向：建立正常访问基线；方法：按来源 IP、URL、状态码和时间段对比后续访问日志。"
        )
    if not recommendations:
        recommendations.append(
            "方向：扩大证据范围进行关联分析；方法：补充同时间段的认证、应用或审计日志后按 IP、账户和时间线比对。"
        )
    return recommendations


def _merge_templates(parsed_logs: list[ParsedLog]) -> list[dict[str, object]]:
    """合并多份日志的模板挖掘结果，按出现次数排序。"""

    merged: dict[str, int] = {}
    for parsed in parsed_logs:
        for item in parsed.templates:
            template = str(item["template"])
            merged[template] = merged.get(template, 0) + int(item["count"])  # type: ignore[arg-type]
    total = sum(merged.values())
    ranked = sorted(merged.items(), key=lambda item: (-item[1], item[0]))[:MAX_MERGED_TEMPLATES]
    return [
        {
            "template": template,
            "count": count,
            "ratio": round(count / total, 4),
            "rare": count <= RARE_TEMPLATE_COUNT,
        }
        for template, count in ranked
    ]


def collect_records(
    filenames: list[str], parsed_logs: list[ParsedLog]
) -> list[dict[str, str | None]]:
    """把各文件的记录合成一份列表，并就地补上来源文件与日志类型。

    就地在原字典上补键，而不是 `{**record, ...}` 复制：单条记录复制一次就是一份
    完整字典（实测约 300 字节/条），大日志下峰值内存会成倍抬高。
    """

    records: list[dict[str, str | None]] = []
    for filename, parsed in zip(filenames, parsed_logs):
        for record in parsed.records:
            record["source_file"] = filename
            record["log_type"] = parsed.log_type
            records.append(record)
    return records


def assign_record_ids(records: list[dict[str, str | None]]) -> list[dict[str, str | None]]:
    """就地按时间排序并写入稳定编号（UI 与 AI 证据引用都用它）。

    同样不复制：返回的就是传入的那个列表，语义与原来的 `sorted()` 结果一致。
    """

    records.sort(key=lambda record: record.get("timestamp_iso") or "")
    for index, record in enumerate(records, start=1):
        record["record_id"] = f"record-{index}"
        record["evidence_id"] = f"evidence-record-{index}"
    return records


def load_whitelist_matcher() -> WhitelistMatcher:
    """读取当前生效的白名单。

    读取失败时退回「没有白名单」——宁可多报，也不能因为白名单读不到而漏报。
    """

    try:
        return WhitelistMatcher(whitelist_repository.list_entries())
    except Exception:
        return WhitelistMatcher([])


def analyze_parsed_logs(
    filenames: list[str],
    parsed_logs: list[ParsedLog],
    whitelist: WhitelistMatcher | None = None,
) -> AnalysisResult:
    matcher = whitelist if whitelist is not None else load_whitelist_matcher()
    if matcher:
        # 命中白名单的记录不参与规则匹配（不产生告警），但原始记录仍保留在明细里作为证据。
        # 标记必须写回 parsed_logs 的原始记录：调用方会另行组装 records，只改本地副本会丢标记。
        for parsed_log in parsed_logs:
            for record in parsed_log.records:
                hit = matcher.match(record)
                if hit:
                    record["whitelisted_by"] = hit

    records = collect_records(filenames, parsed_logs)
    parsed = ParsedLog(
        log_type=(
            parsed_logs[0].log_type
            if len({item.log_type for item in parsed_logs}) == 1
            else "mixed"
        ),
        confidence=min((item.confidence for item in parsed_logs), default=0),
        total_lines=sum(item.total_lines for item in parsed_logs),
        parsed_lines=sum(item.parsed_lines for item in parsed_logs),
        records=records,
        parse_error_details=[
            {**detail, "source_file": filename}
            for filename, item in zip(filenames, parsed_logs)
            for detail in item.parse_error_details
        ][:100],
    )
    records = assign_record_ids(records)
    failed = sum(record.get("result") == "failure" for record in records)
    successful = sum(record.get("result") == "success" for record in records)
    timestamps = [record["timestamp"] for record in records if record.get("timestamp")]
    if matcher:
        matchable = [record for record in records if not record.get("whitelisted_by")]
        whitelisted = len(records) - len(matchable)
    else:
        matchable = records
        whitelisted = 0
    events, covered_ids = detect_events_with_coverage(matchable)
    coverage = _build_coverage(
        records,
        covered_ids,
        sum(item.parse_failures for item in parsed_logs),
        sum(item.parse_errors for item in parsed_logs),
        sum(item.retention_drops for item in parsed_logs),
        parsed.parse_error_details,
        whitelisted,
    )
    deviations = build_behavior_deviations(records)
    risk, conclusion, confidence = _build_judgement(events, coverage, deviations)

    # 异常评分（CRS 思路）：默认只计算展示，不改变等级；开启后按同源累计分升级
    risk_scores = score_events(events)
    if scoring_enabled():
        escalated_level = highest_level(risk_scores, risk)
        if RISK_ORDER.index(escalated_level) > RISK_ORDER.index(risk):
            boosted = next(
                item for item in risk_scores if item.escalated_level == escalated_level
            )
            risk = escalated_level
            conclusion = (
                f"{conclusion} 同一来源 {boosted.source_ip} 的多项异常累计 "
                f"{boosted.score} 分（{boosted.baseline_level} → {risk}），已按异常评分升级风险等级。"
            )

    status_counts = Counter(record["status"] for record in records if record.get("status"))
    statistics = LogStatistics(
        total=parsed.total_lines,
        failed_login=failed,
        successful_login=successful,
        top_source_ips=count_values(records, "source_ip"),
        top_users=count_values(records, "username"),
        status_codes=[
            {"value": value, "count": count}
            for value, count in status_counts.most_common(10)
        ],
    )
    metadata = LogMetadata(
        filename=filenames[0] if len(filenames) == 1 else f"{len(filenames)} 个日志文件",
        source_files=filenames,
        log_type=parsed.log_type,
        recognition_confidence=parsed.confidence,
        total_lines=parsed.total_lines,
        parsed_lines=parsed.parsed_lines,
        time_range={
            "start": timestamps[0] if timestamps else None,
            "end": timestamps[-1] if timestamps else None,
        },
    )
    return AnalysisResult(
        metadata=metadata,
        statistics=statistics,
        # 落库前按风险从高到低排（同级按次数降序），报告 / 导出 / 详情都是同一顺序；
        # 前面的定级、评分、串联都按检测产出顺序算，不受排序影响。
        events=sort_events_by_risk(events),
        templates=_merge_templates(parsed_logs),
        coverage=coverage,
        risk_score=risk_scores[0].score if risk_scores else 0,
        risk_score_enabled=scoring_enabled(),
        risk_scores=risk_scores,
        entities=build_entity_profiles(records, events),
        timeline=build_timeline(records, events),
        terminal_chains=build_terminal_evidence_chains(records, events),
        has_suspicious_behavior=bool(events),
        risk_level=risk,
        confidence=confidence,
        conclusion=conclusion,
        analysis_source="rules",
        behavior_deviations=deviations,
        summary=(
            f"发现 {len(events)} 个可疑事件。"
            if events
            else (
                f"检测覆盖不完整：{coverage.limitation}，本次结论无法作为「已排查无问题」的依据。"
                if coverage.limitation
                else (
                    f"未命中任何攻击特征，但存在 {len(deviations)} 项行为偏离"
                    "（与本批次相比首次出现的地址 / 域名 / 端口等），"
                    "均为低置信度信号，需结合业务基线核实。"
                    if deviations
                    else f"未发现当前规则覆盖范围内的明显可疑事件"
                    f"（{coverage.covered_records}/{coverage.total_records} 条记录命中规则）。"
                )
            )
        ),
        recommendations=_build_recommendations(
            parsed.log_type, events, coverage, deviations
        ),
    )


def analyze_log(
    filename: str, text: str, whitelist: WhitelistMatcher | None = None
) -> AnalysisResult:
    return analyze_parsed_logs([filename], [parse_log(text)], whitelist=whitelist)
