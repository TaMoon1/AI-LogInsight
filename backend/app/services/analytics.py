"""AI 赋能洞察：时间频次柱状图 + 攻击链（ATT&CK 风格映射）。

- `build_timeseries`：把全部记录按时间分桶，输出每桶记录数、独立来源 IP 数、
  失败/成功登录数，用于「攻击前后频次对比」。
- `build_attack_chains`：把可疑事件按来源 IP（或账户）串成按时间排序的杀伤链，
  每条阶段映射到 ATT&CK 战术（简化映射，非完整 MITRE）。
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone

from ..models import (
    AttackChain,
    AttackChainStage,
    EntityProfile,
    Event,
    RiskLevel,
    TimeBucket,
)

RISK_ORDER = ("info", "low", "medium", "high", "critical")

# rule_id / event.type → (ATT&CK tactic, technique)
_TACTICS: dict[str, tuple[str, str]] = {
    "ssh.bruteforce": ("凭据访问", "T1110 暴力破解"),
    "ssh.bruteforce.success": ("初始访问", "成功登录（破解得手）"),
    "ssh.privileged_login": ("权限提升", "特权账户登录"),
    "rdp.bruteforce": ("凭据访问", "T1110 RDP 暴力破解"),
    "rdp.bruteforce.success": ("初始访问", "RDP 成功登录"),
    "windows.privileged_logon": ("权限提升", "特权账户登录"),
    "windows.lolbin_download": ("执行", "T1218 系统工具代理执行"),
    "windows.suspicious_executable_in_temp": ("执行", "T1204 用户执行落地文件"),
    "windows.archive_with_password": ("数据渗出", "T1560 归档收集数据"),
    "windows.masquerade_extension": ("防御规避", "T1036.008 伪装文件扩展名"),
    "windows.credential_file_access": ("凭据访问", "T1555 凭据文件访问"),
    "windows.payload_cleanup": ("防御规避", "T1070.004 文件删除"),
    "windows.registry_certificate_store": ("防御规避", "T1553.004 安装根证书"),
    "windows.suspicious_dns_query": ("命令与控制", "T1071.004 DNS 通信"),
    "windows.discovery_command": ("发现", "T1082 系统信息发现"),
    "windows.payload_outbound_connection": ("命令与控制", "T1071 应用层协议外联"),
    "windows.executable_drop_in_temp": ("初始访问", "T1105 落地载荷文件"),
    "windows.registry_bulk_write": ("防御规避", "T1112 批量修改注册表"),
    "auth.bruteforce": ("凭据访问", "T1110 暴力破解"),
    "auth.bruteforce.success": ("初始访问", "成功登录"),
    "web.scanner_user_agent": ("侦察", "T1595 漏洞扫描器 UA"),
    "web.404_scan": ("发现", "目录/文件枚举"),
    "web.sensitive_path": ("发现", "敏感路径探测"),
    "web.sensitive_interface": ("发现", "敏感管理接口探测"),
    "web.path_traversal": ("初始访问", "T1190 路径穿越"),
    "web.sensitive_file_access": ("发现", "敏感文件路径探测"),
    "web.sensitive_file_access.success": ("凭据访问", "敏感文件成功读取"),
    "web.sql_injection": ("初始访问", "T1190 SQL 注入"),
    "web.xss": ("初始访问", "T1059 XSS"),
    "web.command_injection": ("执行", "T1059 命令注入"),
    "web.webshell": ("持久化", "T1505 WebShell"),
    "web.auth_bruteforce": ("凭据访问", "T1110 Web 登录爆破"),
    "web.auth_bruteforce.success": ("初始访问", "Web 成功登录"),
    "web.5xx_burst": ("影响", "T1499 服务异常突发"),
    "firewall.port_scan": ("发现", "T1046 端口扫描"),
    "app.sensitive_path_probe": ("发现", "敏感路径探测（应用侧判定）"),
    "app.auth_threshold_block": ("凭据访问", "T1110 认证阈值触发封禁"),
    "app.restricted_resource_access": ("发现", "受限资源访问"),
    "windows.account_lockout": ("凭据访问", "T1110 账户被锁定"),
    "windows.service_install": ("持久化", "T1543.003 新建服务"),
    "windows.protection_service_stopped": ("防御规避", "T1562.001 削弱防御：停止安全工具"),
    "windows.script_interpreter_encoded": ("执行", "T1059.001 编码 / 隐藏窗口命令"),
    "windows.command_shell_suspicious_parent": ("执行", "T1059.003 可疑父进程启动命令行"),
    # 数据库
    "db.bruteforce": ("凭据访问", "T1110 数据库暴力破解"),
    "db.bruteforce.success": ("初始访问", "数据库破解得手后成功登录"),
    "db.sql_injection": ("初始访问", "T1190 数据库查询注入"),
    "db.destructive_query": ("影响", "T1485 破坏性数据库操作"),
    "db.privilege_escalation": ("权限提升", "数据库权限变更 / 提权"),
    "db.data_exfiltration": ("数据渗出", "数据库批量导出 / 数据外传"),
    "db.privileged_login": ("权限提升", "数据库高权限账户登录"),
}

# 战术 → 阶段序（用于排序与配色，数值越小越靠前）
_PHASE_ORDER = {
    "侦察": 0,
    "发现": 1,
    "初始访问": 2,
    "凭据访问": 3,
    "执行": 4,
    "横向移动": 5,
    "权限提升": 6,
    "防御规避": 7,
    "持久化": 8,
    "收集": 9,
    "命令与控制": 10,
    "数据渗出": 11,
    "影响": 12,
    "其他": 13,
}


def _tactic(rule_id: str | None, event_type: str) -> tuple[str, str]:
    return (
        _TACTICS.get(rule_id or "")
        or _TACTICS.get(event_type)
        or ("其他", "可疑行为")
    )


def _phase_index(tactic: str) -> int:
    return _PHASE_ORDER.get(tactic, _PHASE_ORDER["其他"])


def _epoch(iso: str | None) -> float | None:
    if not iso:
        return None
    try:
        parsed = datetime.fromisoformat(iso.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def _iso_label(epoch: float) -> tuple[str, str]:
    dt = datetime.fromtimestamp(epoch, tz=timezone.utc)
    return dt.isoformat(), dt.strftime("%m-%d %H:%M")


def build_timeseries(
    records: list[dict[str, str | None]],
    max_buckets: int = 48,
    timed_events: list[tuple[float, str]] | None = None,
) -> list[TimeBucket]:
    """把记录按时间分桶，输出频次与独立来源 IP 数。

    `timed_events` 是（时间戳, 风险等级）对的列表，用于在同一条时间轴上叠加
    「可疑事件」的分布（Zircolite 风格的中轴双向图：上方记录数、下方事件按等级分层）。
    **事件必须与记录共用同一套桶边界**，否则上下两条轴对不齐，看起来像两个时间范围。
    """

    points: list[tuple[float, dict[str, str | None]]] = []
    for record in records:
        ts = _epoch(record.get("timestamp_iso"))
        if ts is None:
            continue
        points.append((ts, record))

    if not points:
        return []

    points.sort(key=lambda item: item[0])
    start = points[0][0]
    end = points[-1][0]
    span = max(1.0, end - start)
    raw_bucket = span / max_buckets
    # 归整到「好看」的桶宽
    for width in (1, 5, 15, 30, 60, 300, 900, 1800, 3600, 7200, 21600, 43200, 86400, 172800, 604800):
        if raw_bucket <= width:
            bucket = width
            break
    else:
        bucket = int(raw_bucket) or 1

    buckets: dict[int, dict[str, int | set]] = {}
    for ts, record in points:
        index = int((ts - start) // bucket)
        slot = buckets.setdefault(index, {"count": 0, "ips": set(), "fail": 0, "success": 0})
        slot["count"] += 1
        ip = record.get("source_ip")
        if ip:
            slot["ips"].add(ip)  # type: ignore[union-attr]
        result = record.get("result")
        if result == "failure":
            slot["fail"] += 1
        elif result == "success":
            slot["success"] += 1

    series: list[TimeBucket] = []
    for index in range(int((end - start) // bucket) + 1):
        slot = buckets.get(index)
        epoch = start + index * bucket
        start_iso, label = _iso_label(epoch)
        series.append(
            TimeBucket(
                start_iso=start_iso,
                label=label,
                count=slot["count"] if slot else 0,
                unique_source_ips=len(slot["ips"]) if slot else 0,
                failed_login=slot["fail"] if slot else 0,
                successful_login=slot["success"] if slot else 0,
            )
        )
    if not timed_events:
        return series

    # 事件按同一套桶边界落桶；桶边界之外的事件（时间戳早于/晚于记录范围）计入最近的桶，
    # 丢弃会让「有事件却看不到」变成一个查不出来的假象。
    last_index = len(series) - 1
    for ts, level in timed_events:
        index = int((ts - start) // bucket)
        if index < 0:
            index = 0
        elif index > last_index:
            index = last_index
        counts = series[index].levels
        counts[level] = counts.get(level, 0) + 1
    return series


def build_attack_chains(
    events: list[Event],
    entities: list[EntityProfile],
    max_chains: int = 0,
) -> list[AttackChain]:
    """把可疑事件串成时间排序的杀伤链：优先按来源 IP，其次按目标资产（主机），最后按规则。

    主机侧日志（Sysmon / Windows）没有来源 IP，若无 target_asset 分会退化成
    「一个规则一条链」，同一主机的行为链被拆散。

    ⚠️ 链的数量等于「来源 IP 数」：认证导出这类日志有几千个来源 IP，就会产生几千条链
    （实测 11091 条记录 → 1999 条链 / 2.33 MB）。所以这里的排序不只是好看，
    而是配合 `max_chains` 让「截断后留下的是最值得看的链」：
    风险高 → 阶段多（行为链更完整）→ 活动量大 → 发生更早。
    `max_chains=0` 表示不截断（导出或需要全量时用）。
    """

    groups: dict[tuple[str, str], list[Event]] = defaultdict(list)
    for event in events:
        if event.source_ip:
            key, kind = event.source_ip, "source_ip"
        elif event.target_asset:
            key, kind = event.target_asset, "target_asset"
        else:
            key, kind = f"rule:{event.rule_id or event.type}", "rule"
        groups[(key, kind)].append(event)

    # 实体补充：无事件命中但有跨文件/账户关联的实体也纳入（给出上下文）
    entity_by_value = {
        entity.value: entity
        for entity in entities
        if entity.event_count > 0 or entity.record_count >= 2
    }

    chains: list[AttackChain] = []
    for (key, kind), group in groups.items():
        stages: list[AttackChainStage] = []
        for event in sorted(
            group, key=lambda item: (_epoch(item.first_seen) or 0.0, item.rule_id or "")
        ):
            tactic, technique = _tactic(event.rule_id, event.type)
            stages.append(
                AttackChainStage(
                    phase=tactic,
                    tactic=tactic,
                    technique=technique,
                    event_type=event.type,
                    name=event.name,
                    risk_level=event.risk_level,
                    source_ip=event.source_ip,
                    first_seen=event.first_seen,
                    last_seen=event.last_seen,
                    count=event.count,
                    rule_id=event.rule_id,
                    summary=event.summary,
                )
            )
        if not stages:
            continue
        chain_risk: RiskLevel = "info"
        for stage in stages:
            if RISK_ORDER.index(stage.risk_level) > RISK_ORDER.index(chain_risk):
                chain_risk = stage.risk_level
        chains.append(
            AttackChain(key=key, kind=kind, risk_level=chain_risk, stages=stages)
        )

    # 按阶段序二次排序，使链内顺序更符合「前因后果」
    for chain in chains:
        chain.stages.sort(
            key=lambda stage: (
                _phase_index(stage.phase),
                _epoch(stage.first_seen) or 0.0,
            )
        )
    # 链间排序：风险倒序 → 阶段数倒序 → 总触发次数倒序 → 起始时间正序
    chains.sort(
        key=lambda chain: (
            RISK_ORDER.index(chain.risk_level),
            len(chain.stages),
            sum(stage.count for stage in chain.stages),
            -(_epoch(chain.stages[0].first_seen) or 0.0),
        ),
        reverse=True,
    )
    if max_chains > 0:
        return chains[:max_chains]
    return chains
