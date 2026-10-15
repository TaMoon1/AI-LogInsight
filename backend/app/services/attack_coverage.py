"""ATT&CK 技术覆盖度评估。

外部 EVTX 样本只作为可导入的基准清单，不把第三方原始日志打包进产品。
规则覆盖仍以本地规则和本地回归语料为准，避免把「有标签」误认为「已验证」。
"""

from __future__ import annotations

import json
from pathlib import Path

from ..models import AttackCoverageReport, AttackCoverageTechnique
from .rule_quality import load_corpus
from .rules import get_rules
from ..runtime_paths import backend_root

DEFAULT_BENCHMARK = backend_root() / "evaluation" / "attack-benchmark.json"

# 规则正文保持简洁，ATT&CK 组织关系集中维护，便于后续导入外部映射时替换。
#
# 映射口径：**只写技术定义真正对得上的**，宁缺勿宽。
#   - 反例（已纠）：`web.404_scan` 曾映射 T1046「网络服务扫描」——它其实是 Web 目录/文件枚举，
#     属 Active Scanning / Discovery，不是服务扫描；T1046 由 `firewall.port_scan` 覆盖即可。
#   - `windows.suspicious_executable_in_temp` 刻意不映射 T1204「用户执行」：落地到临时目录
#     不等于用户执行，硬套会让「执行」这一类虚高。
#   - ⚠️ 已知的一处宽松映射（待确认，未改）：`db.privilege_escalation` 映射 T1068
#     「利用漏洞提权」，但该规则实际判据是 GRANT / CREATE USER / SET GLOBAL 这类权限变更语句
#     （更贴近 T1098 Account Manipulation）。改了 T1068 就会变成真缺口（当前无规则覆盖漏洞利用提权），
#     所以先把判断留给负责人，不擅自调整覆盖率数字。
RULE_TECHNIQUES: dict[str, tuple[str, ...]] = {
    "ssh.bruteforce": ("T1110.001",),
    "ssh.bruteforce.success": ("T1110.001", "T1078", "T1021.004"),
    "ssh.privileged_login": ("T1078", "T1021.004"),
    "auth.bruteforce": ("T1110",),
    "auth.bruteforce.success": ("T1110", "T1078"),
    "rdp.bruteforce": ("T1110.001", "T1021.001"),
    "rdp.bruteforce.success": ("T1110.001", "T1021.001", "T1078"),
    "windows.privileged_logon": ("T1078",),
    "windows.account_lockout": ("T1110",),
    "windows.service_install": ("T1543.003",),
    "windows.protection_service_stopped": ("T1562.001",),
    "windows.lolbin_download": ("T1218", "T1105"),
    "windows.archive_with_password": ("T1560.001",),
    "windows.masquerade_extension": ("T1036.008",),
    "windows.credential_file_access": ("T1555", "T1552.004"),
    "windows.payload_cleanup": ("T1070.004",),
    "windows.registry_certificate_store": ("T1553.004",),
    "windows.suspicious_dns_query": ("T1071.004",),
    "windows.discovery_command": ("T1082", "T1057", "T1016"),
    "windows.executable_drop_in_temp": ("T1105",),
    "windows.registry_bulk_write": ("T1112",),
    "windows.script_interpreter_encoded": ("T1059.001",),
    "windows.command_shell_suspicious_parent": ("T1059.003",),
    "windows.auth_export.suspicious_ip": ("T1078",),
    "windows.auth_export.abnormal_time": ("T1078",),
    "web.sql_injection": ("T1190",),
    "web.command_injection": ("T1059",),
    "web.webshell": ("T1505.003",),
    "firewall.port_scan": ("T1046",),
    "db.bruteforce": ("T1110",),
    "db.bruteforce.success": ("T1110", "T1078"),
    "db.privilege_escalation": ("T1068",),
    "db.data_exfiltration": ("T1041",),
    # ---- 本项目补充的技术（不在外部参考集内，见 attack-benchmark.json 的 origin 字段）----
    # 影响（Impact）：原规则库在该战术下完全空白
    "windows.inhibit_recovery": ("T1490",),
    "windows.ransomware_extension": ("T1486",),
    "windows.security_service_stop": ("T1489",),
    "windows.data_destruction": ("T1485",),
    # 凭证访问
    "windows.lsass_memory_dump": ("T1003.001",),
    "windows.sam_registry_dump": ("T1003.002", "T1003.003"),
    "windows.credential_hunting": ("T1552.001",),
    # 防御规避
    "windows.eventlog_cleared": ("T1070.001",),
    "windows.defender_exclusion_added": ("T1562.001",),
    "windows.certutil_decode": ("T1140",),
    "windows.uac_bypass": ("T1548.002",),
    "windows.hidden_file_attrib": ("T1564.001",),
    # 账户操作与自启动
    "windows.create_local_account": ("T1136.001",),
    "windows.account_manipulation": ("T1098",),
    "windows.registry_run_key": ("T1547.001",),
    # 发现
    "windows.network_connection_discovery": ("T1049",),
    "windows.file_directory_discovery": ("T1083",),
    "windows.account_discovery": ("T1087",),
}


def _load_benchmark(path: Path = DEFAULT_BENCHMARK) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _rule_techniques(rule) -> set[str]:
    mapped = set(RULE_TECHNIQUES.get(rule.id, ()))
    for tag in rule.tags:
        if tag.lower().startswith("attack.t"):
            mapped.add(tag.split(".", 1)[1].upper())
    return mapped


def evaluate_attack_coverage(
    benchmark_path: Path = DEFAULT_BENCHMARK,
) -> AttackCoverageReport:
    benchmark = _load_benchmark(benchmark_path)
    technique_rules: dict[str, list[str]] = {}
    for rule in get_rules():
        for technique in _rule_techniques(rule):
            technique_rules.setdefault(technique, []).append(rule.id)

    # 本地正样本：用例里声明命中了某条规则 → 该规则映射到的技术都算「有样本验证」。
    # 用「技术 → 规则」反查而不是只看 RULE_TECHNIQUES，Sigma 规则靠 tags 声明的技术也能算上。
    local_cases = load_corpus()
    samples_by_technique: dict[str, set[str]] = {}
    for case in local_cases:
        case_name = str(case.get("name") or case.get("file") or "unnamed")
        for expectation in case.get("expect") or []:
            rule_id = str(expectation.get("rule") or "")
            for technique_id, rule_ids in technique_rules.items():
                if rule_id in rule_ids:
                    samples_by_technique.setdefault(technique_id, set()).add(case_name)

    techniques: list[AttackCoverageTechnique] = []
    for item in benchmark.get("techniques", []):
        technique_id = str(item["id"]).upper()
        rule_ids = sorted(set(technique_rules.get(technique_id, [])))
        techniques.append(
            AttackCoverageTechnique(
                technique_id=technique_id,
                name=str(item.get("name") or technique_id),
                tactic=str(item.get("tactic") or ""),
                # 缺省视为外部参考集原有技术，保持对旧清单的向后兼容
                origin=str(item.get("origin") or "external"),
                covered=bool(rule_ids),
                rule_ids=rule_ids,
                local_sample_count=len(samples_by_technique.get(technique_id, set())),
            )
        )
    covered = sum(1 for item in techniques if item.covered)
    sample_validated = sum(1 for item in techniques if item.local_sample_count)
    external = [item for item in techniques if item.origin == "external"]
    project = [item for item in techniques if item.origin != "external"]
    return AttackCoverageReport(
        source=str(benchmark.get("source") or "local benchmark"),
        source_url=str(benchmark.get("source_url") or ""),
        reference_sample_count=int(benchmark.get("reference_sample_count") or 0),
        reference_packaged=bool(benchmark.get("reference_packaged") or False),
        scope_note=str(benchmark.get("scope_note") or ""),
        local_case_count=len(local_cases),
        local_whole_log_case_count=sum(1 for case in local_cases if case.get("log_file")),
        local_chain_case_count=sum(
            1
            for case in local_cases
            if case.get("scenario") == "attack_chain"
            or "攻击链" in str(case.get("family") or "")
        ),
        technique_count=len(techniques),
        covered_technique_count=covered,
        coverage_ratio=covered / len(techniques) if techniques else 1.0,
        external_technique_count=len(external),
        external_covered_count=sum(1 for item in external if item.covered),
        project_technique_count=len(project),
        project_covered_count=sum(1 for item in project if item.covered),
        sample_validated_technique_count=sample_validated,
        sample_validation_ratio=sample_validated / len(techniques) if techniques else 1.0,
        uncovered_techniques=[
            item.technique_id for item in techniques if not item.covered
        ],
        covered_without_sample=[
            item.technique_id
            for item in techniques
            if item.covered and not item.local_sample_count
        ],
        techniques=techniques,
    )


def render_markdown(report: AttackCoverageReport) -> str:
    lines = [
        "# ATT&CK 技术覆盖报告",
        "",
        "> 本文件由 `backend/scripts/attack_coverage.py --write` 生成。",
        "> **「有规则」不等于「验证过」**：覆盖表示存在对应检测规则，本地正样本才表示这条技术被真实语料跑通过。",
        "",
        f"- 基准来源：{report.source}",
    ]
    if report.source_url:
        lines.append(f"- 基准链接：{report.source_url}")
    lines += [
        f"- 外部参考集规模：**{report.reference_sample_count}** 个样本"
        f"（{'已打包' if report.reference_packaged else '**未打包**，只作标尺，产品不解析第三方样本'}）",
        f"- 本地回归用例：**{report.local_case_count}**"
        f"（其中整份真实日志用例 **{report.local_whole_log_case_count}**、攻击链场景 family **{report.local_chain_case_count}**）",
        f"- ATT&CK 技术覆盖：**{report.covered_technique_count} / {report.technique_count}** "
        f"（{report.coverage_ratio:.1%}）",
        f"- 本地正样本验证：**{report.sample_validated_technique_count} / {report.technique_count}** "
        f"（{report.sample_validation_ratio:.1%}）",
        f"- 有规则但缺本地正样本：{'、'.join(report.covered_without_sample) or '无'}",
        f"- 未覆盖（缺口）：{'、'.join(report.uncovered_techniques) or '无'}",
        "",
        "**按来源拆分的覆盖口径**（两份清单分开算，不合并成一个百分比）：",
        "",
        f"- 外部参考集原有技术：**{report.external_covered_count} / {report.external_technique_count}**"
        f"（{report.external_covered_count / report.external_technique_count:.1%}）"
        if report.external_technique_count
        else "- 外部参考集原有技术：无",
        f"- 本项目补充技术：**{report.project_covered_count} / {report.project_technique_count}**"
        f"（{report.project_covered_count / report.project_technique_count:.1%}）"
        if report.project_technique_count
        else "- 本项目补充技术：无",
        "",
    ]
    if report.scope_note:
        lines += [f"> {report.scope_note}", ""]
    if report.techniques and not report.uncovered_techniques:
        lines += [
            f"> **这份清单已全部覆盖，但不代表检测能力到顶**：清单只有 {report.technique_count} 项"
            f"（外部参考集原有 {report.external_technique_count} 项 + 本项目补充 {report.project_technique_count} 项），"
            "ATT&CK Enterprise 有 200+ 技术。"
            "下一步的价值在继续「扩充基准清单」——把新技术的样本与规则一起补上，而不是停在 100%。",
            "",
        ]
    lines += [
        "| 技术 | 战术 | 来源 | 规则 | 本地正样本 | 状态 |",
        "| --- | --- | --- | --- | ---: | --- |",
    ]
    for item in report.techniques:
        if not item.covered:
            status = "缺口：无规则"
        elif not item.local_sample_count:
            status = "已覆盖，缺本地正样本"
        else:
            status = "已覆盖并验证"
        origin_label = "外部参考集" if item.origin == "external" else "本项目补充"
        lines.append(
            f"| `{item.technique_id}` {item.name} | {item.tactic or '-'} | {origin_label} | "
            f"{'、'.join(item.rule_ids) or '-'} | {item.local_sample_count} | {status} |"
        )
    return "\n".join(lines) + "\n"
