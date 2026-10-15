from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


RiskLevel = Literal["critical", "high", "medium", "low", "info"]
RISK_ORDER = ("info", "low", "medium", "high", "critical")
AnalysisStatus = Literal["processing", "completed", "failed"]
AiStatus = Literal["not_analyzed", "completed", "unavailable"]
ReviewStatus = Literal["pending", "confirmed", "rejected", "needs_review"]


class AiBehavior(BaseModel):
    type: str
    name: str
    confidence: float = Field(ge=0, le=1)
    evidence: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    analysis: str


class StructuredVerdict(BaseModel):
    """AI 强制输出的结构化研判结论（标准化 → 富化 → AI 研判的最终落地）。"""

    event_time: str | None = None
    attack_source_ip: str | None = None
    target_asset: str | None = None
    involved_account: str | None = None
    abnormal_behavior: str | None = None
    related_logs: list[str] = Field(default_factory=list)
    attack_type: str | None = None
    risk_level: RiskLevel = "info"
    judgment_basis: str | None = None
    success_indicator: str | None = None
    recommended_actions: list[str] = Field(default_factory=list)


class LogMetadata(BaseModel):
    filename: str
    source_files: list[str] = Field(default_factory=list)
    log_type: str
    recognition_confidence: float = Field(ge=0, le=1)
    total_lines: int = Field(ge=0)
    parsed_lines: int = Field(ge=0)
    time_range: dict[str, str | None]


class LogStatistics(BaseModel):
    total: int = 0
    failed_login: int = 0
    successful_login: int = 0
    top_source_ips: list[dict[str, int | str]] = Field(default_factory=list)
    top_users: list[dict[str, int | str]] = Field(default_factory=list)
    status_codes: list[dict[str, int | str]] = Field(default_factory=list)


class RuleDefinition(BaseModel):
    id: str
    name: str
    log_types: list[str] = Field(default_factory=list)
    risk_level: RiskLevel
    enabled: bool = True
    threshold: int | None = None
    window_seconds: int | None = None
    description: str
    source: str = "builtin"
    tags: list[str] = Field(default_factory=list)
    author: str | None = None
    version: str | None = None
    license: str | None = None
    references: list[str] = Field(default_factory=list)
    validation_status: str = "unverified"


class EvidenceItem(BaseModel):
    id: str
    record_id: str | None = None
    timestamp: str | None = None
    source_file: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    username: str | None = None
    url: str | None = None
    user_agent: str | None = None
    destination_port: str | None = None
    raw: str


class Event(BaseModel):
    id: str
    type: str
    name: str
    risk_level: RiskLevel
    source_ip: str | None = None
    # 主机侧日志（Sysmon / Windows）没有来源 IP，用目标资产（主机名）作为归组依据；
    # 否则同一主机的多条行为会被拆成多条杀伤链。
    target_asset: str | None = None
    first_seen: str | None = None
    last_seen: str | None = None
    count: int = 0
    evidence: list[str] = Field(default_factory=list)
    evidence_items: list[EvidenceItem] = Field(default_factory=list)
    timeline: list[str] = Field(default_factory=list)
    source_files: list[str] = Field(default_factory=list)
    correlation_basis: list[str] = Field(default_factory=list)
    rule_id: str | None = None
    summary: str


def sort_events_by_risk(events: list[Event]) -> list[Event]:
    """按「风险从高到低」排列事件，同等级内触发次数多的在前。

    列表是有上限的（详情接口默认只返回前 200 条），若按检测产出顺序截取，
    用户最先看到的是「最早产出的事件」而不是「最严重的事件」。等级相同时
    按次数降序（同一规则反复触发通常比偶发一次更值得先看）。
    `sorted` 稳定，等级与次数都相同时保持原有检测顺序，不制造随机抖动。
    """

    return sorted(
        events,
        key=lambda event: (-RISK_ORDER.index(event.risk_level), -event.count),
    )


class LogTemplate(BaseModel):
    template: str
    count: int
    ratio: float
    rare: bool = False


class EntityProfile(BaseModel):
    kind: Literal["source_ip", "destination_ip", "account"]
    value: str
    risk_level: RiskLevel = "info"
    record_count: int = 0
    event_count: int = 0
    rule_ids: list[str] = Field(default_factory=list)
    log_types: list[str] = Field(default_factory=list)
    source_files: list[str] = Field(default_factory=list)
    first_seen: str | None = None
    last_seen: str | None = None
    summary: str


class TimelineEntry(BaseModel):
    timestamp: str | None = None
    timestamp_iso: str | None = None
    kind: Literal["event", "evidence"]
    title: str
    risk_level: RiskLevel = "info"
    rule_id: str | None = None
    source_ip: str | None = None
    username: str | None = None
    record_id: str | None = None
    source_file: str | None = None
    detail: str | None = None


class TerminalEvidenceChain(BaseModel):
    """按目标资产聚合的终端行为链；仅表示日志关联，不代表攻击结论。"""

    chain_id: str
    target_asset: str | None = None
    risk_level: RiskLevel = "info"
    record_count: int = 0
    first_seen: str | None = None
    last_seen: str | None = None
    summary: str
    nodes: list[dict[str, Any]] = Field(default_factory=list)


class AiToolCall(BaseModel):
    """一次只读工具调用的留痕。

    `tool == "usage"` 是特例：它不是工具调用，而是本轮研究的 token 用量总账
    （见 `ai.py` 的 `_merge_usage`），复用同一列表以便一次请求全部带回前端。
    """

    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    summary: str = ""
    source: Literal["auto", "model"] = "model"
    usage: dict[str, Any] | None = None


class AiLedger(BaseModel):
    """一次 AI 研判的可追溯台账。"""

    analysis_id: str
    created_at: str
    status: Literal["completed", "unavailable"]
    provider: str = ""
    model: str = ""
    duration_ms: int = 0
    tool_trace: list[AiToolCall] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    unsupported_claims: list[str] = Field(default_factory=list)
    usage: dict[str, Any] | None = None
    #: 成本 × 质量联合指标（见 `AnalysisResult.ai_metrics`）。
    metrics: dict[str, Any] | None = None
    summary: str = ""


class ReviewEntry(BaseModel):
    """一次人工确认动作的留痕。"""

    id: int
    status: ReviewStatus
    reviewer: str = ""
    note: str = ""
    created_at: str


class ReviewUpdate(BaseModel):
    """提交人工确认。`reviewer` 必填，否则确认无法追溯到人。"""

    status: ReviewStatus
    reviewer: str = Field(min_length=1)
    note: str = ""


class HumanReview(BaseModel):
    """AI 结论的人工确认状态：当前值 + 完整历史。

    `history` 为空即「未确认」——这一态不落库，避免用一条假记录表示「没人看过」。
    """

    analysis_id: str
    status: ReviewStatus = "pending"
    reviewer: str = ""
    note: str = ""
    updated_at: str | None = None
    history: list[ReviewEntry] = Field(default_factory=list)


class RiskScoreItem(BaseModel):
    """异常评分明细。

    `key` / `kind` 是归组对象（来源 IP 或目标主机）；`source_ip` 保留旧语义，
    仅为兼容历史结果，主机维度下为空字符串。
    """

    source_ip: str = ""
    key: str = ""
    kind: str = "source_ip"
    score: int = 0
    baseline_level: RiskLevel = "info"
    escalated_level: RiskLevel = "info"
    escalated: bool = False
    rule_ids: list[str] = Field(default_factory=list)


class TimeBucket(BaseModel):
    start_iso: str
    label: str
    count: int = 0
    unique_source_ips: int = 0
    failed_login: int = 0
    successful_login: int = 0
    #: 该时段内**事件**按风险等级的计数（键为风险等级）。与 `count`（记录数）是两个单位，
    #: 前端展示时必须分别标注，不能混着当同一个数字用。
    levels: dict[str, int] = Field(default_factory=dict)

    @property
    def detections(self) -> int:
        return sum(self.levels.values())


class AttackChainStage(BaseModel):
    phase: str
    tactic: str
    technique: str
    event_type: str
    name: str
    risk_level: RiskLevel = "info"
    source_ip: str | None = None
    first_seen: str | None = None
    last_seen: str | None = None
    count: int = 0
    rule_id: str | None = None
    summary: str


class AttackChain(BaseModel):
    key: str
    kind: str = "source_ip"
    risk_level: RiskLevel = "info"
    stages: list[AttackChainStage] = Field(default_factory=list)


class Insights(BaseModel):
    timeseries: list[TimeBucket] = Field(default_factory=list)
    attack_chains: list[AttackChain] = Field(default_factory=list)
    # 攻击链条数会随「来源 IP 数」线性增长（认证导出可达数千条），列表按上限返回，
    # 真实条数放这里，界面上必须把「已展示 N / 共 M」讲清楚，否则等于谎报。
    attack_chains_total: int = 0


class BehaviorDeviation(BaseModel):
    """IOA 行为偏离：未命中攻击特征时的低置信度信号。

    `basis` 必须写明基线口径（本期一律是「与本批次相比首次出现」）。
    该结构不参与风险定级，也不进入 `events`。
    """

    kind: str
    name: str
    basis: str
    detail: str
    count: int = 1
    evidence: list[str] = Field(default_factory=list)


class WhitelistEntryModel(BaseModel):
    """用户白名单条目。"""

    id: int
    kind: str
    value: str
    note: str = ""
    enabled: bool = True
    created_at: str


class WhitelistOverview(BaseModel):
    kinds: dict[str, str] = Field(default_factory=dict)
    entries: list[WhitelistEntryModel] = Field(default_factory=list)
    changes: list[dict[str, str]] = Field(default_factory=list)


class WhitelistCreateRequest(BaseModel):
    kind: str
    value: str
    note: str = ""


class RulePreviewRequest(BaseModel):
    """规则草稿预览：只校验和试运行，不写入规则目录。"""

    yaml_text: str | None = None
    rule: dict[str, Any] | None = None
    rules: list[dict[str, Any]] | None = None
    sample_log: str = ""
    filename: str = "preview.log"
    expected_rule_ids: list[str] = Field(default_factory=list)


class RulePreviewReport(BaseModel):
    valid: bool = True
    errors: list[str] = Field(default_factory=list)
    rule_ids: list[str] = Field(default_factory=list)
    event_count: int = 0
    covered_records: int = 0
    true_positive: int = 0
    false_positive: int = 0
    false_negative: int = 0
    rollback_required: bool = False
    events: list[Event] = Field(default_factory=list)


class RuleAuditEntry(BaseModel):
    id: int
    action: str
    rule_id: str
    before: str = ""
    after: str = ""
    actor: str = "console"
    note: str = ""
    created_at: str


class DetectionCoverage(BaseModel):
    """检测覆盖度：把「没有异常」和「没法评估」在产品里区分开。

    `limitation` 非空表示本次检测覆盖不完整，结论不能当作「已排查且无问题」。
    """

    total_records: int = 0
    evaluable_records: int = 0
    covered_records: int = 0
    uncovered_records: int = 0
    parse_failures: int = 0
    parse_errors: int = 0
    retention_drops: int = 0
    whitelisted_records: int = 0
    parse_error_details: list[dict[str, str | int | None]] = Field(default_factory=list)
    limitation: str | None = None


class AnalysisResult(BaseModel):
    id: str = ""
    created_at: str = ""
    metadata: LogMetadata
    statistics: LogStatistics
    events: list[Event] = Field(default_factory=list)
    # 本批次事件总数。大记录下 HTTP 响应会按上限裁剪 events（实测 7536 个事件 = 37 MB，
    # 前端解析与渲染都会卡住），但总数必须保持真值，否则界面会谎报"只有 200 个事件"。
    events_total: int | None = None
    templates: list[LogTemplate] = Field(default_factory=list)
    coverage: DetectionCoverage = Field(default_factory=DetectionCoverage)
    behavior_deviations: list[BehaviorDeviation] = Field(default_factory=list)
    risk_score: int = 0
    risk_score_enabled: bool = False
    risk_scores: list[RiskScoreItem] = Field(default_factory=list)
    entities: list[EntityProfile] = Field(default_factory=list)
    timeline: list[TimelineEntry] = Field(default_factory=list)
    terminal_chains: list[TerminalEvidenceChain] = Field(default_factory=list)
    has_suspicious_behavior: bool = False
    risk_level: RiskLevel = "info"
    confidence: float = Field(default=0.35, ge=0, le=1)
    conclusion: str = "当前没有发现明显异常。"
    analysis_source: Literal["rules", "ai", "rules_and_ai"] = "rules"
    ai_status: AiStatus = "not_analyzed"
    ai_error: str | None = None
    ai_behaviors: list[AiBehavior] = Field(default_factory=list)
    ai_tool_trace: list[AiToolCall] = Field(default_factory=list)
    ai_unsupported_claims: list[str] = Field(default_factory=list)
    #: 单次研判的成本 × 质量联合指标（账单、上下文体量、证据引用覆盖）。
    #: 只读观测，不参与研判判定；`build_ai_context` 会把它排除，不进模型上下文。
    ai_metrics: dict[str, Any] | None = None
    structured_verdict: StructuredVerdict | None = None
    summary: str
    recommendations: list[str] = Field(default_factory=list)


class LogSummary(BaseModel):
    id: str
    filename: str
    status: AnalysisStatus
    risk_level: RiskLevel
    log_type: str
    created_at: str
    updated_at: str
    error_message: str | None = None


class LogSummaryPage(BaseModel):
    items: list[LogSummary]
    page: int
    page_size: int
    total: int
    total_pages: int
    available_log_types: list[str] = Field(default_factory=list)


class AiUsagePoint(BaseModel):
    """一次历史 AI 研判的用量点，用于前端画跨分析趋势。

    `usage` 为 `None` 表示该次研判没有留下用量记录（例如工具轮次中途失败后
    走降级路径的旧数据）。刻意不用 0 填充——「没记录」和「消耗为 0」是两回事，
    混在一起会把趋势图画出误导性的低谷。
    """

    analysis_id: str
    filename: str
    log_type: str
    created_at: str
    usage: dict[str, Any] | None = None


class AiUsageHistory(BaseModel):
    points: list[AiUsagePoint] = Field(default_factory=list)
    # 汇总只统计 usage 非空的点，并明确告知样本量，避免把残缺数据当成全量结论
    with_usage: int = 0
    total_points: int = 0
    avg_prompt_tokens: int = 0
    avg_completion_tokens: int = 0
    avg_cache_hit_ratio: float | None = None


class UploadResponse(BaseModel):
    analysis_id: str
    result: AnalysisResult


class AiConfigStatus(BaseModel):
    configured: bool
    provider: str
    model: str
    base_url: str
    api_key_present: bool
    message: str
    supported_providers: list[str] = Field(default_factory=list)
    provider_presets: dict[str, dict[str, object]] = Field(default_factory=dict)


class AiConfigUpdate(BaseModel):
    provider: str
    base_url: str = ""
    model: str = ""
    api_key: str | None = None
    clear_api_key: bool = False


class DemoAnalyzeRequest(BaseModel):
    files: list[str] = Field(min_length=1, max_length=20)


class RuleQualityRule(BaseModel):
    rule_id: str
    positive: int = 0
    tp: int = 0
    fp: int = 0
    fn: int = 0


class RuleQualityCase(BaseModel):
    name: str
    family: str
    expected: str
    actual: str
    ok: bool
    details: list[str] = Field(default_factory=list)


class RuleQualityReport(BaseModel):
    case_count: int = 0
    passed_count: int = 0
    rule_count: int = 0
    # 内置规则（自己写的）必须每条都有本地正样本；导入的社区规则做不到，单独统计并显式列出，
    # 不能混进「已覆盖」里蒙过去。
    builtin_rule_count: int = 0
    imported_rule_count: int = 0
    covered_rule_count: int = 0
    unverified_rule_count: int = 0
    duplicate_hit_count: int = 0
    true_positive: int = 0
    false_positive: int = 0
    false_negative: int = 0
    precision: float = 1.0
    recall: float = 1.0
    uncovered_rules: list[str] = Field(default_factory=list)
    unverified_rules: list[str] = Field(default_factory=list)
    duplicate_hits: list[str] = Field(default_factory=list)
    rules: list[RuleQualityRule] = Field(default_factory=list)
    cases: list[RuleQualityCase] = Field(default_factory=list)


class AttackCoverageTechnique(BaseModel):
    technique_id: str
    name: str
    tactic: str = ""
    # 技术来源：`external` = 外部参考集（EVTX-to-MITRE-Attack）原有；`project` = 本项目补充。
    # 分开标注是为了不让「自选清单」冒充「外部标尺」——覆盖率必须说清是在哪份清单上算的。
    origin: str = "external"
    covered: bool = False
    rule_ids: list[str] = Field(default_factory=list)
    # 「有规则」与「有本地正样本验证」是两件事：前者只说明写了规则，后者才说明跑通过。
    local_sample_count: int = 0


class AttackCoverageReport(BaseModel):
    source: str
    source_url: str = ""
    # 外部参考集规模：只作标尺，**没有打包进本仓库**（第三方样本的许可与处置风险）
    reference_sample_count: int = 0
    reference_packaged: bool = False
    # 外部参考集是一份**优先清单**，不等于 ATT&CK 全量技术，别把覆盖率当「覆盖了所有手法」
    scope_note: str = ""
    local_case_count: int = 0
    local_whole_log_case_count: int = 0
    local_chain_case_count: int = 0
    technique_count: int = 0
    covered_technique_count: int = 0
    coverage_ratio: float = 0.0
    # 按来源拆分的覆盖口径：外部参考集原有技术 vs 本项目补充技术。
    # 两者分开统计，避免把「自己加进来的技术」算成「外部基准的覆盖率」。
    external_technique_count: int = 0
    external_covered_count: int = 0
    project_technique_count: int = 0
    project_covered_count: int = 0
    sample_validated_technique_count: int = 0
    sample_validation_ratio: float = 0.0
    uncovered_techniques: list[str] = Field(default_factory=list)
    covered_without_sample: list[str] = Field(default_factory=list)
    techniques: list[AttackCoverageTechnique] = Field(default_factory=list)


class SigmaConvertedRule(BaseModel):
    id: str
    title: str
    level: RiskLevel = "info"
    tags: list[str] = Field(default_factory=list)
    path: str = ""
    rule: dict[str, Any] = Field(default_factory=dict)


class SigmaSkippedRule(BaseModel):
    path: str
    title: str
    reason: str


class SigmaImportReport(BaseModel):
    total: int = 0
    converted_count: int = 0
    skipped_count: int = 0
    converted: list[SigmaConvertedRule] = Field(default_factory=list)
    skipped: list[SigmaSkippedRule] = Field(default_factory=list)


class LogRecord(BaseModel):
    record_id: str | None = None
    evidence_id: str | None = None
    timestamp: str | None = None
    timestamp_iso: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    username: str | None = None
    action: str | None = None
    result: str | None = None
    status: str | None = None
    url: str | None = None
    destination_port: str | None = None
    protocol: str | None = None
    process_image: str | None = None
    command_line: str | None = None
    parent_image: str | None = None
    process_id: str | None = None
    parent_process_id: str | None = None
    target_filename: str | None = None
    service_name: str | None = None
    service_state: str | None = None
    registry_key: str | None = None
    query_name: str | None = None
    query_results: str | None = None
    target_asset: str | None = None
    event_id: str | None = None
    whitelisted_by: str | None = None
    source_file: str | None = None
    log_type: str | None = None
    raw: str | None = None


class LogRecordPage(BaseModel):
    items: list[LogRecord]
    page: int
    page_size: int
    total: int
    total_pages: int
    available_log_types: list[str] = Field(default_factory=list)


class EntityInvestigation(BaseModel):
    """按实体（IP / 账号 / 主机 / 域名 / 进程）查看关联记录、事件与时间线。

    `records` 分页，`events` 与 `timeline` 按上限截断——真实条数放 `events_total` /
    `timeline_total`，界面必须把「已展示 N / 共 M」讲清楚，否则等于谎报。
    实体匹配一律**精确匹配**（忽略大小写），不做子串包含：取证视图里
    `10.0.0.8` 命中 `10.0.0.80` 属于制造不存在的关联。
    """

    kind: str
    value: str
    records: LogRecordPage
    events: list[Event] = Field(default_factory=list)
    events_total: int = 0
    timeline: list[TimelineEntry] = Field(default_factory=list)
    timeline_total: int = 0


class ThreatIntelSourceResult(BaseModel):
    """一个情报源对一个指标的查询结果。

    `status == "not_listed"` 只表示「该库未收录」，**不等于安全**；
    `confidence` 是来源方给出的置信度（0~1），不是本项目判定。
    """

    source: str
    status: Literal["hit", "not_listed", "error", "skipped"]
    confidence: float | None = Field(default=None, ge=0, le=1)
    detail: str = ""
    link: str | None = None


class ThreatIntelFinding(BaseModel):
    """一个指标（公网 IP / 域名）在所有情报源上的查询结果汇总。

    独立于 `events` 展示：命中情报库不改变风险等级，也不进入 AI 上下文——
    情报库的收录口径与日志证据是两回事，混进判定链会把第三方数据当成事实。
    """

    indicator_type: Literal["ip", "domain"]
    value: str
    origins: list[str] = Field(default_factory=list)
    related_events: int = 0
    sources: list[ThreatIntelSourceResult] = Field(default_factory=list)
    summary: str = ""


class ThreatIntelReport(BaseModel):
    """威胁情报富化报告：把研判中的公网指标送到公开情报库比对。

    默认关闭（`THREAT_INTEL_ENABLED`）：查询会把指标发送到外部服务，
    本地优先的工具必须由用户显式开启。
    """

    analysis_id: str
    enabled: bool = False
    generated_at: str = ""
    indicators_total: int = 0
    findings: list[ThreatIntelFinding] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    note: str = ""


class SeverityCell(BaseModel):
    """一档风险的小结：事件数 + 命中规则数（Zircolite 概览卡片的口径）。"""

    risk_level: RiskLevel
    events: int = 0
    rules: int = 0


class TacticCell(BaseModel):
    """一个 ATT&CK 战术格的计数。`phase_index` 用于按攻击阶段排序（不是字母序）。"""

    tactic: str
    phase_index: int = 99
    events: int = 0
    rules: int = 0


class TopItem(BaseModel):
    """Top 榜单条目：规则 / 主机 / 来源 IP 共用。"""

    key: str
    label: str = ""
    risk_level: RiskLevel = "info"
    events: int = 0
    rules: int = 0


class AnalysisDashboard(BaseModel):
    """仿 Zircolite 概览页的看板数据。

    全部由既有 `events` / `records` 推导，**不新增判定、不改风险等级**——
    它只是同一批事实的另一种排布方式。注意两个单位不要混：
    `events_total` 是事件数，`buckets[].count` 是记录数。
    """

    analysis_id: str
    events_total: int = 0
    covered_records: int = 0
    total_records: int = 0
    severities: list[SeverityCell] = Field(default_factory=list)
    buckets: list[TimeBucket] = Field(default_factory=list)
    tactics: list[TacticCell] = Field(default_factory=list)
    techniques: list[TopItem] = Field(default_factory=list)
    top_rules: list[TopItem] = Field(default_factory=list)
    top_hosts: list[TopItem] = Field(default_factory=list)
    top_ips: list[TopItem] = Field(default_factory=list)
    generated_at: str = ""
    note: str = ""


class DetectionVariant(BaseModel):
    """同一规则在不同实体上的一次命中（Zircolite 的「变体」行）。"""

    event_id: str
    label: str = ""
    risk_level: RiskLevel = "info"
    events: int = 0
    first_seen: str | None = None
    summary: str = ""


class DetectionGroup(BaseModel):
    """一条规则的检测汇总。

    `event_count` 是**事件条数**，`trigger_count` 是这些事件的**触发次数合计**——
    两者在不同日志上差别很大（一次聚合事件可能代表几百次触发），界面必须分开写清。
    """

    rule_id: str
    name: str
    risk_level: RiskLevel
    tactic: str = "其他"
    technique: str = ""
    event_count: int = 0
    trigger_count: int = 0
    source: str = "unknown"
    description: str = ""
    tags: list[str] = Field(default_factory=list)
    author: str | None = None
    version: str | None = None
    license: str | None = None
    references: list[str] = Field(default_factory=list)
    validation_status: str = "unverified"
    enabled: bool = True
    first_seen: str | None = None
    last_seen: str | None = None
    source_files: list[str] = Field(default_factory=list)
    entities: list[str] = Field(default_factory=list)
    variants: list[DetectionVariant] = Field(default_factory=list)
    variants_total: int = 0


class DetectionsReport(BaseModel):
    """检测视图：按规则归组的命中汇总（只归组，不改判定）。"""

    analysis_id: str
    groups_total: int = 0
    groups: list[DetectionGroup] = Field(default_factory=list)
    generated_at: str = ""
    note: str = ""


class AttackTechniqueCell(BaseModel):
    """ATT&CK 矩阵里的一个技术格。

    `in_benchmark=False` 表示该技术不在项目内置标尺清单里，但**本次确实命中了**——
    如实显示，不因为是清单外的手法就藏起来。
    """

    technique: str
    name: str = ""
    tactic: str = "其他"
    events: int = 0
    rules: list[str] = Field(default_factory=list)
    in_benchmark: bool = True
    #: 命中该技术的事件里最高的风险等级（导出 ATT&CK Navigator 时用于着色）
    risk_level: RiskLevel = "info"


class AttackTacticColumn(BaseModel):
    """一个战术列：该战术下的技术与事件合计。"""

    tactic: str
    phase_index: int = 99
    events: int = 0
    techniques: list[AttackTechniqueCell] = Field(default_factory=list)


class AttackMatrix(BaseModel):
    """ATT&CK 战术 × 技术两级矩阵（只映射与计数，不改判定）。"""

    analysis_id: str
    columns: list[AttackTacticColumn] = Field(default_factory=list)
    techniques_total: int = 0
    techniques_hit: int = 0
    events_total: int = 0
    generated_at: str = ""
    note: str = ""


class SearchTerm(BaseModel):
    """一个查询词项：字段（可空 = 全文）、值、是否取反。"""

    field: str | None = None
    value: str
    negated: bool = False


class SearchResult(BaseModel):
    """搜索语法查询结果。

    `records` 是**原始事实**、`events` 是**规则结论**，单位不同，因此各自给总数——
    混成一个数字会让「3 条记录 / 1 个事件」被读成「3 个事件」。
    `warnings` 非空表示有词项没被完整理解（例如字段名拼错），**不能静默忽略**。
    """

    analysis_id: str
    query: str
    terms: list[SearchTerm] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    records: list[LogRecord] = Field(default_factory=list)
    records_total: int = 0
    events: list[Event] = Field(default_factory=list)
    events_total: int = 0
    page: int = 1
    page_size: int = 50


class FacetValue(BaseModel):
    """一个字段取值及其出现次数。"""

    value: str
    count: int = 0


class FacetField(BaseModel):
    """字段概览：覆盖率 + 取值 Top。

    `coverage` 低**不代表该字段没有异常**，只说明这份日志里它基本没被填过；
    `values_total` 是去重取值总数，`values` 是截断后的 Top N——截断处必须能报出真实总数。
    """

    name: str
    label: str = ""
    coverage: float = 0.0
    present_records: int = 0
    values_total: int = 0
    values: list[FacetValue] = Field(default_factory=list)


class LogFacets(BaseModel):
    analysis_id: str
    total_records: int = 0
    fields: list[FacetField] = Field(default_factory=list)
    note: str = ""
