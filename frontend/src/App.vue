<script setup lang="ts">
import {
  computed,
  defineComponent,
  h,
  nextTick,
  onBeforeUnmount,
  onMounted,
  ref,
  watch,
  type PropType,
} from "vue";

type TimelineEntry = {
  timestamp: string | null;
  timestamp_iso: string | null;
  kind: "event" | "evidence";
  title: string;
  risk_level: string;
  rule_id: string | null;
  source_ip: string | null;
  username: string | null;
  record_id: string | null;
  source_file: string | null;
  detail: string | null;
};

type EventItem = {
  id: string;
  name: string;
  type: string;
  risk_level: string;
  source_ip: string | null;
  count: number;
  summary: string;
  evidence: string[];
  evidence_items: {
    id: string;
    record_id: string | null;
    timestamp: string | null;
    source_file: string | null;
    source_ip: string | null;
    destination_ip: string | null;
    username: string | null;
    url: string | null;
    raw: string;
  }[];
  timeline: string[];
  source_files: string[];
  correlation_basis: string[];
  rule_id: string | null;
};

type AiBehavior = {
  type: string;
  name: string;
  confidence: number;
  evidence: string[];
  evidence_ids: string[];
  analysis: string;
};

type StructuredVerdict = {
  event_time: string | null;
  attack_source_ip: string | null;
  target_asset: string | null;
  involved_account: string | null;
  abnormal_behavior: string | null;
  related_logs: string[];
  attack_type: string | null;
  risk_level: string;
  judgment_basis: string | null;
  success_indicator: string | null;
  recommended_actions: string[];
};

type Result = {
  id: string;
  metadata: {
    filename: string;
    source_files: string[];
    log_type: string;
    recognition_confidence: number;
    total_lines: number;
    parsed_lines: number;
    time_range: { start: string | null; end: string | null };
  };
  statistics: {
    failed_login: number;
    successful_login: number;
    top_source_ips: { value: string; count: number }[];
    status_codes: { value: string; count: number }[];
  };
  events_total?: number | null;
  events: EventItem[];
  coverage?: {
    total_records: number;
    evaluable_records: number;
    covered_records: number;
    uncovered_records: number;
    parse_failures: number;
    parse_errors: number;
    retention_drops: number;
    whitelisted_records: number;
    parse_error_details: {
      source_file?: string;
      line_number?: number;
      reason?: string;
      raw_preview?: string;
    }[];
    limitation: string | null;
  };
  behavior_deviations?: {
    kind: string;
    name: string;
    basis: string;
    detail: string;
    count: number;
    evidence: string[];
  }[];
  templates: { template: string; count: number; ratio: number; rare: boolean }[];
  entities: {
    kind: string;
    value: string;
    risk_level: string;
    record_count: number;
    event_count: number;
    rule_ids: string[];
    log_types: string[];
    source_files: string[];
    first_seen: string | null;
    last_seen: string | null;
    summary: string;
  }[];
  timeline: TimelineEntry[];
  terminal_chains: {
    chain_id: string;
    target_asset: string | null;
    risk_level: string;
    record_count: number;
    first_seen: string | null;
    last_seen: string | null;
    summary: string;
    nodes: {
      timestamp: string | null;
      timestamp_iso: string | null;
      kind: string;
      title: string;
      evidence_id: string | null;
      record_id: string | null;
      source_file: string | null;
      target_asset: string | null;
      process_image: string | null;
      command_line: string | null;
      parent_image: string | null;
      process_id: string | null;
      parent_process_id: string | null;
      target_filename: string | null;
      service_name: string | null;
      service_state: string | null;
      registry_key: string | null;
      query_name: string | null;
      query_results: string | null;
      destination_ip: string | null;
      destination_port: string | null;
      event_id: string | null;
      detail: string | null;
      risk_level: string;
    }[];
    relationships: {
      kind: string;
      from_record_id: string | null;
      to_record_id: string | null;
      from_evidence_id: string | null;
      to_evidence_id: string | null;
      confidence: "strong" | "medium" | "weak";
      basis: string;
    }[];
  }[];
  has_suspicious_behavior: boolean;
  risk_level: string;
  confidence: number;
  conclusion: string;
  analysis_source: "rules" | "ai" | "rules_and_ai";
  ai_status: "not_analyzed" | "completed" | "unavailable";
  ai_error: string | null;
  risk_score: number;
  risk_score_enabled: boolean;
  risk_scores: {
    source_ip: string;
    key?: string;
    kind?: string;
    score: number;
    baseline_level: string;
    escalated_level: string;
    escalated: boolean;
    rule_ids: string[];
  }[];
  ai_behaviors: AiBehavior[];
  ai_tool_trace: { tool: string; arguments: Record<string, unknown>; summary: string; source: string; usage?: Record<string, number> | null }[];
  ai_unsupported_claims: string[];
  structured_verdict: StructuredVerdict | null;
  summary: string;
  recommendations: string[];
};

type LogSummary = {
  id: string;
  filename: string;
  status: "processing" | "completed" | "failed";
  risk_level: string;
  log_type: string;
  created_at: string;
  updated_at: string;
  error_message: string | null;
};

type LogSummaryPage = {
  items: LogSummary[];
  page: number;
  page_size: number;
  total: number;
  total_pages: number;
  available_log_types: string[];
};

// 一次历史研判的用量点。usage 为 null 表示该次研判没有留下用量记录
// （例如工具轮次中途失败后走降级路径的旧数据）——不能当成「消耗为 0」。
type AiUsagePoint = {
  analysis_id: string;
  filename: string;
  log_type: string;
  created_at: string;
  usage: Record<string, number> | null;
};

type AiUsageHistory = {
  points: AiUsagePoint[];
  with_usage: number;
  total_points: number;
  avg_prompt_tokens: number;
  avg_completion_tokens: number;
  avg_cache_hit_ratio: number | null;
};

type AiLedger = {
  analysis_id: string;
  created_at: string;
  status: "completed" | "unavailable";
  provider: string;
  model: string;
  duration_ms: number;
  tool_trace: {
    tool: string;
    arguments: Record<string, unknown>;
    summary: string;
    source: "auto" | "model";
    usage?: Record<string, unknown> | null;
  }[];
  evidence_ids: string[];
  unsupported_claims: string[];
  usage: Record<string, unknown> | null;
  summary: string;
};

type RulePreviewReport = {
  valid: boolean;
  errors: string[];
  rule_ids: string[];
  event_count: number;
  covered_records: number;
  true_positive: number;
  false_positive: number;
  false_negative: number;
  rollback_required: boolean;
  events: EventItem[];
};

// AI 结论的人工确认状态。history 为空即「未确认」——后端不为「没人看过」造记录。
type ReviewStatus = "pending" | "confirmed" | "rejected" | "needs_review";

type HumanReview = {
  analysis_id: string;
  status: ReviewStatus;
  reviewer: string;
  note: string;
  updated_at: string | null;
  history: {
    id: number;
    status: ReviewStatus;
    reviewer: string;
    note: string;
    created_at: string;
  }[];
};

// 实体调查：按实体（IP / 账号 / 主机 / 域名 / 进程）查关联记录、事件与时间线。
// 实体值由后端精确匹配；events / timeline 有上限，真实条数在 *_total，
// 界面必须把「已展示 N / 共 M」讲清楚，不能只说 N。
type EntityInvestigation = {
  kind: string;
  value: string;
  records: RecordPage;
  events: EventItem[];
  events_total: number;
  timeline: TimelineEntry[];
  timeline_total: number;
};

type AiConfig = {
  configured: boolean;
  provider: string;
  model: string;
  base_url: string;
  api_key_present: boolean;
  message: string;
  supported_providers: string[];
  provider_presets: Record<string, { base_url: string; models: string[] }>;
};

type DemoLog = {
  name: string;
  path: string;
  category: string;
  description: string;
  size: number;
};

type AiConnection = {
  configured: boolean;
  reachable: boolean;
  provider: string;
  model: string;
  message: string;
};

type LogRecord = {
  record_id: string | null;
  evidence_id: string | null;
  timestamp: string | null;
  timestamp_iso: string | null;
  source_ip: string | null;
  destination_ip: string | null;
  username: string | null;
  action: string | null;
  result: string | null;
  status: string | null;
  url: string | null;
  destination_port: string | null;
  protocol: string | null;
  process_image: string | null;
  command_line: string | null;
  parent_image: string | null;
  process_id: string | null;
  parent_process_id: string | null;
  target_filename: string | null;
  service_name: string | null;
  service_state: string | null;
  registry_key: string | null;
  query_name: string | null;
  query_results: string | null;
  target_asset: string | null;
  event_id: string | null;
  whitelisted_by?: string | null;
  source_file: string | null;
  log_type: string | null;
  raw: string | null;
};

type RecordPage = {
  items: LogRecord[];
  page: number;
  page_size: number;
  total: number;
  total_pages: number;
  available_log_types: string[];
};

type TimeBucket = {
  start_iso: string;
  label: string;
  count: number;
  unique_source_ips: number;
  failed_login: number;
  successful_login: number;
};

type AttackChainStage = {
  phase: string;
  tactic: string;
  technique: string;
  event_type: string;
  name: string;
  risk_level: string;
  source_ip: string | null;
  first_seen: string | null;
  last_seen: string | null;
  count: number;
  rule_id: string | null;
  summary: string;
};

type AttackChain = {
  key: string;
  kind: string;
  risk_level: string;
  stages: AttackChainStage[];
};

type Insights = {
  timeseries: TimeBucket[];
  attack_chains: AttackChain[];
  // 攻击链条数 = 来源 IP 数，可能上千条；列表按上限返回，真实条数在这里
  attack_chains_total?: number;
};

// 威胁情报富化：公网指标送公开情报库比对，独立展示，不改变风险等级
type ThreatIntelSourceResult = {
  source: string;
  status: "hit" | "not_listed" | "error" | "skipped";
  confidence: number | null;
  detail: string;
  link: string | null;
};

type ThreatIntelFinding = {
  indicator_type: "ip" | "domain";
  value: string;
  origins: string[];
  related_events: number;
  sources: ThreatIntelSourceResult[];
  summary: string;
};

type ThreatIntelReport = {
  analysis_id: string;
  enabled: boolean;
  generated_at: string;
  indicators_total: number;
  findings: ThreatIntelFinding[];
  errors: string[];
  note: string;
};

// 概览看板（仿 Zircolite Overview）：严重度卡片、时间分布、ATT&CK 战术网格、Top 榜单
type SeverityCell = {
  risk_level: string;
  events: number;
  rules: number;
};

type TacticCell = {
  tactic: string;
  phase_index: number;
  events: number;
  rules: number;
};

type TopItem = {
  key: string;
  label: string;
  risk_level: string;
  events: number;
  rules: number;
};

type DashboardBucket = {
  start_iso: string;
  label: string;
  count: number;
  unique_source_ips: number;
  failed_login: number;
  successful_login: number;
  levels: Record<string, number>;
};

type AnalysisDashboard = {
  analysis_id: string;
  events_total: number;
  covered_records: number;
  total_records: number;
  severities: SeverityCell[];
  buckets: DashboardBucket[];
  tactics: TacticCell[];
  techniques: TopItem[];
  top_rules: TopItem[];
  top_hosts: TopItem[];
  top_ips: TopItem[];
  generated_at: string;
  note: string;
};

// 字段概览（facet）：覆盖率 + 取值 Top
type FacetValue = { value: string; count: number };
type FacetField = {
  name: string;
  label: string;
  coverage: number;
  present_records: number;
  values_total: number;
  values: FacetValue[];
};
type LogFacets = {
  analysis_id: string;
  total_records: number;
  fields: FacetField[];
  note: string;
};

/** 明细筛选参数名（由 emptyRecordFilters 推导，避免两处各写一份字段清单） */
type RecordFilters = ReturnType<typeof emptyRecordFilters>;

/** 字段 → 明细筛选参数名（能走服务端筛选的走筛选，其余走搜索语法） */
const FACET_FILTER_PARAMS: Record<string, keyof RecordFilters> = {
  source_ip: "source_ip",
  destination_ip: "destination_ip",
  url: "path",
  log_type: "log_type",
  action: "action",
  status: "status",
};

// 进程树（由终端证据链的进程节点构建，不新增接口）
type ProcessNode = {
  key: string;
  asset: string;
  image: string;
  pid: string;
  ppid: string;
  kinds: string[];
  records: string[];
  risk: string;
  children: ProcessNode[];
  /** 父进程不在本次日志中（不猜、不造一个父节点，只标注） */
  orphan: boolean;
};

// 搜索语法查询
type SearchTerm = { field: string | null; value: string; negated: boolean };

type SearchResult = {
  analysis_id: string;
  query: string;
  terms: SearchTerm[];
  warnings: string[];
  records: LogRecord[];
  records_total: number;
  events: EventItem[];
  events_total: number;
  page: number;
  page_size: number;
};

// ATT&CK 矩阵（战术 × 技术两级）
type AttackTechniqueCell = {
  technique: string;
  name: string;
  tactic: string;
  events: number;
  rules: string[];
  in_benchmark: boolean;
};

type AttackTacticColumn = {
  tactic: string;
  phase_index: number;
  events: number;
  techniques: AttackTechniqueCell[];
};

type AttackMatrix = {
  analysis_id: string;
  columns: AttackTacticColumn[];
  techniques_total: number;
  techniques_hit: number;
  events_total: number;
  generated_at: string;
  note: string;
};

// 检测视图（按规则归组）
type DetectionVariant = {
  event_id: string;
  label: string;
  risk_level: string;
  events: number;
  first_seen: string | null;
  summary: string;
};

type DetectionGroup = {
  rule_id: string;
  name: string;
  risk_level: string;
  tactic: string;
  technique: string;
  event_count: number;
  trigger_count: number;
  source: string;
  description: string;
  tags: string[];
  author: string | null;
  version: string | null;
  license: string | null;
  references: string[];
  validation_status: string;
  enabled: boolean;
  first_seen: string | null;
  last_seen: string | null;
  source_files: string[];
  entities: string[];
  variants: DetectionVariant[];
  variants_total: number;
};

type DetectionsReport = {
  analysis_id: string;
  groups_total: number;
  groups: DetectionGroup[];
  generated_at: string;
  note: string;
};

type PageItem = number | "gap";

const RISK_LABELS: Record<string, string> = {
  critical: "严重",
  high: "高风险",
  medium: "中风险",
  low: "低风险",
  info: "信息",
};
const RISK_ORDER = ["critical", "high", "medium", "low", "info"];
const STATUS_LABELS: Record<string, string> = {
  completed: "已完成",
  processing: "分析中",
  failed: "失败",
};

function emptyRecordFilters() {
  return {
    source_ip: "",
    destination_ip: "",
    path: "",
    log_type: "",
    action: "",
    status: "",
  };
}

/* ---------- 视图与筛选状态 ---------- */

const view = ref<"list" | "detail">("list");
const detailLoading = ref(false);
const healthOk = ref(false);

const listFilters = ref({
  keyword: "",
  log_type: "",
  risk_level: "",
  status: "",
  sort: "created_desc",
});
const listPage = ref(1);
const listPageSize = ref(10);

const recordFilters = ref(emptyRecordFilters());
const recordPageSize = ref(50);

/* ---------- 数据状态 ---------- */

const files = ref<File[]>([]);
const demoLogs = ref<DemoLog[]>([]);
const selectedDemoLogs = ref<string[]>([]);
const dragActive = ref(false);
const uploadOpen = ref(false);
const result = ref<Result | null>(null);
const history = ref<LogSummary[]>([]);
const historyTotal = ref(0);
const historyLogTypes = ref<string[]>([]);
// 跨分析的用量趋势：数据来自后端从 result_json 里抽取的用量记录
const usageHistory = ref<AiUsageHistory | null>(null);
const usageChartMode = ref<"tokens" | "cache">("tokens");
const loading = ref(false);
const records = ref<RecordPage | null>(null);
const recordLoading = ref(false);
const selectedRecordId = ref("");
const error = ref("");
const notice = ref("");
const insights = ref<Insights | null>(null);
const dashboard = ref<AnalysisDashboard | null>(null);
const dashboardLoading = ref(false);
// 概览里的严重度卡片可直接带上风险过滤跳到「检测」视图
const detectionLevelFilter = ref("");
/** 展开的进程节点 key 集合；超过阈值时默认只展开根节点（避免一屏几百行） */
const expandedProcess = ref<string[]>([]);
const facets = ref<LogFacets | null>(null);
const expandedFacetFields = ref<string[]>([]);
const searchQuery = ref("");
const searchResult = ref<SearchResult | null>(null);
const searchLoading = ref(false);
const SEARCH_FIELD_HINTS = [
  "source_ip", "destination_ip", "username", "status", "url", "query_name",
  "process", "command_line", "host", "event_id", "log_type", "source_file",
];
const attackMatrix = ref<AttackMatrix | null>(null);
/** 默认只看命中的技术；关掉后展示完整标尺清单（含 0 值格子）。 */
const attackFullMatrix = ref(false);
/** 展开的 ATT&CK 技术格（看它由哪些规则报出来） */
const expandedTechniques = ref<string[]>([]);
const detections = ref<DetectionsReport | null>(null);
const detectionsLoading = ref(false);
/** 检测视图里展开规则详情的规则编号集合（默认全部收起，避免一屏上百行） */
const expandedRules = ref<string[]>([]);
const threatIntel = ref<ThreatIntelReport | null>(null);
const threatIntelLoading = ref(false);
const ledgerOpen = ref(false);
const ledgerLoading = ref(false);
const aiLedger = ref<AiLedger | null>(null);
const previewOpen = ref(false);
const previewLoading = ref(false);
const previewError = ref("");
const previewReport = ref<RulePreviewReport | null>(null);
const previewForm = ref({
  yaml_text: "",
  sample_log: "",
  filename: "preview.log",
});

const aiLoading = ref(false);
const theme = ref<"light" | "dark">("light");

// 人工确认：AI 推断不能自动变成事实，必须有人落笔
const humanReview = ref<HumanReview | null>(null);
const reviewSaving = ref(false);
const reviewForm = ref<{ status: ReviewStatus; reviewer: string; note: string }>({
  status: "confirmed",
  reviewer: "",
  note: "",
});

const REVIEW_STATUS_LABELS: Record<ReviewStatus, string> = {
  pending: "未确认",
  confirmed: "确认",
  rejected: "否定",
  needs_review: "需复核",
};

const REVIEW_OPTIONS: { value: ReviewStatus; label: string; hint: string }[] = [
  { value: "confirmed", label: "确认", hint: "证据支持该结论" },
  { value: "rejected", label: "否定", hint: "判定为误报" },
  { value: "needs_review", label: "需复核", hint: "证据不足，待补材料" },
  { value: "pending", label: "退回未确认", hint: "撤销此前的确认" },
];

const reviewStatusText = computed(
  () => REVIEW_STATUS_LABELS[humanReview.value?.status ?? "pending"],
);

// 实体调查：从「实体关联」表点进完整调查视图
const entityOpen = ref(false);
const entityLoading = ref(false);
const entityError = ref("");
const entityDetail = ref<EntityInvestigation | null>(null);
const ENTITY_PAGE_SIZE = 50;

// 明暗两套 logo：浅色版是深色字，深色版是白色字（两版均已抠成透明底，可贴合任意主题背景）
const brandLogo = computed(() =>
  theme.value === "dark" ? "/logo-dark.png" : "/logo-light.png",
);

function applyTheme() {
  document.documentElement.dataset.theme = theme.value;
}

function toggleTheme() {
  theme.value = theme.value === "dark" ? "light" : "dark";
  localStorage.setItem("loginsight-theme", theme.value);
  applyTheme();
}
const aiProgressActive = ref(0);
const aiProgressPercent = ref(0);
const aiPartialText = ref("");

// 事件列表按上限加载：大记录曾有 7536 个事件 / 37 MB，一次全量会让页面卡在「正在加载」
const EVENTS_DEFAULT_LIMIT = 200;
const EVENTS_PAGE_STEP = 200;
const eventLimit = ref(EVENTS_DEFAULT_LIMIT);
const eventsTotal = computed(() => result.value?.events_total ?? result.value?.events.length ?? 0);
const eventsTruncated = computed(
  () => !!result.value && result.value.events.length < eventsTotal.value,
);

// 攻击链同理：链数 = 来源 IP 数，认证导出可到 2000 条，一次全量会让浏览器渲染几千张卡片
const CHAINS_DEFAULT_LIMIT = 20;
const CHAINS_PAGE_STEP = 20;
const chainLimit = ref(CHAINS_DEFAULT_LIMIT);
const chainsTotal = computed(
  () => insights.value?.attack_chains_total ?? insights.value?.attack_chains.length ?? 0,
);
const chainsTruncated = computed(
  () => !!insights.value && insights.value.attack_chains.length < chainsTotal.value,
);

// ---------- 概览看板（仿 Zircolite Overview） ----------

/** 严重度卡片：按风险从高到低，空档也保留（「这一档没有」本身就是信息）。 */
const severityCards = computed(() => {
  const cells = dashboard.value?.severities ?? [];
  const order = RISK_ORDER;
  return [...cells].sort((a, b) => order.indexOf(a.risk_level) - order.indexOf(b.risk_level));
});

/** 时间分布的上轴（记录数）与下轴（事件数）各自归一化——两个单位不能共用一个最大值。 */
const stripMaxRecords = computed(() =>
  Math.max(1, ...(dashboard.value?.buckets ?? []).map((bucket) => bucket.count)),
);
const stripMaxDetections = computed(() =>
  Math.max(
    1,
    ...(dashboard.value?.buckets ?? []).map((bucket) =>
      Object.values(bucket.levels).reduce((sum, value) => sum + value, 0),
    ),
  ),
);
/** 柱高用平方根缩放：少数高峰会把其余柱子压成一条线（与 Zircolite 同一处理）。 */
function stripHeight(value: number, max: number) {
  if (!value) return 0;
  return Math.max(3, Math.sqrt(value / max) * 100);
}
/** 下轴按风险分层：最严重的一层贴近中轴，便于一眼看出「哪个时段出了严重事件」。 */
function stripLayers(bucket: DashboardBucket) {
  return RISK_ORDER.filter((level) => (bucket.levels[level] ?? 0) > 0).map((level) => ({
    level,
    count: bucket.levels[level],
    height: stripHeight(bucket.levels[level], stripMaxDetections.value),
  }));
}
function stripDetections(bucket: DashboardBucket) {
  return Object.values(bucket.levels).reduce((sum, value) => sum + value, 0);
}
function bucketTip(bucket: DashboardBucket) {
  const layers = stripLayers(bucket)
    .map((layer) => `${riskText(layer.level)} ${layer.count}`)
    .join(" · ");
  return `${bucket.label} · 记录 ${bucket.count}${layers ? ` · 事件 ${stripDetections(bucket)}（${layers}）` : ""}`;
}

/** ATT&CK 战术网格：按最忙的战术归一化，用深浅表示相对规模。 */
const tacticMaxEvents = computed(() =>
  Math.max(1, ...(dashboard.value?.tactics ?? []).map((cell) => cell.events)),
);
function tacticHeat(cell: TacticCell) {
  const share = cell.events / tacticMaxEvents.value;
  return { opacity: cell.events ? 0.12 + 0.78 * Math.sqrt(share) : 0 };
}
const tacticGrid = computed(() => dashboard.value?.tactics ?? []);

/** 事件列表的风险过滤：概览卡片点一下就能看到「这一档到底有哪些事件」。 */
const visibleEvents = computed(() => {
  const events = result.value?.events ?? [];
  if (!detectionLevelFilter.value) return events;
  return events.filter((item) => item.risk_level === detectionLevelFilter.value);
});

const PROCESS_AUTO_EXPAND_LIMIT = 300;

/**
 * 从终端证据链的进程节点构建进程树。
 *
 * 口径：**只连日志里真实存在的父子关系**（同一资产内按 PID/父 PID 匹配）；
 * 父进程不在本次日志中时标为根并注明，不凭 PID 大小或时间猜测父节点。
 */
const processTrees = computed(() => {
  const chains = result.value?.terminal_chains ?? [];
  const byAsset = new Map<string, Map<string, ProcessNode>>();

  for (const chain of chains) {
    for (const node of chain.nodes as Record<string, unknown>[]) {
      const pid = String(node.process_id ?? "").trim();
      const image = String(node.process_image ?? "").trim();
      if (!pid || !image) continue;
      const asset = String(node.target_asset ?? chain.target_asset ?? "未知资产");
      const registry = byAsset.get(asset) ?? new Map<string, ProcessNode>();
      byAsset.set(asset, registry);
      const key = `${asset}#${pid}`;
      const existing = registry.get(key);
      if (existing) {
        const kind = String(node.kind ?? "");
        if (kind && !existing.kinds.includes(kind)) existing.kinds.push(kind);
        const recordId = String(node.record_id ?? "");
        if (recordId && !existing.records.includes(recordId)) existing.records.push(recordId);
        const risk = String(node.risk_level ?? "info");
        if (RISK_ORDER.indexOf(risk) < RISK_ORDER.indexOf(existing.risk)) existing.risk = risk;
        continue;
      }
      registry.set(key, {
        key,
        asset,
        image,
        pid,
        ppid: String(node.parent_process_id ?? "").trim(),
        kinds: [String(node.kind ?? "")].filter(Boolean),
        records: [String(node.record_id ?? "")].filter(Boolean),
        risk: String(node.risk_level ?? "info"),
        children: [],
        orphan: false,
      });
    }
  }

  const trees: { asset: string; roots: ProcessNode[]; total: number }[] = [];
  for (const [asset, registry] of byAsset) {
    const roots: ProcessNode[] = [];
    for (const node of registry.values()) {
      const parent = node.ppid ? registry.get(`${asset}#${node.ppid}`) : undefined;
      if (parent && parent !== node) {
        parent.children.push(node);
      } else {
        node.orphan = Boolean(node.ppid);
        roots.push(node);
      }
    }
    const total = registry.size;
    if (total) trees.push({ asset, roots, total });
  }
  trees.sort((a, b) => b.total - a.total);
  return trees;
});

/** 把树展平成带深度的行：模板里不递归渲染（Vue 递归需要额外组件），只按缩进画。 */
const processRows = computed(() => {
  const rows: { node: ProcessNode; depth: number; hasChildren: boolean }[] = [];
  const walk = (node: ProcessNode, depth: number) => {
    rows.push({ node, depth, hasChildren: node.children.length > 0 });
    if (!isProcessExpanded(node)) return;
    for (const child of node.children) walk(child, depth + 1);
  };
  for (const tree of processTrees.value) {
    for (const root of tree.roots) walk(root, 0);
  }
  return rows;
});

/** 大树上默认只展开根节点：一屏几百行没人看，也没法看。 */
function isProcessExpanded(node: ProcessNode) {
  if (expandedProcess.value.includes(node.key)) return true;
  return processTrees.value.every((tree) => tree.total <= PROCESS_AUTO_EXPAND_LIMIT);
}

function toggleProcessNode(node: ProcessNode) {
  expandedProcess.value = expandedProcess.value.includes(node.key)
    ? expandedProcess.value.filter((item) => item !== node.key)
    : [...expandedProcess.value, node.key];
}

function processImageName(image: string) {
  return image.split("\\").pop() ?? image;
}

function processKindText(kind: string) {
  const labels: Record<string, string> = {
    process_created: "进程创建",
    file_activity: "文件活动",
    registry_activity: "注册表修改",
    dns_query: "DNS 查询",
    network_connection: "网络外联",
  };
  return labels[kind] ?? kind;
}

function setDetectionFilter(level: string) {
  detectionLevelFilter.value = detectionLevelFilter.value === level ? "" : level;
  if (!detectionLevelFilter.value) return;
  setActiveView("events");
}

// 步骤与后端 request_ai_judgement 的真实阶段一一对应
const AI_PROGRESS_STEPS = [
  { label: "准备日志上下文", desc: "提取关键事件与证据片段" },
  { label: "执行分析工具", desc: "确定性提取统计、证据与时间线" },
  { label: "调用 AI 模型", desc: "发送语义分析请求" },
  { label: "解析研判结果", desc: "整理行为识别与风险等级" },
  { label: "溯源校验与合并", desc: "校验证据引用并合并结论" },
  { label: "AI 研判完成", desc: "结果已应用到当前分析" },
];

const AI_STAGE_INDEX: Record<string, number> = {
  prepare_context: 0,
  run_tools: 1,
  call_model: 2,
  parse_response: 3,
  grounding: 4,
  completed: 5,
};

const aiConfig = ref<AiConfig | null>(null);
const aiTesting = ref(false);
const aiConnection = ref<AiConnection | null>(null);
const configOpen = ref(false);
const whitelistOpen = ref(false);
const whitelistOverview = ref<{
  kinds: Record<string, string>;
  entries: {
    id: number;
    kind: string;
    value: string;
    note: string;
    enabled: boolean;
    created_at: string;
  }[];
  changes: { action: string; kind: string; value: string; note: string; created_at: string }[];
}>({ kinds: {}, entries: [], changes: [] });
const whitelistForm = ref({ kind: "ip", value: "", note: "" });
const whitelistError = ref("");
const configSaving = ref(false);
const configNotice = ref("");
const configNoticeType = ref<"success" | "error">("success");
const configForm = ref({
  provider: "deepseek",
  base_url: "",
  model: "",
  api_key: "",
  clear_api_key: false,
});

const selectedProviderPreset = computed(() =>
  aiConfig.value?.provider_presets?.[configForm.value.provider] ?? null,
);

function applyProviderPreset() {
  const preset = selectedProviderPreset.value;
  if (!preset) return;
  configForm.value.base_url = preset.base_url;
  configForm.value.model = preset.models[0] ?? "";
  configForm.value.clear_api_key = false;
  customModel.value = !preset.models.length;
}

/* ---------- 自定义选择器（替代原生 select） ---------- */

const PROVIDER_LABELS: Record<string, string> = {
  openai: "OpenAI",
  deepseek: "DeepSeek",
  qwen: "通义千问",
  qianfan: "百度千帆",
  zhipu: "智谱 GLM",
  moonshot: "Moonshot Kimi",
  minimax: "MiniMax",
  siliconflow: "硅基流动",
  openrouter: "OpenRouter",
  groq: "Groq",
  together: "Together AI",
  fireworks: "Fireworks",
  mistral: "Mistral",
  xai: "xAI Grok",
  gemini: "Google Gemini",
  ollama: "Ollama（本地）",
  anthropic: "Anthropic Claude",
  openai_compatible: "OpenAI 兼容",
};

type ProviderOption = {
  value: string;
  label: string;
  hint: string;
  initial: string;
  tone: number;
};

const picker = ref("");
const providerQuery = ref("");
const customModel = ref(false);

const showModelInput = computed(
  () => customModel.value || !(selectedProviderPreset.value?.models.length ?? 0),
);

function toneOf(value: string) {
  let hash = 0;
  for (const char of value) hash = (hash * 31 + char.charCodeAt(0)) % 997;
  return hash % 6;
}

const providerOptions = computed<ProviderOption[]>(() =>
  (aiConfig.value?.supported_providers ?? []).map((value) => {
    const models = aiConfig.value?.provider_presets?.[value]?.models ?? [];
    const label = PROVIDER_LABELS[value] ?? value;
    return {
      value,
      label,
      hint: models.length
        ? `默认模型 ${models[0]}${models.length > 1 ? ` · 共 ${models.length} 个` : ""}`
        : "自定义 Base URL 与模型",
      initial: label.slice(0, 1).toUpperCase(),
      tone: toneOf(value),
    };
  }),
);

const filteredProviderOptions = computed(() => {
  const keyword = providerQuery.value.trim().toLowerCase();
  if (!keyword) return providerOptions.value;
  return providerOptions.value.filter((item) =>
    `${item.value} ${item.label} ${item.hint}`.toLowerCase().includes(keyword),
  );
});

const currentProviderOption = computed(
  () => providerOptions.value.find((item) => item.value === configForm.value.provider) ?? null,
);

function togglePicker(name: string) {
  if (picker.value === name) {
    picker.value = "";
    return;
  }
  picker.value = name;
  providerQuery.value = "";
}

function closePickers() {
  picker.value = "";
  providerQuery.value = "";
}

function chooseProvider(value: string) {
  configForm.value.provider = value;
  applyProviderPreset();
  closePickers();
}

function chooseModel(value: string) {
  if (value === "__custom__") {
    customModel.value = true;
    configForm.value.model = "";
  } else {
    customModel.value = false;
    configForm.value.model = value;
  }
  closePickers();
}


/* ---------- 通用下拉选择器（内联组件，替代原生 select） ---------- */

type PickerChoice = { value: string | number; label: string; hint?: string; tone?: string };

const PickerSelect = defineComponent({
  name: "PickerSelect",
  props: {
    name: { type: String, required: true },
    modelValue: { type: [String, Number], default: "" },
    options: { type: Array as PropType<PickerChoice[]>, default: () => [] },
    placeholder: { type: String, default: "请选择" },
    ariaLabel: { type: String, default: "" },
    searchable: { type: Boolean, default: false },
  },
  emits: ["update:modelValue"],
  setup(props, { emit }) {
    const keyword = ref("");
    const isOpen = computed(() => picker.value === props.name);
    const selected = computed(
      () => props.options.find((item) => String(item.value) === String(props.modelValue)) ?? null,
    );
    const label = computed(() => selected.value?.label ?? props.placeholder);
    const muted = computed(() => String(props.modelValue ?? "") === "" || !selected.value);
    const showSearch = computed(() => props.searchable || props.options.length > 7);
    const visible = computed(() => {
      const query = keyword.value.trim().toLowerCase();
      if (!query) return props.options;
      return props.options.filter((item) =>
        `${item.value} ${item.label} ${item.hint ?? ""}`.toLowerCase().includes(query),
      );
    });

    function toggle() {
      if (isOpen.value) {
        picker.value = "";
        return;
      }
      keyword.value = "";
      picker.value = props.name;
    }

    function choose(value: string | number) {
      emit("update:modelValue", value);
      picker.value = "";
    }

    const checkIcon = () =>
      h(
        "svg",
        {
          class: "picker-check",
          width: 15,
          height: 15,
          viewBox: "0 0 15 15",
          fill: "none",
          "aria-hidden": "true",
        },
        [
          h("path", {
            d: "m3 7.8 3 3 6-6.4",
            stroke: "currentColor",
            "stroke-width": "1.8",
            "stroke-linecap": "round",
            "stroke-linejoin": "round",
          }),
        ],
      );

    return () =>
      h(
        "div",
        { class: ["picker", "picker-inline", isOpen.value && "open"] },
        [
          h(
            "button",
            {
              type: "button",
              class: "picker-trigger",
              "aria-label": props.ariaLabel || props.placeholder,
              "aria-expanded": isOpen.value ? "true" : "false",
              onClick: toggle,
            },
            [
              selected.value?.tone
                ? h("span", { class: ["picker-dot", `tone-${selected.value.tone}`] })
                : null,
              h("span", { class: ["picker-value", muted.value && "is-placeholder"] }, label.value),
              h(
                "svg",
                {
                  class: "picker-chevron",
                  width: 14,
                  height: 14,
                  viewBox: "0 0 14 14",
                  fill: "none",
                  "aria-hidden": "true",
                },
                [
                  h("path", {
                    d: "M3.5 5.5 7 9l3.5-3.5",
                    stroke: "currentColor",
                    "stroke-width": "1.6",
                    "stroke-linecap": "round",
                    "stroke-linejoin": "round",
                  }),
                ],
              ),
            ],
          ),
          isOpen.value
            ? h("div", { class: "picker-panel" }, [
                showSearch.value
                  ? h("div", { class: "picker-search" }, [
                      h(
                        "svg",
                        { width: 14, height: 14, viewBox: "0 0 14 14", fill: "none", "aria-hidden": "true" },
                        [
                          h("circle", {
                            cx: "6.2",
                            cy: "6.2",
                            r: "4.2",
                            stroke: "currentColor",
                            "stroke-width": "1.5",
                          }),
                          h("path", {
                            d: "m9.6 9.6 2.4 2.4",
                            stroke: "currentColor",
                            "stroke-width": "1.5",
                            "stroke-linecap": "round",
                          }),
                        ],
                      ),
                      h("input", {
                        type: "search",
                        value: keyword.value,
                        placeholder: "搜索…",
                        onInput: (event: Event) => {
                          keyword.value = (event.target as HTMLInputElement).value;
                        },
                      }),
                    ])
                  : null,
                h(
                  "div",
                  { class: "picker-list" },
                  visible.value.length
                    ? visible.value.map((item) =>
                        h(
                          "button",
                          {
                            type: "button",
                            class: [
                              "picker-option",
                              "plain",
                              String(item.value) === String(props.modelValue) && "active",
                            ],
                            onClick: () => choose(item.value),
                          },
                          [
                            item.tone
                              ? h("span", { class: ["picker-dot", `tone-${item.tone}`] })
                              : null,
                            h("span", { class: "picker-option-body" }, [
                              h("strong", item.label),
                              item.hint ? h("small", item.hint) : null,
                            ]),
                            String(item.value) === String(props.modelValue) ? checkIcon() : null,
                          ],
                        ),
                      )
                    : [h("p", { class: "picker-empty" }, "没有匹配项")],
                ),
              ])
            : null,
        ],
      );
  },
});

/* ---------- 筛选与分页下拉的选项 ---------- */

// 日志类型 → 颜色语义（下拉色点 + 表格标签共用）
const LOG_TYPE_TONES: Record<string, string> = {
  ssh: "purple",
  iis: "blue",
  nginx: "blue",
  apache: "blue",
  web: "blue",
  windows: "teal",
  evtx: "teal",
  json: "amber",
  csv: "green",
  firewall_waf: "red",
  generic: "gray",
  mixed: "indigo",
  mysql: "orange",
  postgresql: "cyan",
  mongodb: "lime",
  redis: "rose",
  sqlserver: "fuchsia",
  oracle: "slate",
  syslog: "sky",
  windows_event: "teal",
  windows_auth_export: "teal",
  unsupported_xlsx: "gray",
};

function logTypeTone(type: string) {
  return LOG_TYPE_TONES[type] ?? "gray";
}

const listTypeOptions = computed<PickerChoice[]>(() => [
  { value: "", label: "全部日志类型" },
  ...listLogTypes.value.map((type) => ({ value: type, label: type, tone: logTypeTone(type) })),
]);

const riskLevelOptions: PickerChoice[] = [
  { value: "", label: "全部风险等级" },
  { value: "critical", label: RISK_LABELS.critical ?? "critical", tone: "critical" },
  { value: "high", label: RISK_LABELS.high ?? "high", tone: "high" },
  { value: "medium", label: RISK_LABELS.medium ?? "medium", tone: "orange" },
  { value: "low", label: RISK_LABELS.low ?? "low", tone: "green" },
  { value: "info", label: RISK_LABELS.info ?? "info", tone: "blue" },
];

const listStatusOptions: PickerChoice[] = [
  { value: "", label: "全部状态" },
  { value: "completed", label: "已完成", tone: "green" },
  { value: "processing", label: "分析中", tone: "blue" },
  { value: "failed", label: "失败", tone: "red" },
];

const listSortOptions: PickerChoice[] = [
  { value: "created_desc", label: "最近上传优先", tone: "sky" },
  { value: "created_asc", label: "最早上传优先", tone: "sky" },
  { value: "risk_desc", label: "风险从高到低", tone: "red" },
  { value: "risk_asc", label: "风险从低到高", tone: "green" },
];

const recordTypeOptions = computed<PickerChoice[]>(() => [
  { value: "", label: "全部日志类型" },
  ...(records.value?.available_log_types ?? []).map((type) => ({
    value: type,
    label: type,
    tone: logTypeTone(type),
  })),
]);

const listPageSizeOptions: PickerChoice[] = [10, 20, 50].map((size) => ({
  value: size,
  label: String(size),
}));

const recordPageSizeOptions: PickerChoice[] = [20, 50, 100].map((size) => ({
  value: size,
  label: String(size),
}));

watch(recordPageSize, () => {
  loadRecords(1);
});

function onDocumentPointerDown(event: MouseEvent) {
  if (!picker.value) return;
  const target = event.target as HTMLElement | null;
  if (target?.closest(".picker")) return;
  closePickers();
}

function onDocumentKeydown(event: KeyboardEvent) {
  if (event.key !== "Escape") return;
  if (picker.value) {
    closePickers();
    return;
  }
  if (configOpen.value) configOpen.value = false;
  else if (uploadOpen.value) closeUpload();
}

/* ---------- 列表筛选与分页 ---------- */

const filteredHistory = computed(() => history.value);

const listTotalPages = computed(() => Math.max(1, Math.ceil(historyTotal.value / listPageSize.value)));

const pagedHistory = computed(() => history.value);

const listLogTypes = computed(() =>
  historyLogTypes.value
);

const hasListFilters = computed(() => {
  const { keyword, log_type, risk_level, status } = listFilters.value;
  return Boolean(keyword.trim() || log_type || risk_level || status);
});

const hasRecordFilters = computed(() => Object.values(recordFilters.value).some((value) => Boolean(value)));

const toolbarCount = computed(() =>
  view.value === "list"
    ? `共 ${historyTotal.value} 条`
    : `日志明细 ${records.value?.total ?? 0} 条`
);

function buildPageItems(current: number, total: number): PageItem[] {
  if (total <= 7) return Array.from({ length: total }, (_, index) => index + 1);
  const items: PageItem[] = [1];
  const start = Math.max(2, current - 1);
  const end = Math.min(total - 1, current + 1);
  if (start > 2) items.push("gap");
  for (let page = start; page <= end; page += 1) items.push(page);
  if (end < total - 1) items.push("gap");
  items.push(total);
  return items;
}

const listPageItems = computed(() => buildPageItems(listPage.value, listTotalPages.value));
const recordPageItems = computed(() => buildPageItems(records.value?.page ?? 1, records.value?.total_pages ?? 0));
const currentRecordPage = computed(() => records.value?.page ?? 1);

function goToPage(target: PageItem) {
  if (target === "gap") return;
  listPage.value = target;
}

function goToRecordPage(target: PageItem) {
  if (target === "gap") return;
  loadRecords(target);
}

watch([listFilters, listPageSize], () => {
  listPage.value = 1;
  loadHistory(1);
}, { deep: true });

watch(listTotalPages, (total) => {
  if (listPage.value > total) listPage.value = total;
});

watch(listPage, (page, previous) => {
  if (page !== previous) loadHistory(page);
});

/* ---------- 展示辅助 ---------- */

const riskLabel = computed(() => (result.value ? RISK_LABELS[result.value.risk_level] ?? result.value.risk_level : ""));

const aiStatusText = computed(() => {
  if (!result.value) return "";
  if (result.value.ai_status === "completed") return "AI 已完成";
  if (result.value.ai_status === "unavailable") return "AI 不可用";
  return "AI 未分析";
});

const aiStatusClass = computed(() => {
  if (!result.value) return "neutral";
  if (result.value.ai_status === "completed") return "completed";
  if (result.value.ai_status === "unavailable") return "failed";
  return "neutral";
});

const analysisSourceText = computed(() => {
  if (!result.value) return "";
  if (result.value.analysis_source === "rules_and_ai") return "规则 + AI 综合分析";
  if (result.value.analysis_source === "ai") return "AI 研判";
  return "本地规则初步研判";
});

function riskText(level: string) {
  return RISK_LABELS[level] ?? level;
}

function terminalNodeText(kind: string) {
  return {
    process_created: "进程",
    file_activity: "文件",
    registry_change: "注册表",
    dns_query: "DNS",
    outbound_connection: "外联",
  }[kind] ?? kind;
}

const ENTITY_LABELS: Record<string, string> = {
  source_ip: "来源 IP",
  destination_ip: "目的 IP",
  account: "账户",
};

// 攻击链归组维度：主机侧日志没有来源 IP，按目标资产（主机名）归组
const CHAIN_KIND_LABELS: Record<string, string> = {
  source_ip: "来源 IP",
  target_asset: "目标资产",
  rule: "规则",
};

function chainKindText(kind: string) {
  return CHAIN_KIND_LABELS[kind] ?? kind;
}

function entityKindText(kind: string) {
  return ENTITY_LABELS[kind] ?? kind;
}

/** 异常评分的归组标签：主机侧日志按目标主机归组，需要标出来避免被误读成来源 IP。 */
function riskScoreLabel(item: { source_ip: string; key?: string; kind?: string }) {
  const value = item.key || item.source_ip;
  return item.kind === "target_asset" ? `主机 ${value}` : value;
}

/** 「未纳入检测」的拆分说明；无拆分数据时返回空串（仍只显示总数）。 */
function coverageDropDetail(coverage: { parse_errors: number; retention_drops: number }) {
  const parts: string[] = [];
  if (coverage.parse_errors) parts.push(`解析失败 ${coverage.parse_errors} 条`);
  if (coverage.retention_drops) parts.push(`超出保留上限 ${coverage.retention_drops} 条`);
  return parts.join(" · ");
}

/* ---------- 详情页模块导航 ---------- */

type DetailModule = {
  id: string;
  label: string;
  index: string;
  tier: "verdict" | "ai" | "context" | "insight" | "raw";
  count: number | null;
};

const TIER_LABELS: Record<DetailModule["tier"], string> = {
  verdict: "研判结论",
  ai: "AI 语义",
  context: "关联分析",
  insight: "AI 赋能",
  raw: "原始数据",
};

const detailModules = computed<DetailModule[]>(() => {
  const current = result.value;
  if (!current) return [];
  const hasAi =
    current.ai_status !== "not_analyzed" ||
    current.ai_behaviors.length > 0 ||
    current.ai_tool_trace.length > 0 ||
    current.ai_unsupported_claims.length > 0;
  const candidates: (Omit<DetailModule, "index"> & { visible: boolean })[] = [
    { id: "overview", label: "分析概览", tier: "verdict", count: null, visible: true },
    { id: "events", label: "可疑事件", tier: "verdict", count: current.events.length, visible: true },
    {
      id: "query",
      label: "查询",
      tier: "context",
      count: searchResult.value?.records_total ?? null,
      visible: true,
    },
    {
      id: "attack",
      label: "ATT&CK",
      tier: "insight",
      count: attackMatrix.value?.techniques_hit ?? 0,
      visible: true,
    },
    {
      id: "detections",
      label: "检测",
      tier: "verdict",
      count: detections.value?.groups_total ?? 0,
      visible: true,
    },
    { id: "threat-intel", label: "威胁情报", tier: "context", count: threatIntel.value?.findings.length ?? 0, visible: true },
    {
      id: "insights",
      label: "AI 洞察",
      tier: "insight",
      count: (insights.value?.attack_chains.length ?? 0) + (insights.value?.timeseries.length ?? 0),
      visible: !!insights.value && (insights.value.timeseries.length > 0 || insights.value.attack_chains.length > 0),
    },
    {
      id: "ai",
      label: "AI 研判",
      tier: "ai",
      count: current.ai_behaviors.length + current.ai_tool_trace.filter((call) => call.tool !== "usage").length,
      visible: hasAi,
    },
    { id: "templates", label: "日志模板", tier: "context", count: current.templates.length, visible: current.templates.length > 0 },
    { id: "entities", label: "实体关联", tier: "context", count: current.entities.length, visible: current.entities.length > 0 },
    { id: "processes", label: "进程树", tier: "context", count: processTrees.value.length, visible: processTrees.value.length > 0 },
    { id: "timeline", label: "统一时间线", tier: "context", count: current.timeline.length, visible: current.timeline.length > 0 },
    { id: "terminal-chains", label: "终端证据链", tier: "context", count: current.terminal_chains.length, visible: current.terminal_chains.length > 0 },
    { id: "records", label: "日志明细", tier: "raw", count: records.value?.total ?? 0, visible: true },
  ];
  return candidates
    .filter((item) => item.visible)
    .map(({ visible: _visible, ...item }, position) => ({
      ...item,
      index: String(position + 1).padStart(2, "0"),
    }));
});

function moduleOf(id: string) {
  return detailModules.value.find((item) => item.id === id);
}

function moduleIndex(id: string) {
  return moduleOf(id)?.index ?? "--";
}

function moduleTierLabel(id: string) {
  const tier = moduleOf(id)?.tier;
  return tier ? TIER_LABELS[tier] : "";
}

const highestEventLevel = computed(() => {
  const events = result.value?.events ?? [];
  return events.reduce(
    (highest, item) => (RISK_ORDER.indexOf(item.risk_level) > RISK_ORDER.indexOf(highest) ? item.risk_level : highest),
    "info",
  );
});

const RISK_TONES: Record<string, string> = {
  critical: "critical",
  high: "high",
  medium: "orange",
  low: "green",
  info: "blue",
};

type StructuredRow = {
  label: string;
  kind: "text" | "list" | "success" | "risk";
  text: string;
  list: string[];
  positive: boolean;
  tone: string;
  cls: string;
};

const structuredRows = computed<StructuredRow[]>(() => {
  const v = result.value?.structured_verdict;
  if (!v) return [];
  return [
    { label: "事件时间", kind: "text", text: v.event_time || "—", list: [], positive: false, tone: "", cls: "mono" },
    { label: "攻击源IP", kind: "text", text: v.attack_source_ip || "—", list: [], positive: false, tone: "", cls: "mono sv-ip" },
    { label: "目标资产", kind: "text", text: v.target_asset || "—", list: [], positive: false, tone: "", cls: "" },
    { label: "涉及账号", kind: "text", text: v.involved_account || "—", list: [], positive: false, tone: "", cls: "mono" },
    { label: "异常行为", kind: "text", text: v.abnormal_behavior || "—", list: [], positive: false, tone: "", cls: "" },
    { label: "关联日志", kind: "list", text: "", list: v.related_logs, positive: false, tone: "", cls: "" },
    { label: "攻击类型", kind: "text", text: v.attack_type || "—", list: [], positive: false, tone: "", cls: "" },
    { label: "风险等级", kind: "risk", text: riskText(v.risk_level), list: [], positive: false, tone: RISK_TONES[v.risk_level] ?? "blue", cls: "" },
    { label: "判断依据", kind: "text", text: v.judgment_basis || "—", list: [], positive: false, tone: "", cls: "" },
    { label: "成功迹象", kind: "success", text: v.success_indicator || "—", list: [], positive: /是|成功|已|yes|true|succeed|确凿/i.test(v.success_indicator || ""), tone: "", cls: "" },
    { label: "建议处置", kind: "list", text: "", list: v.recommended_actions, positive: false, tone: "", cls: "" },
  ];
});

// AI 赋能流水线：把确定性工具映射为「标准化 → 富化 → 研判 → 溯源」阶段并给出产出计数
const enrichmentStages = computed(() => {
  const r = result.value;
  if (!r) return [];
  const evidenceCount = r.events.reduce((sum, event) => sum + event.evidence_items.length, 0);
  return [
    { tool: "log_metadata", stage: "标准化", detail: `${r.metadata.total_lines} 行 · 解析 ${r.metadata.parsed_lines}` },
    { tool: "log_statistics", stage: "统计富化", detail: `失败 ${r.statistics.failed_login} / 成功 ${r.statistics.successful_login}` },
    { tool: "query_events", stage: "事件研判", detail: `${r.events.length} 个事件` },
    { tool: "query_evidence", stage: "证据检索", detail: `${evidenceCount} 条证据` },
    { tool: "timeline", stage: "时间线", detail: `${r.timeline.length} 条` },
    {
      tool: "grounding",
      stage: "溯源校验",
      detail: r.ai_unsupported_claims.length ? `${r.ai_unsupported_claims.length} 条未支撑` : "全部通过",
    },
  ];
});

// tool_trace 里混着一条 tool === "usage" 的用量总账（不是工具调用），
// 展示时必须拆开，否则「N 次工具调用」会被虚增、列表里也会多出一行空条目。
const aiToolCalls = computed(() =>
  (result.value?.ai_tool_trace ?? []).filter((call) => call.tool !== "usage"),
);
const aiUsage = computed(
  () => (result.value?.ai_tool_trace ?? []).find((call) => call.tool === "usage")?.usage ?? null,
);
const aiUsageText = computed(() => {
  const usage = aiUsage.value;
  if (!usage || typeof usage.prompt_tokens !== "number") return "";
  const parts = [
    `输入 ${usage.prompt_tokens.toLocaleString()} tokens`,
    `输出 ${(usage.completion_tokens ?? 0).toLocaleString()}`,
    `${usage.rounds ?? 1} 轮`,
  ];
  // 命中率只在服务端回传命中数时才有意义——缺失不等于 0%，因此不显示 0%
  if (typeof usage.cache_hit_ratio === "number") {
    parts.push(`缓存命中 ${(usage.cache_hit_ratio * 100).toFixed(0)}%`);
  }
  return parts.join(" · ");
});

const insightsSeries = computed(() => insights.value?.timeseries ?? []);
const insightsMax = computed(() =>
  Math.max(1, ...insightsSeries.value.map((item) => item.count)),
);
const insightsPeakIndex = computed(() => {
  const series = insightsSeries.value;
  if (!series.length) return -1;
  let peak = 0;
  for (let index = 1; index < series.length; index++) {
    if (series[index].count > series[peak].count) peak = index;
  }
  return peak;
});

// x 轴刻度：最多约 8 个，独立轴层按百分比定位（不占用柱子列空间，保证基线齐平）
const insightsTicks = computed(() => {
  const series = insightsSeries.value;
  if (series.length < 2) return [];
  const step = Math.max(1, Math.ceil(series.length / 8));
  const ticks: { index: number; label: string; left: number }[] = [];
  for (let index = 0; index < series.length; index += step) {
    ticks.push({
      index,
      label: series[index].label,
      left: ((index + 0.5) / series.length) * 100,
    });
  }
  return ticks;
});

const COLLAPSED_MODULES_KEY = "loginsight-collapsed-modules";

/** 读取上次的模块折叠状态；没有存过返回 null（区别于「显式全部展开」的空数组）。 */
function loadCollapsedModules(): string[] | null {
  try {
    const raw = localStorage.getItem(COLLAPSED_MODULES_KEY);
    if (raw === null) return null;
    const parsed: unknown = JSON.parse(raw);
    return Array.isArray(parsed)
      ? parsed.filter((item): item is string => typeof item === "string")
      : null;
  } catch {
    return null;
  }
}

// 左侧分区导航：一次只显示一个视图（仿 Zircolite NavRail）
const activeView = ref("overview");
const collapsedModules = ref<string[]>(loadCollapsedModules() ?? []);

watch(collapsedModules, (value) => {
  try {
    localStorage.setItem(COLLAPSED_MODULES_KEY, JSON.stringify(value));
  } catch {
    // 隐私模式等场景下 localStorage 不可用：忽略即可，不影响本次折叠
  }
});

/** 切换视图：进入时自动展开该模块，并把内容区滚回顶部（否则会停在上一屏的位置）。 */
function setActiveView(id: string) {
  activeView.value = id;
  if (isCollapsed(id)) {
    collapsedModules.value = collapsedModules.value.filter((item) => item !== id);
  }
  nextTick(() => window.scrollTo({ top: 0, behavior: "auto" }));
}

/** 视图失效兜底：换了一份日志后原来的视图可能不存在（例如没有实体），回到第一个可用视图。 */
watch(detailModules, (items) => {
  if (!items.length) return;
  if (!items.some((item) => item.id === activeView.value)) {
    activeView.value = items[0].id;
  }
});

function isCollapsed(id: string) {
  return collapsedModules.value.includes(id);
}

function toggleModule(id: string) {
  collapsedModules.value = isCollapsed(id)
    ? collapsedModules.value.filter((item) => item !== id)
    : [...collapsedModules.value, id];
}

watch(result, () => {
  // 换了一份日志：回到概览，并沿用用户上次的折叠偏好（切换视图时会自动展开目标视图）
  activeView.value = "overview";
  collapsedModules.value = loadCollapsedModules() ?? [];
});

function formatArguments(args: Record<string, unknown>) {
  const text = JSON.stringify(args);
  return text === "{}" || text === "undefined" ? "" : text;
}

function statusText(status: string) {
  return STATUS_LABELS[status] ?? status;
}

function formatTime(value: string | null) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString("zh-CN", { hour12: false });
}

function formatSize(bytes: number) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

/* ---------- 上传 ---------- */

function openUpload() {
  uploadOpen.value = true;
  error.value = "";
  notice.value = "";
  loadDemoLogs();
}

function closeUpload() {
  uploadOpen.value = false;
  dragActive.value = false;
}

function selectFile(event: Event) {
  const input = event.target as HTMLInputElement;
  mergeFiles(Array.from(input.files ?? []));
  input.value = "";
}

function onDrop(event: DragEvent) {
  dragActive.value = false;
  mergeFiles(Array.from(event.dataTransfer?.files ?? []));
}

function mergeFiles(incoming: File[]) {
  if (!incoming.length) return;
  const merged = [...files.value];
  incoming.forEach((item) => {
    if (!merged.some((file) => file.name === item.name && file.size === item.size)) merged.push(item);
  });
  files.value = merged;
  error.value = "";
}

function removeFile(index: number) {
  files.value = files.value.filter((_, position) => position !== index);
}

async function upload() {
  if (!files.value.length) return;
  loading.value = true;
  error.value = "";
  const form = new FormData();
  files.value.forEach((item) => form.append("files", item));
  try {
    const response = await fetch("/api/logs/upload", { method: "POST", body: form });
    if (!response.ok) {
      const body = await response.json().catch(() => ({}));
      throw new Error((body as { detail?: string }).detail ?? "分析失败");
    }
    const body = await response.json();
    files.value = [];
    uploadOpen.value = false;
    await enterAnalysisDetail(body.result);
    await loadHistory();
  } catch (reason) {
    error.value = reason instanceof Error ? reason.message : "分析失败";
  } finally {
    loading.value = false;
  }
}

async function loadDemoLogs() {
  try {
    const response = await fetch("/api/demo/logs");
    if (!response.ok) return;
    demoLogs.value = await response.json();
    if (!selectedDemoLogs.value.length) {
      const preferred = demoLogs.value.find(
        (item) => item.path === "structured/auth-events-demo.csv",
      );
      selectedDemoLogs.value = preferred
        ? [preferred.path]
        : demoLogs.value.length
          ? [demoLogs.value[0].path]
          : [];
    }
  } catch {
    demoLogs.value = [];
  }
}

function toggleDemoLog(path: string) {
  selectedDemoLogs.value = selectedDemoLogs.value.includes(path)
    ? selectedDemoLogs.value.filter((item) => item !== path)
    : [...selectedDemoLogs.value, path];
}

async function analyzeDemoLogs() {
  if (!selectedDemoLogs.value.length || loading.value) return;
  loading.value = true;
  error.value = "";
  try {
    const response = await fetch("/api/demo/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ files: selectedDemoLogs.value }),
    });
    const body = await response.json();
    if (!response.ok) throw new Error((body as { detail?: string }).detail ?? "演示日志分析失败");
    uploadOpen.value = false;
    await enterAnalysisDetail(body.result);
    await loadHistory();
  } catch (reason) {
    error.value = reason instanceof Error ? reason.message : "演示日志分析失败";
  } finally {
    loading.value = false;
  }
}

/* ---------- 列表与详情 ---------- */

async function loadHistory(page = listPage.value) {
  const params = new URLSearchParams({
    page: String(page),
    page_size: String(listPageSize.value),
  });
  const { keyword, log_type, risk_level, status } = listFilters.value;
  if (keyword.trim()) params.set("keyword", keyword.trim());
  if (log_type) params.set("log_type", log_type);
  if (risk_level) params.set("risk_level", risk_level);
  if (status) params.set("status", status);
  if (listFilters.value.sort) params.set("sort", listFilters.value.sort);
  const response = await fetch(`/api/logs?${params}`);
  if (!response.ok) return;
  const payload = await response.json() as LogSummaryPage;
  history.value = payload.items;
  historyTotal.value = payload.total;
  historyLogTypes.value = payload.available_log_types;
}

/** 拉取跨分析用量趋势。失败不弹错——它只是列表页的一块辅助信息。 */
async function loadUsageHistory() {
  try {
    const response = await fetch("/api/ai/usage-history?limit=30");
    if (!response.ok) return;
    usageHistory.value = await response.json() as AiUsageHistory;
  } catch {
    usageHistory.value = null;
  }
}

/** 只有留下用量记录的点才能上趋势图；缺失点用 null 表示，不画成 0。 */
const usagePoints = computed(() => usageHistory.value?.points ?? []);
const usageWithData = computed(() => usagePoints.value.filter((point) => point.usage));

/** 趋势图按时间正序（老的在前、新的在后），取最近 N 条便于阅读。 */
const usageSeries = computed(() =>
  [...usagePoints.value].reverse().slice(-12),
);

type UsageBar = {
  key: string;
  label: string;
  value: number;
  display: string;
  ratio: number;
  hasUsage: boolean;
};

const usageBars = computed<UsageBar[]>(() => {
  const series = usageSeries.value;
  const cacheMode = usageChartMode.value === "cache";
  const values = series.map((point) => {
    const usage = point.usage;
    if (!usage) return null;
    if (cacheMode) {
      // 命中率缺失时不给 0——宁可这根柱子不画，也不虚构一个低谷
      const ratio = usage.cache_hit_ratio;
      return typeof ratio === "number" ? ratio : null;
    }
    return typeof usage.prompt_tokens === "number" ? usage.prompt_tokens : null;
  });
  const max = Math.max(
    // 缓存命中率是 0~1 的比例，分母下限必须是它自己的量级；
    // 用 1 兜底会让所有命中率柱子都被压成不到 1 的高度，看不出差异。
    cacheMode ? 0.01 : 1,
    ...values.filter((v): v is number => v !== null),
  );
  return series.map((point, index) => {
    const value = values[index];
    const hasUsage = value !== null;
    return {
      key: point.analysis_id,
      label: point.created_at.slice(5, 16).replace("T", " "),
      value: value ?? 0,
      display: hasUsage
        ? cacheMode
          ? `${(value * 100).toFixed(0)}%`
          : value.toLocaleString()
        : "—",
      ratio: hasUsage ? Math.max(0.02, value / max) : 0,
      hasUsage,
    };
  });
});

const usageSummary = computed(() => {
  const data = usageHistory.value;
  if (!data || !data.with_usage) return "";
  const parts = [
    `近 ${data.total_points} 次研判中 ${data.with_usage} 次有账单`,
    `平均输入 ${data.avg_prompt_tokens.toLocaleString()} tokens`,
    `平均输出 ${data.avg_completion_tokens.toLocaleString()}`,
  ];
  if (typeof data.avg_cache_hit_ratio === "number") {
    parts.push(`平均缓存命中 ${(data.avg_cache_hit_ratio * 100).toFixed(0)}%`);
  }
  return parts.join(" · ");
});

async function checkHealth() {
  try {
    const response = await fetch("/api/health");
    healthOk.value = response.ok;
  } catch {
    healthOk.value = false;
  }
}

function backToList() {
  view.value = "list";
  error.value = "";
  result.value = null;
  records.value = null;
}

/** 进入详情页只有这一条路径：分页上限要重置、明细与洞察都要按新记录重新拉。
 *
 *  上传与演示分析曾经只设 `result` 而不刷新洞察，于是上一条记录的柱状图与攻击链
 *  会留在新记录的页面上（一张只有 1 条记录的 auth.log 顶着「AI 洞察 2047」就是这么来的），
 *  分页上限也会沿用上一条记录的值。
 */
async function enterAnalysisDetail(analysis: Result) {
  result.value = analysis;
  records.value = null;
  recordFilters.value = emptyRecordFilters();
  eventLimit.value = EVENTS_DEFAULT_LIMIT;
  chainLimit.value = CHAINS_DEFAULT_LIMIT;
  insights.value = null;
  dashboard.value = null;
  detectionLevelFilter.value = "";
  detections.value = null;
  expandedRules.value = [];
  attackMatrix.value = null;
  attackFullMatrix.value = false;
  searchResult.value = null;
  searchQuery.value = "";
  expandedProcess.value = [];
  facets.value = null;
  expandedFacetFields.value = [];
  expandedTechniques.value = [];
  threatIntel.value = null;
  threatIntelLoading.value = false;
  humanReview.value = null;
  reviewForm.value = { ...reviewForm.value, note: "" };
  entityOpen.value = false;
  entityDetail.value = null;
  entityError.value = "";
  view.value = "detail";
  await loadRecords(1);
  await loadInsights(analysis.id);
  await loadDashboard(analysis.id);
  await loadDetections(analysis.id);
  await loadAttackMatrix(analysis.id);
  await loadFacets(analysis.id);
  await loadHumanReview(analysis.id);
}

async function openAnalysis(item: LogSummary) {
  if (item.status !== "completed") {
    notice.value = `该记录状态为「${statusText(item.status)}」，暂不能查看分析结果。${item.error_message ?? ""}`;
    return;
  }
  notice.value = "";
  error.value = "";
  detailLoading.value = true;
  // 加载期间先清空旧内容，否则会看到上一条记录的结论与洞察
  result.value = null;
  records.value = null;
  insights.value = null;
  recordFilters.value = emptyRecordFilters();
  view.value = "detail";
  try {
    const response = await fetch(`/api/analysis/${item.id}?event_limit=${eventLimit.value}`);
    if (!response.ok) throw new Error("未能读取该分析结果，记录可能已被删除。");
    await enterAnalysisDetail(await response.json());
  } catch (reason) {
    error.value = reason instanceof Error ? reason.message : "加载分析结果失败";
    view.value = "list";
  } finally {
    detailLoading.value = false;
  }
}

async function loadMoreEvents() {
  if (!result.value) return;
  const offset = result.value.events.length;
  const response = await fetch(
    `/api/analysis/${result.value.id}?event_offset=${offset}&event_limit=${EVENTS_PAGE_STEP}`,
  );
  if (!response.ok) return;
  const page = (await response.json()) as Result;
  result.value = {
    ...result.value,
    ...page,
    events: [...result.value.events, ...page.events],
  };
  eventLimit.value = result.value.events.length;
}

async function loadInsights(analysisId: string, append = false) {
  try {
    const offset = append ? insights.value?.attack_chains.length ?? 0 : 0;
    const limit = append ? CHAINS_PAGE_STEP : CHAINS_DEFAULT_LIMIT;
    const response = await fetch(
      `/api/analysis/${analysisId}/insights?chain_offset=${offset}&chain_limit=${limit}`,
    );
    if (!response.ok) return;
    const page = (await response.json()) as Insights;
    insights.value = append && insights.value
      ? {
          ...page,
          attack_chains: [...insights.value.attack_chains, ...page.attack_chains],
        }
      : page;
    chainLimit.value = insights.value?.attack_chains.length ?? CHAINS_DEFAULT_LIMIT;
  } catch {
    if (!append) insights.value = null;
  }
}

async function loadMoreChains() {
  if (!result.value) return;
  await loadInsights(result.value.id, true);
}

// 检测视图：按规则归组的命中汇总，与详情一起加载
async function loadDetections(analysisId: string) {
  detectionsLoading.value = true;
  try {
    const response = await fetch(`/api/analysis/${analysisId}/detections`);
    if (!response.ok) return;
    detections.value = (await response.json()) as DetectionsReport;
  } catch {
    detections.value = null;
  } finally {
    detectionsLoading.value = false;
  }
}

async function loadFacets(analysisId: string) {
  try {
    const response = await fetch(`/api/analysis/${analysisId}/facets`);
    if (!response.ok) return;
    facets.value = (await response.json()) as LogFacets;
  } catch {
    facets.value = null;
  }
}

function toggleFacetField(name: string) {
  expandedFacetFields.value = expandedFacetFields.value.includes(name)
    ? expandedFacetFields.value.filter((item) => item !== name)
    : [...expandedFacetFields.value, name];
}

/** 加/排除一个取值：能走明细筛选的走筛选，其余（DNS、进程、注册表…）转成搜索语法查询。 */
async function applyFacetValue(field: FacetField, value: string, negate: boolean) {
  const param = FACET_FILTER_PARAMS[field.name];
  if (param && !negate) {
    recordFilters.value = { ...emptyRecordFilters(), [param]: value };
    setActiveView("records");
    await loadRecords(1);
    return;
  }
  searchQuery.value = `${negate ? "-" : ""}${field.name}:"${value}"`;
  await runSearch(1);
}

function facetCoverageText(field: FacetField) {
  return `${Math.round(field.coverage * 100)}%（${field.present_records}/${facets.value?.total_records ?? 0}）`;
}

/** 执行搜索语法查询；结果切到「查询」视图展示。 */
async function runSearch(page = 1) {
  if (!result.value) return;
  searchLoading.value = true;
  try {
    const params = new URLSearchParams({ q: searchQuery.value, page: String(page), page_size: "50" });
    const response = await fetch(`/api/analysis/${result.value.id}/search?${params}`);
    if (!response.ok) throw new Error("查询失败，记录可能已被删除。");
    searchResult.value = (await response.json()) as SearchResult;
    setActiveView("query");
  } catch (reason) {
    notice.value = reason instanceof Error ? reason.message : "查询失败";
  } finally {
    searchLoading.value = false;
  }
}

/** 导出 ATT&CK Navigator 图层：浏览器直接下载 JSON。 */
function exportAttackNavigator() {
  if (!result.value) return;
  const url = `/api/analysis/${result.value.id}/attack-navigator`;
  const link = document.createElement("a");
  link.href = url;
  link.download = `attack-navigator-${result.value.id.slice(0, 8)}.json`;
  document.body.appendChild(link);
  link.click();
  link.remove();
}

function searchTermText(term: SearchTerm) {
  const body = term.field ? `${term.field}:${term.value}` : `"${term.value}"`;
  return term.negated ? `排除 ${body}` : body;
}

async function loadAttackMatrix(analysisId: string) {
  try {
    const response = await fetch(`/api/analysis/${analysisId}/attack-matrix`);
    if (!response.ok) return;
    attackMatrix.value = (await response.json()) as AttackMatrix;
  } catch {
    attackMatrix.value = null;
  }
}

/** 按开关决定每列展示哪些技术：默认只留命中的，避免 45 个空格子把版面撑散。 */
function attackColumnCells(column: AttackTacticColumn) {
  return attackFullMatrix.value
    ? column.techniques
    : column.techniques.filter((cell) => cell.events > 0);
}

const attackVisibleColumns = computed(() =>
  (attackMatrix.value?.columns ?? []).filter(
    (column) => attackFullMatrix.value || column.events > 0,
  ),
);

const attackMaxEvents = computed(() =>
  Math.max(
    1,
    ...(attackMatrix.value?.columns ?? []).flatMap((column) =>
      column.techniques.map((cell) => cell.events),
    ),
  ),
);

function techniqueHeat(cell: AttackTechniqueCell) {
  return { opacity: cell.events ? 0.12 + 0.6 * Math.sqrt(cell.events / attackMaxEvents.value) : 0 };
}

function toggleTechnique(technique: string) {
  expandedTechniques.value = expandedTechniques.value.includes(technique)
    ? expandedTechniques.value.filter((item) => item !== technique)
    : [...expandedTechniques.value, technique];
}

function toggleRuleDetail(ruleId: string) {
  expandedRules.value = expandedRules.value.includes(ruleId)
    ? expandedRules.value.filter((item) => item !== ruleId)
    : [...expandedRules.value, ruleId];
}

/** 从检测视图直接进入实体调查：优先按来源 IP 查，否则当主机处理。 */
function openEntityFromRule(group: DetectionGroup) {
  const value = group.entities[0];
  if (!value) return;
  const events = result.value?.events ?? [];
  const isSource = events.some((item) => item.source_ip === value);
  void openEntityInvestigation(isSource ? "source_ip" : "host", value);
}

/** 规则来源：内置规则有本地标注语料；Sigma 导入规则只做过「正常流量零命中」筛查。 */
function ruleSourceText(group: DetectionGroup) {
  if (group.source === "sigma") return "Sigma 导入（未本地验证）";
  if (group.source === "builtin") return "内置规则（有标注语料）";
  return "来源未知";
}

// 概览看板：与详情一起加载；失败只影响看板，不影响结论与明细（与 insights 同一处理）
async function loadDashboard(analysisId: string) {
  dashboardLoading.value = true;
  try {
    const response = await fetch(`/api/analysis/${analysisId}/dashboard`);
    if (!response.ok) return;
    dashboard.value = (await response.json()) as AnalysisDashboard;
  } catch {
    dashboard.value = null;
  } finally {
    dashboardLoading.value = false;
  }
}

// 威胁情报是按需触发的：默认关闭（外发查询需显式开启），不随详情自动加载
async function loadThreatIntel(refresh = false) {
  if (!result.value || threatIntelLoading.value) return;
  threatIntelLoading.value = true;
  try {
    const response = await fetch(
      `/api/analysis/${result.value.id}/threat-intel${refresh ? "?refresh=true" : ""}`,
    );
    if (!response.ok) throw new Error("未能读取威胁情报结果，记录可能已被删除。");
    threatIntel.value = (await response.json()) as ThreatIntelReport;
  } catch (reason) {
    notice.value = reason instanceof Error ? reason.message : "威胁情报查询失败";
  } finally {
    threatIntelLoading.value = false;
  }
}

function threatIntelStatusText(status: string) {
  const labels: Record<string, string> = {
    hit: "收录为恶意",
    not_listed: "未收录",
    error: "查询失败",
    skipped: "未查询",
  };
  return labels[status] ?? status;
}

async function removeAnalysis(item: LogSummary) {
  const response = await fetch(`/api/analysis/${item.id}`, { method: "DELETE" });
  if (!response.ok) return;
  if (result.value?.id === item.id) backToList();
  await loadHistory();
}

/* ---------- 日志明细 ---------- */

async function loadRecords(page = 1, focusRecordId = "") {
  if (!result.value) return;
  recordLoading.value = true;
  selectedRecordId.value = focusRecordId;
  const params = new URLSearchParams({
    page: String(page),
    page_size: String(recordPageSize.value),
  });
  Object.entries(recordFilters.value).forEach(([key, value]) => {
    if (value) params.set(key, value);
  });
  if (focusRecordId) params.set("record_id", focusRecordId);
  try {
    const response = await fetch(`/api/analysis/${result.value.id}/records?${params}`);
    if (response.ok) records.value = await response.json();
    if (focusRecordId) {
      await nextTick();
      document.getElementById(`record-row-${focusRecordId}`)?.scrollIntoView({
        behavior: "smooth",
        block: "center",
      });
    }
  } finally {
    recordLoading.value = false;
  }
}

async function focusEvidence(recordId: string | null) {
  if (!recordId || !result.value) return;
  recordFilters.value = emptyRecordFilters();
  // 被折叠时先展开明细模块，否则无法滚动定位到目标记录
  collapsedModules.value = collapsedModules.value.filter((item) => item !== "records");
  await loadRecords(1, recordId);
}

function resetRecordFilters() {
  recordFilters.value = emptyRecordFilters();
  loadRecords(1);
}

function resetListFilters() {
  listFilters.value = { keyword: "", log_type: "", risk_level: "", status: "", sort: "created_desc" };
}

function exportRecords() {
  if (!result.value) return;
  const params = new URLSearchParams();
  Object.entries(recordFilters.value).forEach(([key, value]) => {
    if (value) params.set(key, value);
  });
  window.open(`/api/analysis/${result.value.id}/records/export?${params}`, "_blank");
}

async function openAiLedger() {
  if (!result.value) return;
  ledgerOpen.value = true;
  ledgerLoading.value = true;
  aiLedger.value = null;
  try {
    const response = await fetch(`/api/analysis/${result.value.id}/ai/ledger`);
    const body = await response.json().catch(() => null);
    if (!response.ok) {
      throw new Error((body as { detail?: string } | null)?.detail ?? "AI 审查台账读取失败");
    }
    aiLedger.value = body as AiLedger;
  } catch (reason) {
    error.value = reason instanceof Error ? reason.message : "AI 审查台账读取失败";
    ledgerOpen.value = false;
  } finally {
    ledgerLoading.value = false;
  }
}

function exportAiLedger(format: "json" | "html" | "csv") {
  if (!result.value) return;
  window.open(`/api/analysis/${result.value.id}/ai/ledger/export?format=${format}`, "_blank");
}

async function loadHumanReview(analysisId: string) {
  humanReview.value = null;
  try {
    const response = await fetch(`/api/analysis/${analysisId}/review`);
    if (!response.ok) return;
    humanReview.value = (await response.json()) as HumanReview;
  } catch {
    // 确认状态读不到不影响规则与 AI 结果展示，保持「未确认」即可，不打断详情页
  }
}

async function submitHumanReview() {
  if (!result.value || reviewSaving.value) return;
  const reviewer = reviewForm.value.reviewer.trim();
  if (!reviewer) {
    error.value = "请先填写确认人：确认记录必须能追溯到人。";
    return;
  }
  reviewSaving.value = true;
  error.value = "";
  try {
    const response = await fetch(`/api/analysis/${result.value.id}/review`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        status: reviewForm.value.status,
        reviewer,
        note: reviewForm.value.note.trim(),
      }),
    });
    const body = (await response.json().catch(() => null)) as
      | (HumanReview & { detail?: string })
      | null;
    if (!response.ok) throw new Error(body?.detail ?? "人工确认保存失败");
    humanReview.value = body;
    reviewForm.value = { ...reviewForm.value, note: "" };
    notice.value = `已记录人工确认：${REVIEW_STATUS_LABELS[body?.status ?? "pending"]}`;
  } catch (reason) {
    error.value = reason instanceof Error ? reason.message : "人工确认保存失败";
  } finally {
    reviewSaving.value = false;
  }
}

async function openEntityInvestigation(kind: string, value: string, page = 1) {
  if (!result.value || entityLoading.value) return;
  entityOpen.value = true;
  entityLoading.value = true;
  entityError.value = "";
  // 翻页时保留旧内容，避免弹层闪成空白；换实体才清空
  if (page === 1) entityDetail.value = null;
  try {
    const params = new URLSearchParams({
      page: String(page),
      page_size: String(ENTITY_PAGE_SIZE),
    });
    const response = await fetch(
      `/api/analysis/${result.value.id}/entities/${encodeURIComponent(kind)}/${encodeURIComponent(value)}?${params}`,
    );
    const body = await response.json().catch(() => null);
    if (!response.ok) {
      throw new Error((body as { detail?: string } | null)?.detail ?? "实体调查读取失败");
    }
    entityDetail.value = body as EntityInvestigation;
  } catch (reason) {
    entityError.value = reason instanceof Error ? reason.message : "实体调查读取失败";
    entityDetail.value = null;
  } finally {
    entityLoading.value = false;
  }
}

function openRulePreview() {
  previewOpen.value = true;
  previewError.value = "";
  previewReport.value = null;
}

async function importPreviewLog(event: Event) {
  const input = event.target as HTMLInputElement;
  const file = input.files?.[0];
  if (!file) return;
  previewForm.value.filename = file.name;
  previewForm.value.sample_log = await file.text();
  input.value = "";
}

async function runRulePreview() {
  if (previewLoading.value) return;
  previewLoading.value = true;
  previewError.value = "";
  previewReport.value = null;
  try {
    const response = await fetch("/api/rules/preview", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(previewForm.value),
    });
    const body = await response.json().catch(() => null);
    if (!response.ok) {
      throw new Error((body as { detail?: string } | null)?.detail ?? "规则试运行失败");
    }
    previewReport.value = body as RulePreviewReport;
  } catch (reason) {
    previewError.value = reason instanceof Error ? reason.message : "规则试运行失败";
  } finally {
    previewLoading.value = false;
  }
}

const REPORT_FORMATS = ["json", "html", "splunk", "elastic", "opensearch", "timesketch", "sarif"] as const;

function downloadReport(format: (typeof REPORT_FORMATS)[number]) {
  if (!result.value) return;
  window.open(`/api/analysis/${result.value.id}/report?format=${format}`, "_blank");
}

function onSiemExport(event: Event) {
  const select = event.target as HTMLSelectElement;
  if (select.value) downloadReport(select.value as (typeof REPORT_FORMATS)[number]);
  select.value = "";
}

const canDownload = computed(() => {
  if (!result.value) return false;
  const files = result.value.metadata.source_files.length
    ? result.value.metadata.source_files
    : [result.value.metadata.filename];
  return files.some((name) => !name.startsWith("demo-"));
});

function downloadLogs() {
  if (!result.value) return;
  window.open(`/api/analysis/${result.value.id}/download`, "_blank");
}

function downloadAnalysisFiles(id: string) {
  window.open(`/api/analysis/${id}/download`, "_blank");
}

type AiTaskState = {
  task_id: string;
  status: "running" | "completed" | "failed";
  stage: string;
  progress: number;
  error: string | null;
  result: Result | null;
  partial: string | null;
};

async function pollAiTask(taskId: string): Promise<AiTaskState> {
  for (;;) {
    await new Promise((resolve) => window.setTimeout(resolve, 600));
    const response = await fetch(`/api/ai/tasks/${taskId}`);
    if (!response.ok) {
      const body = await response.json().catch(() => null);
      throw new Error((body as { detail?: string } | null)?.detail ?? "AI 研判进度查询失败");
    }
    const task = (await response.json()) as AiTaskState;
    const stageIndex = AI_STAGE_INDEX[task.stage];
    if (stageIndex !== undefined) aiProgressActive.value = stageIndex;
    if (typeof task.progress === "number") aiProgressPercent.value = task.progress;
    if (task.partial) aiPartialText.value = task.partial;
    if (task.status === "completed" || task.status === "failed") return task;
  }
}

async function analyzeWithAi() {
  if (!result.value || aiLoading.value) return;
  aiLoading.value = true;
  aiProgressActive.value = 0;
  aiProgressPercent.value = 5;
  aiPartialText.value = "";
  error.value = "";
  try {
    const startResponse = await fetch(`/api/analysis/${result.value.id}/ai/start`, {
      method: "POST",
    });
    const startBody = await startResponse.json();
    if (!startResponse.ok) {
      throw new Error((startBody as { detail?: string }).detail ?? "AI 研判启动失败");
    }
    const final = await pollAiTask((startBody as { task_id: string }).task_id);
    if (final.status === "failed") throw new Error(final.error ?? "AI 研判失败");
    result.value = final.result;
    await loadHistory();
    aiPartialText.value = "";
    aiProgressPercent.value = 100;
    await new Promise((resolve) => window.setTimeout(resolve, 500));
  } catch (reason) {
    error.value = reason instanceof Error ? reason.message : "AI 研判失败";
  } finally {
    aiLoading.value = false;
  }
}

/* ---------- AI 配置 ---------- */

async function loadAiConfig() {
  const response = await fetch("/api/ai/config");
  if (response.ok) {
    const nextConfig: AiConfig = await response.json();
    aiConfig.value = nextConfig;
    if (!configOpen.value) {
      configForm.value.provider = nextConfig.provider;
      configForm.value.base_url = nextConfig.base_url;
      configForm.value.model = nextConfig.model;
    }
  }
}

function openConfig() {
  configOpen.value = true;
  configNotice.value = "";
  configForm.value.provider = aiConfig.value?.provider ?? "deepseek";
  configForm.value.base_url = aiConfig.value?.base_url ?? "";
  configForm.value.model = aiConfig.value?.model ?? "";
  configForm.value.api_key = "";
  configForm.value.clear_api_key = false;
  customModel.value = !(selectedProviderPreset.value?.models.length ?? 0);
  closePickers();
}

async function loadWhitelist() {
  const response = await fetch("/api/whitelist");
  if (response.ok) whitelistOverview.value = await response.json();
}

async function openWhitelist() {
  whitelistOpen.value = true;
  whitelistError.value = "";
  await loadWhitelist();
}

async function addWhitelistEntry() {
  whitelistError.value = "";
  const response = await fetch("/api/whitelist", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(whitelistForm.value),
  });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    whitelistError.value = (body as { detail?: string })?.detail ?? "添加失败";
    return;
  }
  whitelistForm.value.value = "";
  whitelistForm.value.note = "";
  await loadWhitelist();
}

async function toggleWhitelistEntry(id: number, enabled: boolean) {
  await fetch(`/api/whitelist/${id}?enabled=${enabled}`, { method: "PATCH" });
  await loadWhitelist();
}

async function removeWhitelistEntry(id: number) {
  await fetch(`/api/whitelist/${id}`, { method: "DELETE" });
  await loadWhitelist();
}

async function saveConfig() {
  if (configSaving.value) return;
  configSaving.value = true;
  error.value = "";
  configNotice.value = "";
  try {
    const response = await fetch("/api/ai/config", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(configForm.value),
    });
    const body = await response.json();
    if (!response.ok) throw new Error((body as { detail?: string }).detail ?? "AI 配置保存失败");
    aiConfig.value = body;
    configOpen.value = false;
    aiConnection.value = null;
    configNoticeType.value = "success";
    configNotice.value = `AI 配置已保存，后续研判将使用 ${body.provider} / ${body.model}。`;
  } catch (reason) {
    configNoticeType.value = "error";
    configNotice.value = reason instanceof Error ? reason.message : "AI 配置保存失败";
  } finally {
    configSaving.value = false;
  }
}

async function testAiConnection() {
  if (aiTesting.value) return;
  aiTesting.value = true;
  aiConnection.value = null;
  try {
    const response = await fetch("/api/ai/test", { method: "POST" });
    const body = await response.json();
    if (!response.ok) throw new Error((body as { detail?: string }).detail ?? "连接测试失败");
    aiConnection.value = body;
  } catch (reason) {
    aiConnection.value = {
      configured: Boolean(aiConfig.value?.configured),
      reachable: false,
      provider: aiConfig.value?.provider ?? "unknown",
      model: aiConfig.value?.model ?? "unknown",
      message: reason instanceof Error ? reason.message : "连接测试失败",
    };
  } finally {
    aiTesting.value = false;
  }
}

async function refreshAiConfig() {
  aiConnection.value = null;
  await loadAiConfig();
}

onMounted(() => {
  theme.value = localStorage.getItem("loginsight-theme") === "dark" ? "dark" : "light";
  applyTheme();
  loadHistory();
  loadUsageHistory();
  loadAiConfig();
  checkHealth();
  document.addEventListener("mousedown", onDocumentPointerDown);
  document.addEventListener("keydown", onDocumentKeydown);
});

onBeforeUnmount(() => {
  document.removeEventListener("mousedown", onDocumentPointerDown);
  document.removeEventListener("keydown", onDocumentKeydown);
});
</script>

<template>
  <div class="app-shell">
    <aside class="sidebar">
      <div class="brand">
        <img :src="brandLogo" class="brand-logo" alt="AI 日志分析工具" />
        <span class="brand-sub">安全日志分析平台</span>
      </div>

      <nav class="nav">
        <p class="nav-label">分析</p>
        <button class="nav-item" :class="{ active: view === 'list' }" @click="backToList">
          <span class="nav-icon">
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true">
              <path d="M2.5 4h11M2.5 8h11M2.5 12h7" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" />
            </svg>
          </span>
          日志列表
          <span class="nav-count">{{ history.length }}</span>
        </button>
        <button class="nav-item" @click="openConfig">
          <span class="nav-icon">
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true">
              <circle cx="8" cy="8" r="2.4" stroke="currentColor" stroke-width="1.5" />
              <path d="M8 1.6v1.8M8 12.6v1.8M1.6 8h1.8M12.6 8h1.8M3.5 3.5l1.3 1.3M11.2 11.2l1.3 1.3M12.5 3.5l-1.3 1.3M4.8 11.2l-1.3 1.3" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" />
            </svg>
          </span>
          AI 配置
          <span class="nav-count">{{ aiConfig?.configured ? "ON" : "OFF" }}</span>
        </button>
        <button class="nav-item" @click="openWhitelist">
          <span class="nav-icon">
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true">
              <path d="M8 1.8 13.5 4v4.2c0 3-2.3 5.2-5.5 6-3.2-.8-5.5-3-5.5-6V4L8 1.8Z" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round" />
              <path d="M5.9 8.1l1.5 1.5 2.8-3" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" />
            </svg>
          </span>
          白名单
          <span class="nav-count">{{ whitelistOverview.entries.length }}</span>
        </button>
      </nav>

      <div class="side-status">
        <div class="side-status-row"><span>后端服务</span><strong>{{ healthOk ? "正常" : "离线" }}</strong></div>
        <div class="side-status-row">
          <span>分析引擎</span>
          <strong>{{ aiConfig?.configured ? aiConfig.provider : "本地规则" }}</strong>
        </div>
        <small>{{ aiConfig?.message ?? "正在检查 AI 配置..." }}</small>
        <small v-if="aiConfig?.configured">{{ aiConfig.model }}</small>
      </div>
    </aside>

    <div class="main-col">
      <header class="page-header">
        <div class="breadcrumb">
          <strong>{{ view === "list" ? "日志列表" : "分析详情" }}</strong>
          <span v-if="view === 'detail' && result">/ {{ result.metadata.filename }}</span>
        </div>
        <span class="spacer"></span>
        <template v-if="view === 'detail' && result">
          <button v-if="canDownload" class="btn btn-ghost btn-sm" @click="downloadLogs">下载原始日志</button>
          <button class="btn btn-ghost btn-sm" @click="downloadReport('json')">导出 JSON</button>
          <button class="btn btn-ghost btn-sm" @click="downloadReport('html')">导出 HTML</button>
          <select
            class="btn btn-ghost btn-sm"
            aria-label="导出到 SIEM 平台"
            @change="onSiemExport"
          >
            <option value="" disabled selected>导出 SIEM…</option>
            <option value="splunk">Splunk (CIM)</option>
            <option value="elastic">Elastic (ECS)</option>
            <option value="opensearch">OpenSearch (bulk)</option>
            <option value="timesketch">Timesketch</option>
            <option value="sarif">SARIF</option>
          </select>
        </template>
        <button
          class="theme-toggle"
          :title="theme === 'dark' ? '切换为浅色模式' : '切换为暗黑模式'"
          :aria-label="theme === 'dark' ? '切换为浅色模式' : '切换为暗黑模式'"
          @click="toggleTheme"
        >
          <svg v-if="theme === 'dark'" width="15" height="15" viewBox="0 0 24 24" fill="none" aria-hidden="true">
            <circle cx="12" cy="12" r="4.2" stroke="currentColor" stroke-width="1.8" />
            <path d="M12 2.5v2.2M12 19.3v2.2M2.5 12h2.2M19.3 12h2.2M5 5l1.6 1.6M17.4 17.4 19 19M19 5l-1.6 1.6M6.6 17.4 5 19" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" />
          </svg>
          <svg v-else width="15" height="15" viewBox="0 0 24 24" fill="none" aria-hidden="true">
            <path d="M20.2 14.5A8.3 8.3 0 0 1 9.5 3.8a8.3 8.3 0 1 0 10.7 10.7Z" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round" />
          </svg>
        </button>
        <span class="badge badge-state" :class="aiConfig?.configured ? 'on' : 'off'">
          {{ aiConfig?.configured ? `AI 已配置 · ${aiConfig.provider}` : "本地规则引擎" }}
        </span>
        <button class="btn" @click="openUpload">上传日志</button>
      </header>

      <!-- 常驻筛选工具栏：列表视图筛选日志列表，详情视图筛选日志明细 -->
      <section class="toolbar">
        <div class="toolbar-top">
          <template v-if="view === 'list'">
            <span class="scope-chip">
              <svg width="13" height="13" viewBox="0 0 16 16" fill="none" aria-hidden="true">
                <path d="M2 4h12l-4.6 5.2V13l-2.8-1.4V9.2L2 4Z" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round" />
              </svg>
              日志列表筛选
            </span>
            <span class="toolbar-count">{{ toolbarCount }}</span>
          </template>

          <template v-else>
            <button class="btn btn-ghost btn-sm" @click="backToList">← 返回日志列表</button>
            <div v-if="result && !detailLoading" class="toolbar-actions">
              <!-- 搜索语法：字段:值 + 负号排除 + 裸词全文（仿 Zircolite 顶部搜索框） -->
              <div class="search-box">
                <svg width="14" height="14" viewBox="0 0 16 16" fill="none" aria-hidden="true">
                  <circle cx="7" cy="7" r="4.4" stroke="currentColor" stroke-width="1.6" />
                  <path d="M10.4 10.4 14 14" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" />
                </svg>
                <input
                  v-model="searchQuery"
                  type="search"
                  placeholder="查询，例如 source_ip:10.0.0.8 -login"
                  aria-label="搜索语法查询"
                  @keyup.enter="runSearch(1)"
                />
                <button class="btn btn-ghost btn-sm" :disabled="searchLoading" @click="runSearch(1)">
                  {{ searchLoading ? "查询中…" : "查询" }}
                </button>
              </div>
              <button class="btn btn-ghost btn-sm" @click="openRulePreview">规则试运行</button>
              <button class="btn btn-sm" :disabled="aiLoading" @click="analyzeWithAi">
                <span v-if="aiLoading" class="spinner"></span>
                {{ aiLoading ? "AI 研判中..." : "进行 AI 研判" }}
              </button>
            </div>
          </template>
        </div>

        <div v-if="view === 'list'" class="toolbar-fields">
          <input v-model="listFilters.keyword" type="search" placeholder="搜索文件名 / 日志类型 / 任务号" />
          <PickerSelect
            v-model="listFilters.log_type"
            name="list-type"
            :options="listTypeOptions"
            placeholder="全部日志类型"
            aria-label="日志类型"
            class="toolbar-select"
          />
          <PickerSelect
            v-model="listFilters.risk_level"
            name="list-risk"
            :options="riskLevelOptions"
            placeholder="全部风险等级"
            aria-label="风险等级"
            class="toolbar-select"
          />
          <PickerSelect
            v-model="listFilters.status"
            name="list-status"
            :options="listStatusOptions"
            placeholder="全部状态"
            aria-label="分析状态"
            class="toolbar-select"
          />
          <PickerSelect
            v-model="listFilters.sort"
            name="list-sort"
            :options="listSortOptions"
            class="toolbar-select is-sort"
            aria-label="排序"
          />
          <button class="btn btn-ghost btn-sm" :disabled="!hasListFilters" @click="resetListFilters">重置</button>
        </div>

        <div v-else class="filter-bar">
          <div class="filter-cell is-narrow">
            <svg class="field-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
              <circle cx="12" cy="12" r="10" />
              <path d="M2 12h20" />
              <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
            </svg>
            <input v-model="recordFilters.source_ip" placeholder="源 IP" @keyup.enter="loadRecords(1)" />
          </div>
          <div class="filter-cell is-narrow">
            <svg class="field-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
              <circle cx="12" cy="12" r="10" />
              <path d="M12 8l4 4-4 4" />
              <path d="M8 12h8" />
            </svg>
            <input v-model="recordFilters.destination_ip" placeholder="目的 IP" @keyup.enter="loadRecords(1)" />
          </div>
          <div class="filter-cell is-wide">
            <svg class="field-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
              <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71" />
              <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71" />
            </svg>
            <input v-model="recordFilters.path" placeholder="路径 / URL" @keyup.enter="loadRecords(1)" />
          </div>
          <div class="filter-cell is-type">
            <svg class="field-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
              <polygon points="12 2 2 7 12 12 22 7" />
              <polyline points="2 17 12 22 22 17" />
              <polyline points="2 12 12 17 22 12" />
            </svg>
            <PickerSelect
              v-model="recordFilters.log_type"
              name="record-type"
              :options="recordTypeOptions"
              placeholder="全部日志类型"
              aria-label="日志类型"
              class="filter-select"
            />
          </div>
          <div class="filter-cell is-narrow">
            <svg class="field-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
              <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
            </svg>
            <input v-model="recordFilters.action" placeholder="动作" @keyup.enter="loadRecords(1)" />
          </div>
          <div class="filter-cell is-narrow">
            <svg class="field-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
              <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
              <polyline points="22 4 12 14.01 9 11.01" />
            </svg>
            <input v-model="recordFilters.status" placeholder="状态码 / 结果" @keyup.enter="loadRecords(1)" />
          </div>
          <div class="filter-actions">
            <button class="btn btn-sm" @click="loadRecords(1)">筛选</button>
            <button class="btn btn-ghost btn-sm" :disabled="!hasRecordFilters" @click="resetRecordFilters">重置</button>
            <button class="btn btn-soft btn-sm" @click="exportRecords">导出 CSV</button>
            <span class="toolbar-count">{{ toolbarCount }}</span>
          </div>
        </div>
      </section>

      <main class="content">
        <p v-if="error" class="alert alert-error" style="margin-bottom: 14px">{{ error }}</p>
        <p v-else-if="notice" class="alert alert-warn" style="margin-bottom: 14px">{{ notice }}</p>

        <div v-if="configNotice" class="alert" :class="configNoticeType === 'success' ? 'alert-ok' : 'alert-error'" style="margin-bottom: 14px">
          {{ configNotice }}
        </div>

        <!-- 日志列表视图 -->
        <template v-if="view === 'list'">
          <section class="panel">
            <div class="panel-head">
              <div>
                <p class="eyebrow">Logs</p>
                <h2>日志分析列表</h2>
                <p class="panel-sub">
                  共 {{ history.length }} 条记录{{ hasListFilters ? `，当前筛选出 ${filteredHistory.length} 条` : "" }}
                </p>
              </div>
            </div>

            <div v-if="usageWithData.length" class="usage-trend">
              <div class="usage-trend-head">
                <div>
                  <p class="eyebrow">AI Cost</p>
                  <h3>AI 研判用量趋势</h3>
                  <p class="panel-sub">{{ usageSummary }}</p>
                </div>
                <div class="usage-mode">
                  <button
                    class="chip"
                    :class="{ active: usageChartMode === 'tokens' }"
                    @click="usageChartMode = 'tokens'"
                  >输入 tokens</button>
                  <button
                    class="chip"
                    :class="{ active: usageChartMode === 'cache' }"
                    @click="usageChartMode = 'cache'"
                  >缓存命中率</button>
                </div>
              </div>

              <div class="usage-bars">
                <div v-for="bar in usageBars" :key="bar.key" class="usage-bar">
                  <span class="usage-bar-value">{{ bar.display }}</span>
                  <div class="usage-bar-track">
                    <span
                      class="usage-bar-fill"
                      :class="{ 'is-missing': !bar.hasUsage }"
                      :style="{ height: bar.hasUsage ? `${bar.ratio * 100}%` : '0' }"
                    ></span>
                    <span v-if="!bar.hasUsage" class="usage-bar-gap">无记录</span>
                  </div>
                  <span class="usage-bar-label">{{ bar.label }}</span>
                </div>
              </div>

              <p v-if="usageHistory && usageHistory.with_usage < usageHistory.total_points" class="muted usage-note">
                有 {{ usageHistory.total_points - usageHistory.with_usage }} 次研判未留下用量记录（早期工具轮次失败后会丢失轨迹），
                趋势图与均值只按有记录的 {{ usageHistory.with_usage }} 次计算，缺口未按 0 计入。
              </p>
            </div>

            <div v-if="!pagedHistory.length" class="empty-state">
              <span class="empty-icon">
                <svg width="20" height="20" viewBox="0 0 20 20" fill="none" aria-hidden="true">
                  <path d="M4 3h8l4 4v10H4V3Z" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round" />
                  <path d="M7 10h6M7 13h4" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" />
                </svg>
              </span>
              <strong>{{ history.length ? "没有符合筛选条件的日志" : "还没有日志分析记录" }}</strong>
              <p>{{ history.length ? "调整上方筛选条件，或点击重置。" : "上传 SSH、Nginx、Apache 或通用文本日志，系统会自动识别类型并研判可疑行为。" }}</p>
              <button v-if="!history.length" class="btn" @click="openUpload">上传第一份日志</button>
            </div>

            <template v-else>
              <div class="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>文件名</th>
                      <th>日志类型</th>
                      <th>风险等级</th>
                      <th>状态</th>
                      <th>上传时间</th>
                      <th style="text-align: right">操作</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr v-for="item in pagedHistory" :key="item.id" class="clickable" @click="openAnalysis(item)">
                      <td>
                        <div class="cell-strong">{{ item.filename }}</div>
                        <div class="mono" style="color: var(--text-soft); font-size: 11px">{{ item.id.slice(0, 8) }}</div>
                      </td>
                      <td>
                        <span v-if="item.log_type" class="kind-tag" :class="`tone-${logTypeTone(item.log_type)}`">{{ item.log_type }}</span>
                        <span v-else class="muted">-</span>
                      </td>
                      <td>
                        <span v-if="item.status === 'completed'" class="badge badge-risk" :class="item.risk_level">{{ riskText(item.risk_level) }}</span>
                        <span v-else class="badge neutral">—</span>
                      </td>
                      <td><span class="badge badge-status" :class="item.status">{{ statusText(item.status) }}</span></td>
                      <td class="cell-nowrap tabular">{{ formatTime(item.created_at) }}</td>
                      <td>
                        <div class="cell-actions" @click.stop>
                          <button class="btn btn-ghost btn-sm" :disabled="item.status !== 'completed'" @click="openAnalysis(item)">查看</button>
                          <button v-if="!item.filename.startsWith('demo-')" class="btn btn-ghost btn-sm" title="下载原始日志" @click="downloadAnalysisFiles(item.id)">下载</button>
                          <button class="btn btn-danger btn-sm" @click="removeAnalysis(item)">删除</button>
                        </div>
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>

              <div class="pagination">
                <div class="page-size">
                  每页
                  <PickerSelect
                    v-model="listPageSize"
                    name="list-page-size"
                    :options="listPageSizeOptions"
                    aria-label="每页条数"
                    class="pager-select"
                  />
                  条
                </div>
                <span class="page-info">第 {{ listPage }} / {{ listTotalPages }} 页 · 共 {{ filteredHistory.length }} 条</span>
                <div class="page-list">
                  <button class="page-btn" :disabled="listPage <= 1" @click="listPage = 1">首页</button>
                  <button class="page-btn" :disabled="listPage <= 1" @click="listPage -= 1">‹</button>
                  <template v-for="(page, index) in listPageItems" :key="index">
                    <span v-if="page === 'gap'" class="page-gap">…</span>
                    <button v-else class="page-btn" :class="{ active: page === listPage }" @click="goToPage(page)">{{ page }}</button>
                  </template>
                  <button class="page-btn" :disabled="listPage >= listTotalPages" @click="listPage += 1">›</button>
                  <button class="page-btn" :disabled="listPage >= listTotalPages" @click="listPage = listTotalPages">末页</button>
                </div>
              </div>
            </template>
          </section>
        </template>

        <!-- 分析详情视图 -->
        <template v-else>
          <div v-if="detailLoading" class="panel empty-state">
            <span class="empty-icon"><span class="spinner spinner-dark"></span></span>
            <strong>正在加载分析结果…</strong>
          </div>

          <template v-else-if="result">
          <div class="detail-shell">
            <!-- 左侧分区导航（仿 Zircolite NavRail）：一次只显示一个视图 -->
            <nav class="rail" aria-label="分析视图">
              <p class="rail-title">视图</p>
              <button
                v-for="item in detailModules"
                :key="item.id"
                class="rail-item"
                :class="[`tier-${item.tier}`, { active: activeView === item.id }]"
                :title="`切换到${item.label}`"
                @click="setActiveView(item.id)"
              >
                <span class="rail-index">{{ item.index }}</span>
                <span class="rail-label">{{ item.label }}</span>
                <span v-if="item.count !== null" class="rail-count">{{ item.count }}</span>
              </button>
            </nav>
            <div class="detail-main">
            <!-- 01 分析概览：结论、建议与关键统计 -->
            <section v-if="activeView === 'overview'" id="module-overview" class="module tier-verdict">
              <header class="module-head">
                <span class="module-index">{{ moduleIndex("overview") }}</span>
                <div class="module-title">
                  <h2>分析概览</h2>
                  <p class="module-sub">
                    {{ result.metadata.source_files.join("、") || result.metadata.filename }} ·
                    {{ result.metadata.log_type }} 日志 · 识别置信度
                    {{ Math.round(result.metadata.recognition_confidence * 100) }}%
                  </p>
                </div>
                <div class="module-tools">
                  <span class="module-tier">{{ moduleTierLabel("overview") }}</span>
                  <button class="module-toggle" @click="toggleModule('overview')">
                    {{ isCollapsed("overview") ? "展开" : "收起" }}
                  </button>
                </div>
              </header>

              <div v-show="!isCollapsed('overview')" class="module-body">
                <!-- 检测规模看板（仿 Zircolite Overview）：先给规模与分布，再给结论 -->
                <section v-if="dashboard" class="dash">
                  <header class="dash-head">
                    <h3>
                      {{ dashboard.events_total.toLocaleString() }} 个可疑事件
                      <span class="dash-sub">（共 {{ dashboard.total_records.toLocaleString() }} 条记录，{{ dashboard.covered_records.toLocaleString() }} 条命中规则）</span>
                    </h3>
                    <span v-if="dashboard.note" class="dash-note">{{ dashboard.note }}</span>
                  </header>

                  <div class="sev-row">
                    <button
                      v-for="cell in severityCards"
                      :key="cell.risk_level"
                      class="sev-card"
                      :class="[`is-${cell.risk_level}`, { 'is-empty': !cell.events }]"
                      :title="`${riskText(cell.risk_level)}：${cell.events} 个事件、${cell.rules} 条规则`"
                      @click="setDetectionFilter(cell.risk_level)"
                    >
                      <span class="sev-dot" :class="cell.risk_level"></span>
                      <span class="sev-name">{{ riskText(cell.risk_level) }}</span>
                      <strong class="sev-count">{{ cell.events }}</strong>
                      <small>事件 · {{ cell.rules }} 条规则</small>
                    </button>
                  </div>

                  <div v-if="dashboard.buckets.length" class="strip-block">
                    <div class="strip-head">
                      <span class="strip-legend-label">中轴上方 = 记录数，下方 = 可疑事件（按风险分层，最严重贴近中轴）</span>
                      <span class="strip-range">
                        {{ dashboard.buckets[0].label }} — {{ dashboard.buckets[dashboard.buckets.length - 1].label }}
                      </span>
                    </div>
                    <div class="strip" role="img" aria-label="事件时间分布">
                      <div
                        v-for="bucket in dashboard.buckets"
                        :key="bucket.start_iso"
                        class="strip-col"
                        :title="bucketTip(bucket)"
                      >
                        <div class="strip-upper">
                          <span
                            class="strip-bar is-record"
                            :style="{ height: `${stripHeight(bucket.count, stripMaxRecords)}%` }"
                          ></span>
                        </div>
                        <div class="strip-axis"></div>
                        <div class="strip-lower">
                          <span
                            v-for="layer in stripLayers(bucket)"
                            :key="layer.level"
                            class="strip-bar"
                            :class="layer.level"
                            :style="{ height: `${layer.height}%` }"
                          ></span>
                        </div>
                      </div>
                    </div>
                    <div class="strip-legend">
                      <span v-for="level in RISK_ORDER" :key="level" class="legend-item">
                        <i class="sev-dot" :class="level"></i>{{ riskText(level) }}
                      </span>
                    </div>
                  </div>

                  <div v-if="tacticGrid.length" class="tactic-block">
                    <div class="insight-head">
                      <h3>ATT&amp;CK 战术分布</h3>
                      <span class="insight-note">格内数字 = 该战术下的事件数（深色 = 相对更多）· 点击查看该战术的规则榜</span>
                    </div>
                    <div class="tactic-grid">
                      <button
                        v-for="cell in tacticGrid"
                        :key="cell.tactic"
                        class="tactic-cell"
                        :class="{ 'is-empty': !cell.events }"
                        :style="{ '--heat': tacticHeat(cell).opacity }"
                        :title="`${cell.tactic}：${cell.events} 个事件、${cell.rules} 条规则`"
                      >
                        <span class="tactic-name">{{ cell.tactic }}</span>
                        <strong>{{ cell.events }}</strong>
                        <small>{{ cell.rules }} 条规则</small>
                      </button>
                    </div>
                  </div>

                  <div class="top-block">
                    <article class="top-col">
                      <h4>Top 规则</h4>
                      <ol class="top-list">
                        <li v-for="item in dashboard.top_rules" :key="item.key">
                          <i class="sev-dot" :class="item.risk_level"></i>
                          <span class="top-label">{{ item.label }}</span>
                          <code class="rule-code">{{ item.key }}</code>
                          <b class="tabular">{{ item.events }}</b>
                        </li>
                        <li v-if="!dashboard.top_rules.length" class="muted">本次没有命中规则的事件。</li>
                      </ol>
                    </article>
                    <article class="top-col">
                      <h4>Top 主机 / 资产</h4>
                      <ol class="top-list">
                        <li v-for="item in dashboard.top_hosts" :key="item.key">
                          <i class="sev-dot" :class="item.risk_level"></i>
                          <span class="top-label">{{ item.label }}</span>
                          <b class="tabular">{{ item.events }}</b>
                        </li>
                        <li v-if="!dashboard.top_hosts.length" class="muted">主机侧日志（Sysmon / Windows）才会产生主机维度。</li>
                      </ol>
                    </article>
                    <article class="top-col">
                      <h4>Top 来源 IP</h4>
                      <ol class="top-list">
                        <li v-for="item in dashboard.top_ips" :key="item.key">
                          <i class="sev-dot" :class="item.risk_level"></i>
                          <span class="top-label">{{ item.label }}</span>
                          <b class="tabular">{{ item.events }}</b>
                        </li>
                        <li v-if="!dashboard.top_ips.length" class="muted">本次事件没有关联来源 IP。</li>
                      </ol>
                    </article>
                  </div>
                </section>
                <p v-else-if="dashboardLoading" class="muted">正在统计检测规模…</p>

                <section class="metric-grid">
                  <div class="metric">
                    <span>日志类型</span>
                    <strong class="metric-type">
                      <span class="kind-tag" :class="`tone-${logTypeTone(result.metadata.log_type)}`">{{ result.metadata.log_type }}</span>
                    </strong>
                    <small>识别置信度 {{ Math.round(result.metadata.recognition_confidence * 100) }}%</small>
                  </div>
                  <div class="metric">
                    <span>日志行数</span>
                    <strong>{{ result.metadata.total_lines.toLocaleString() }}</strong>
                    <small>已解析 {{ result.metadata.parsed_lines.toLocaleString() }} 行</small>
                  </div>
                  <div class="metric">
                    <span>认证失败 / 成功</span>
                    <strong>{{ result.statistics.failed_login }} / {{ result.statistics.successful_login }}</strong>
                    <small>来自 {{ result.metadata.source_files.length || 1 }} 个来源文件</small>
                  </div>
                  <div class="metric" :class="`is-${result.risk_level}`">
                    <span>当前研判</span>
                    <strong>{{ riskLabel }}</strong>
                    <small>{{ eventsTotal }} 个可疑事件</small>
                  </div>
                </section>

                <div class="overview-grid">
                  <article class="verdict-card" :class="`is-${result.risk_level}`">
                    <div class="verdict-head">
                      <span class="badge badge-risk" :class="result.risk_level">{{ riskLabel }}</span>
                      <strong>研判置信度 {{ Math.round(result.confidence * 100) }}%</strong>
                      <span class="badge neutral badge-plain">{{ analysisSourceText }}</span>
                      <span class="badge badge-ai" :class="aiStatusClass">{{ aiStatusText }}</span>
                    </div>
                    <p class="verdict-text">{{ result.conclusion }}</p>
                    <p class="verdict-meta">{{ result.summary }}</p>
                    <p v-if="result.coverage?.limitation" class="alert alert-warn">
                      检测覆盖不足：{{ result.coverage.limitation }}。本次结论不能作为「已排查无问题」的依据。
                    </p>
                    <p v-if="result.coverage" class="verdict-meta">
                      检测覆盖：{{ result.coverage.covered_records }} /
                      {{ result.coverage.total_records }} 条记录命中规则 ·
                      {{ result.coverage.evaluable_records }} 条含可判定字段<template
                        v-if="result.coverage.parse_failures"
                      >
                        · {{ result.coverage.parse_failures }} 条未纳入检测<template
                          v-if="coverageDropDetail(result.coverage)"
                        >
                          （{{ coverageDropDetail(result.coverage) }}）</template
                        ></template
                      ><template v-if="result.coverage.whitelisted_records">
                        · {{ result.coverage.whitelisted_records }} 条命中白名单已跳过</template
                      >
                    </p>
                    <details
                      v-if="result.coverage?.parse_error_details?.length"
                      class="coverage-errors"
                    >
                      <summary>
                        查看解析失败详情（{{ result.coverage.parse_error_details.length }} 条，后端最多保留 50 条）
                      </summary>
                      <div
                        v-for="(item, index) in result.coverage.parse_error_details"
                        :key="`${item.source_file || 'unknown'}-${item.line_number || index}`"
                        class="coverage-error-item"
                      >
                        <strong>
                          {{ item.source_file || "未标记文件" }}
                          <span v-if="item.line_number"> · 第 {{ item.line_number }} 条</span>
                        </strong>
                        <span>{{ item.reason || "解析失败" }}</span>
                        <code v-if="item.raw_preview">{{ item.raw_preview }}</code>
                      </div>
                    </details>
                    <div v-if="result.analysis_source === 'rules'" class="analysis-note">
                      <strong>当前结论来自确定性规则和日志证据</strong>
                      <span>未调用 AI。点击右上角「进行 AI 研判」可补充语义分析与证据溯源。</span>
                    </div>
                    <div v-if="result.ai_status === 'unavailable'" class="alert alert-warn">
                      AI 暂时不可用，当前展示本地规则分析结果。{{ result.ai_error ? `原因：${result.ai_error}` : "" }}
                    </div>
                  </article>

                  <article v-if="result.behavior_deviations?.length" class="deviation-card">
                    <div class="deviation-head">
                      <h3>行为偏离（IOA）</h3>
                      <span class="badge neutral badge-plain">{{ result.behavior_deviations.length }} 项</span>
                    </div>
                    <p class="deviation-note">
                      未命中已知攻击特征，但存在以下偏离。均为低置信度信号，不构成攻击结论，也不改变风险等级；
                      口径为与本批次记录相比，非历史基线。
                    </p>
                    <div v-for="(item, index) in result.behavior_deviations" :key="`${item.kind}-${index}`" class="deviation-item">
                      <div class="deviation-title">
                        <span class="kind-tag tone-gray">{{ item.name }}</span>
                        <strong v-if="item.count > 1">×{{ item.count }}</strong>
                      </div>
                      <p>{{ item.detail }}</p>
                      <p class="deviation-basis">基线口径：{{ item.basis }}</p>
                      <details v-if="item.evidence.length">
                        <summary>查看原始证据（{{ item.evidence.length }} 条）</summary>
                        <pre class="deviation-evidence">{{ item.evidence.join("\n") }}</pre>
                      </details>
                    </div>
                  </article>

                  <article class="stat-card">
                    <h3>关键统计</h3>
                    <div class="stat-block">
                      <span class="stat-label">来源 IP Top</span>
                      <div v-if="!result.statistics.top_source_ips.length" class="muted">无来源 IP 统计。</div>
                      <div v-for="item in result.statistics.top_source_ips" :key="item.value" class="bar-row">
                        <span class="cell-mono">{{ item.value }}</span>
                        <strong>{{ item.count }}</strong>
                      </div>
                    </div>
                    <div v-if="result.statistics.status_codes.length" class="stat-block">
                      <span class="stat-label">HTTP 状态码</span>
                      <div v-for="item in result.statistics.status_codes" :key="item.value" class="bar-row">
                        <span class="cell-mono">{{ item.value }}</span>
                        <strong>{{ item.count }}</strong>
                      </div>
                    </div>
                    <div v-if="result.risk_scores.length" class="stat-block">
                      <span class="stat-label">
                        异常评分 · {{ result.risk_score_enabled ? "已参与定级" : "仅参考，未参与定级" }}
                      </span>
                      <div
                        v-for="item in result.risk_scores.slice(0, 5)"
                        :key="`${item.kind || 'source_ip'}-${item.key || item.source_ip}`"
                        class="bar-row"
                      >
                        <span class="cell-mono">{{ riskScoreLabel(item) }}</span>
                        <strong>
                          {{ item.score }} 分 ·
                          <span class="badge badge-risk" :class="item.escalated_level">{{ riskText(item.escalated_level) }}</span>
                        </strong>
                      </div>
                    </div>
                  </article>
                </div>

                <article class="advice-card">
                  <h3>处置建议</h3>
                  <ul v-if="result.recommendations.length" class="reco-list">
                    <li v-for="item in result.recommendations" :key="item">{{ item }}</li>
                  </ul>
                  <p v-else class="muted">暂无排查建议。</p>
                </article>
              </div>
            </section>

            <!-- 查询视图（仿 Zircolite 搜索）：字段:值 + 负号排除 + 裸词全文 -->
            <section v-if="activeView === 'query'" id="module-query" class="module tier-context">
              <header class="module-head">
                <span class="module-index">{{ moduleIndex("query") }}</span>
                <div class="module-title">
                  <h2>查询</h2>
                  <p class="module-sub">
                    匹配 {{ searchResult?.records_total ?? 0 }} 条记录 · {{ searchResult?.events_total ?? 0 }} 个事件<template
                      v-if="searchResult?.query"
                    >
                      · 查询「{{ searchResult.query }}」</template
                    >
                  </p>
                </div>
                <div class="module-tools">
                  <span class="module-tier">{{ moduleTierLabel("query") }}</span>
                  <button class="module-toggle" @click="toggleModule('query')">
                    {{ isCollapsed("query") ? "展开" : "收起" }}
                  </button>
                </div>
              </header>

              <div v-show="!isCollapsed('query')" class="module-body">
                <div class="search-bar">
                  <input
                    v-model="searchQuery"
                    type="search"
                    placeholder="例如 source_ip:10.0.0.8 -login 或 账号:root"
                    aria-label="搜索语法查询"
                    @keyup.enter="runSearch(1)"
                  />
                  <button class="btn" :disabled="searchLoading" @click="runSearch(1)">
                    {{ searchLoading ? "查询中…" : "查询" }}
                  </button>
                </div>
                <p class="search-syntax">
                  语法：<code>字段:值</code>（精确包含）· <code>-字段:值</code>（排除）·
                  <code>"多词短语"</code>（整体匹配）· 裸词（跨字段全文）。可用字段：
                  <code v-for="field in SEARCH_FIELD_HINTS" :key="field">{{ field }}</code>
                </p>

                <div v-if="searchResult?.warnings.length" class="alert alert-warn">
                  <p v-for="warning in searchResult.warnings" :key="warning">{{ warning }}</p>
                </div>

                <template v-if="searchResult">
                  <p class="muted">
                    解析为 {{ searchResult.terms.length }} 个条件：<code
                      v-for="term in searchResult.terms"
                      :key="`${term.field}-${term.value}`"
                      class="rule-code"
                    >{{ searchTermText(term) }}</code>
                  </p>

                  <div v-if="searchResult.events_total" class="search-block">
                    <h4>匹配的可疑事件（{{ searchResult.events_total }}）</h4>
                    <article v-for="item in searchResult.events" :key="item.id" class="event" :class="`risk-${item.risk_level}`">
                      <div class="event-head">
                        <div class="event-title">
                          <span class="badge badge-risk" :class="item.risk_level">{{ riskText(item.risk_level) }}</span>
                          <h3>{{ item.name }}</h3>
                        </div>
                        <strong>{{ item.count }} 次</strong>
                      </div>
                      <p>{{ item.summary }}</p>
                      <p v-if="item.rule_id" class="event-meta event-rule">检测规则：<code>{{ item.rule_id }}</code></p>
                    </article>
                  </div>

                  <div class="search-block">
                    <h4>匹配的原始记录（{{ searchResult.records_total }}）</h4>
                    <div v-if="searchResult.records.length" class="table-wrap">
                      <table class="records-table compact">
                        <thead>
                          <tr><th>时间</th><th>来源 IP</th><th>账号</th><th>状态</th><th>URL / 路径</th><th>原文</th></tr>
                        </thead>
                        <tbody>
                          <tr v-for="record in searchResult.records" :key="record.record_id ?? record.raw ?? ''">
                            <td class="cell-nowrap">{{ record.timestamp ?? "-" }}</td>
                            <td class="cell-mono cell-nowrap">{{ record.source_ip ?? "-" }}</td>
                            <td class="cell-nowrap">{{ record.username ?? "-" }}</td>
                            <td class="cell-nowrap tabular">{{ record.status ?? record.result ?? "-" }}</td>
                            <td class="cell-mono">{{ record.url ?? "-" }}</td>
                            <td><small class="cell-note">{{ record.raw }}</small></td>
                          </tr>
                        </tbody>
                      </table>
                    </div>
                    <p v-else class="muted">没有匹配的记录。</p>
                    <div v-if="searchResult.records_total > searchResult.records.length" class="search-pager">
                      <button
                        class="btn btn-ghost btn-sm"
                        :disabled="searchResult.page <= 1"
                        @click="runSearch(searchResult.page - 1)"
                      >上一页</button>
                      <span class="muted">
                        第 {{ searchResult.page }} 页 · 已展示 {{ searchResult.records.length }} /
                        {{ searchResult.records_total }} 条
                      </span>
                      <button
                        class="btn btn-ghost btn-sm"
                        :disabled="searchResult.page * searchResult.page_size >= searchResult.records_total"
                        @click="runSearch(searchResult.page + 1)"
                      >下一页</button>
                    </div>
                  </div>
                </template>
                <p v-else class="muted">在上方输入查询条件后回车或用「查询」按钮执行。</p>
              </div>
            </section>

            <!-- ATT&CK 矩阵（仿 Zircolite Attack 页）：战术 × 技术两级，点击技术看由哪些规则报出 -->
            <section v-if="activeView === 'attack'" id="module-attack" class="module tier-insight">
              <header class="module-head">
                <span class="module-index">{{ moduleIndex("attack") }}</span>
                <div class="module-title">
                  <h2>ATT&amp;CK 矩阵</h2>
                  <p class="module-sub">
                    本次命中 {{ attackMatrix?.techniques_hit ?? 0 }} 项技术 ·
                    标尺清单共 {{ attackMatrix?.techniques_total ?? 0 }} 项<template
                      v-if="attackMatrix?.note"
                    >
                      · {{ attackMatrix.note }}</template
                    >
                  </p>
                </div>
                <div class="module-tools">
                  <button class="btn btn-ghost btn-sm" @click="exportAttackNavigator">
                    导出 ATT&amp;CK Navigator
                  </button>
                  <button class="btn btn-ghost btn-sm" @click="attackFullMatrix = !attackFullMatrix">
                    {{ attackFullMatrix ? "只看命中的技术" : "显示完整清单" }}
                  </button>
                  <button class="module-toggle" @click="toggleModule('attack')">
                    {{ isCollapsed("attack") ? "展开" : "收起" }}
                  </button>
                </div>
              </header>

              <div v-show="!isCollapsed('attack')" class="module-body">
                <p v-if="!attackMatrix" class="muted">正在映射 ATT&amp;CK 技术…</p>
                <div v-else-if="!attackVisibleColumns.length" class="empty-state">
                  <strong>本次没有可映射到 ATT&amp;CK 技术的命中</strong>
                  <p>这不等于没有可疑行为——可能命中的规则尚未声明技术映射，请看「检测」视图。</p>
                </div>
                <div v-else class="attack-grid">
                  <article v-for="column in attackVisibleColumns" :key="column.tactic" class="attack-col">
                    <header class="attack-col-head">
                      <h4>{{ column.tactic }}</h4>
                      <span class="attack-col-count">{{ column.events }} 个事件</span>
                    </header>
                    <button
                      v-for="cell in attackColumnCells(column)"
                      :key="cell.technique"
                      class="attack-cell"
                      :class="{ 'is-empty': !cell.events, 'is-expanded': expandedTechniques.includes(cell.technique) }"
                      :style="{ '--heat': techniqueHeat(cell).opacity }"
                      :title="cell.name ? `${cell.technique} ${cell.name}` : cell.technique"
                      @click="toggleTechnique(cell.technique)"
                    >
                      <span class="attack-cell-id">{{ cell.technique }}</span>
                      <span class="attack-cell-name">{{ cell.name || "标尺清单外的技术" }}</span>
                      <b class="attack-cell-count">{{ cell.events }}</b>
                      <span v-if="!cell.in_benchmark" class="attack-cell-flag" title="不在项目内置标尺清单里，但本次确实命中">清单外</span>
                    </button>
                    <div
                      v-for="cell in attackColumnCells(column).filter((item) => expandedTechniques.includes(item.technique))"
                      :key="`${cell.technique}-detail`"
                      class="attack-cell-detail"
                    >
                      <p class="attack-detail-title">{{ cell.technique }} 由这些规则报出：</p>
                      <ul>
                        <li v-for="rule in cell.rules" :key="rule"><code class="rule-code">{{ rule }}</code></li>
                        <li v-if="!cell.rules.length" class="muted">本次未命中，无对应规则</li>
                      </ul>
                      <button class="btn btn-ghost btn-sm" @click="setActiveView('detections')">去检测视图看规则</button>
                    </div>
                  </article>
                </div>
              </div>
            </section>

            <!-- 检测视图（仿 Zircolite Detections）：按规则归组，看「哪些规则在报、报了多少」 -->
            <section v-if="activeView === 'detections'" id="module-detections" class="module tier-verdict">
              <header class="module-head">
                <span class="module-index">{{ moduleIndex("detections") }}</span>
                <div class="module-title">
                  <h2>检测</h2>
                  <p class="module-sub">
                    共 {{ detections?.groups_total ?? 0 }} 条规则命中<template v-if="detections?.note"> · {{ detections.note }}</template>
                  </p>
                </div>
                <div class="module-tools">
                  <span class="module-tier">{{ moduleTierLabel("detections") }}</span>
                  <button class="module-toggle" @click="toggleModule('detections')">
                    {{ isCollapsed("detections") ? "展开" : "收起" }}
                  </button>
                </div>
              </header>

              <div v-show="!isCollapsed('detections')" class="module-body is-flush">
                <p v-if="detectionsLoading && !detections" class="muted">正在汇总规则命中…</p>
                <div v-else-if="detections && !detections.groups.length" class="empty-state">
                  <strong>本次没有规则命中</strong>
                  <p>这不等于「安全」——能不能下结论要看覆盖度：覆盖不完整时结论是「无法确认」。</p>
                </div>

                <article
                  v-for="group in detections?.groups ?? []"
                  :key="group.rule_id"
                  class="rule-group"
                  :class="`risk-${group.risk_level}`"
                >
                  <header class="rule-group-head" @click="toggleRuleDetail(group.rule_id)">
                    <span class="badge badge-risk" :class="group.risk_level">{{ riskText(group.risk_level) }}</span>
                    <div class="rule-group-title">
                      <strong>{{ group.name }}</strong>
                      <code class="rule-code">{{ group.rule_id }}</code>
                    </div>
                    <span class="rule-group-tactic">{{ group.tactic }}<template v-if="group.technique"> · {{ group.technique }}</template></span>
                    <span class="rule-group-count">{{ group.event_count }} 个事件 · 触发 {{ group.trigger_count }} 次</span>
                    <span class="rule-group-toggle">{{ expandedRules.includes(group.rule_id) ? "收起" : "详情" }}</span>
                  </header>

                  <div v-if="expandedRules.includes(group.rule_id)" class="rule-group-body">
                    <p v-if="group.description" class="rule-group-desc">{{ group.description }}</p>
                    <dl class="rule-meta">
                      <div><dt>规则来源</dt><dd>{{ ruleSourceText(group) }}</dd></div>
                      <div>
                        <dt>验证状态</dt>
                        <dd>{{ group.validation_status === "validated" ? "已验证（有本地正样本）" : "未验证（无本地正样本）" }}</dd>
                      </div>
                      <div v-if="group.entities.length"><dt>涉及实体</dt><dd>{{ group.entities.join("、") }}</dd></div>
                      <div v-if="group.source_files.length"><dt>来源文件</dt><dd>{{ group.source_files.join("、") }}</dd></div>
                      <div v-if="group.first_seen"><dt>首次 / 末次</dt><dd>{{ group.first_seen }} → {{ group.last_seen ?? "-" }}</dd></div>
                      <div v-if="group.author || group.version"><dt>作者 / 版本</dt><dd>{{ group.author ?? "-" }} / {{ group.version ?? "-" }}</dd></div>
                      <div v-if="group.license"><dt>许可证</dt><dd>{{ group.license }}</dd></div>
                    </dl>
                    <div v-if="group.tags.length" class="rule-tags">
                      <span v-for="tag in group.tags" :key="tag" class="rule-tag">{{ tag }}</span>
                    </div>

                    <table class="records-table compact rule-variants">
                      <thead>
                        <tr><th>实体 / 命中</th><th>风险</th><th>触发次数</th><th>首次出现</th></tr>
                      </thead>
                      <tbody>
                        <tr v-for="variant in group.variants" :key="variant.event_id">
                          <td>
                            <div class="cell-mono">{{ variant.label }}</div>
                            <small class="cell-note">{{ variant.summary }}</small>
                          </td>
                          <td><span class="badge badge-risk" :class="variant.risk_level">{{ riskText(variant.risk_level) }}</span></td>
                          <td class="cell-nowrap tabular">{{ variant.events }}</td>
                          <td class="cell-nowrap">{{ variant.first_seen ?? "-" }}</td>
                        </tr>
                      </tbody>
                    </table>
                    <p v-if="group.variants_total > group.variants.length" class="muted">
                      已展示 {{ group.variants.length }} / {{ group.variants_total }} 条命中明细（完整清单见报告导出）
                    </p>
                    <div class="rule-group-actions">
                      <button class="btn btn-ghost btn-sm" @click="setDetectionFilter(group.risk_level)">
                        看该风险等级的全部事件
                      </button>
                      <button class="btn btn-ghost btn-sm" @click="openEntityFromRule(group)">调查首个实体</button>
                    </div>
                  </div>
                </article>
              </div>
            </section>

            <!-- 02 可疑事件 -->
            <section v-if="activeView === 'events'" id="module-events" class="module tier-verdict">
              <header class="module-head">
                <span class="module-index">{{ moduleIndex("events") }}</span>
                <div class="module-title">
                  <h2>可疑事件</h2>
                  <p class="module-sub">
                    共 {{ eventsTotal }} 个事件<template v-if="!eventsTotal">
                      · 当前规则未命中异常特征</template
                    ><template v-else-if="eventsTruncated">
                      · 按风险从高到低展示前 {{ result.events.length }} 条，最高等级
                      {{ riskText(highestEventLevel) }}（完整清单见报告导出）</template
                    ><template v-else>
                      · 已按风险从高到低排列，最高等级 {{ riskText(highestEventLevel) }}</template
                    >
                  </p>
                </div>
                <div class="module-tools">
                  <span class="module-tier">{{ moduleTierLabel("events") }}</span>
                  <button class="module-toggle" @click="toggleModule('events')">
                    {{ isCollapsed("events") ? "展开" : "收起" }}
                  </button>
                </div>
              </header>

              <div v-show="!isCollapsed('events')" class="module-body is-flush">
                  <div
                    v-if="!eventsTotal"
                    class="empty-state"
                    :class="{ 'empty-state-warn': !!result.coverage?.limitation }"
                  >
                    <span class="empty-icon">
                      <svg width="20" height="20" viewBox="0 0 20 20" fill="none" aria-hidden="true">
                        <path d="M10 2.5 3 6v4.2c0 3.6 2.9 6.4 7 7.3 4.1-.9 7-3.7 7-7.3V6l-7-3.5Z" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round" />
                        <path d="M7.6 10.2l1.7 1.7 3.3-3.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" />
                      </svg>
                    </span>
                    <strong>
                      {{
                        result.coverage?.limitation
                          ? "检测覆盖不完整，本次无法确认是否存在异常"
                          : "已解析日志，当前规则未发现可疑事件"
                      }}
                    </strong>
                    <p>{{ result.conclusion }}</p>
                    <p v-if="result.coverage" class="empty-coverage">
                      检测覆盖：{{ result.coverage.covered_records }} /
                      {{ result.coverage.total_records }} 条记录命中规则 · 含可判定字段
                      {{ result.coverage.evaluable_records }} 条<template v-if="result.coverage.parse_failures">
                        · 未纳入检测 {{ result.coverage.parse_failures }} 条<template
                          v-if="coverageDropDetail(result.coverage)"
                        >
                          （{{ coverageDropDetail(result.coverage) }}）</template
                        ></template
                      ><template v-if="result.coverage.whitelisted_records">
                        · 命中白名单已跳过 {{ result.coverage.whitelisted_records }} 条</template
                      >
                    </p>
                    <p v-if="result.templates.length">
                      该日志未匹配已知类型，已用模板挖掘提取固定结构，可在下方「日志模板」查看；只出现一次的罕见模板最值得关注。
                    </p>
                  </div>

                  <button v-if="eventsTruncated" class="events-more" @click="loadMoreEvents">
                    加载更多事件（已展示 {{ result.events.length }} / {{ eventsTotal }} 条）
                  </button>

                  <div v-if="detectionLevelFilter" class="filter-chip">
                    <span>仅显示「{{ riskText(detectionLevelFilter) }}」事件</span>
                    <button class="filter-chip-clear" @click="setDetectionFilter(detectionLevelFilter)">清除</button>
                  </div>

                  <article v-for="item in visibleEvents" :key="item.id" class="event" :class="`risk-${item.risk_level}`">
                    <div class="event-head">
                      <div class="event-title">
                        <span class="badge badge-risk" :class="item.risk_level">{{ riskText(item.risk_level) }}</span>
                        <h3>{{ item.name }}</h3>
                      </div>
                      <strong>{{ item.count }} 次</strong>
                    </div>
                    <p>{{ item.summary }}</p>
                    <p v-if="item.source_files.length" class="event-meta">
                      来源：{{ item.source_files.join("、") }}
                      <span v-if="item.correlation_basis.length"> · 关联依据：{{ item.correlation_basis.join("、") }}</span>
                    </p>
                    <p v-if="item.rule_id" class="event-meta event-rule">检测规则：<code>{{ item.rule_id }}</code></p>
                    <details>
                      <summary>查看原始证据（{{ item.evidence.length }} 条）</summary>
                      <div v-if="item.evidence_items.length" class="evidence-list">
                        <div v-for="evidence in item.evidence_items" :key="evidence.id" class="evidence-item">
                          <div class="evidence-meta">
                            <strong>{{ evidence.id }}</strong>
                            <span>{{ evidence.source_file ?? "未标记来源" }}</span>
                            <span>{{ evidence.timestamp ?? "未知时间" }}</span>
                            <button
                              v-if="evidence.record_id"
                              class="evidence-link"
                              @click="focusEvidence(evidence.record_id)"
                            >
                              定位日志
                            </button>
                          </div>
                          <pre>{{ evidence.raw }}</pre>
                        </div>
                      </div>
                      <pre v-else v-for="line in item.evidence" :key="line">{{ line }}</pre>
                    </details>
                    <details v-if="item.timeline.length">
                      <summary>查看事件时间线（{{ item.timeline.length }} 条）</summary>
                      <pre v-for="line in item.timeline" :key="line">{{ line }}</pre>
                    </details>
                  </article>
              </div>
            </section>

            <!-- 威胁情报富化：公网指标送公开情报库比对，独立展示不参与定级 -->
            <section v-if="activeView === 'threat-intel'" id="module-threat-intel" class="module tier-context">
              <header class="module-head">
                <span class="module-index">{{ moduleIndex("threat-intel") }}</span>
                <div class="module-title">
                  <h2>威胁情报</h2>
                  <p class="module-sub">公网 IP / 域名送公开情报库比对 · 独立展示，不改变风险等级</p>
                </div>
                <div class="module-tools">
                  <span class="module-tier">{{ moduleTierLabel("threat-intel") }}</span>
                  <button class="module-toggle" @click="toggleModule('threat-intel')">
                    {{ isCollapsed("threat-intel") ? "展开" : "收起" }}
                  </button>
                </div>
              </header>
              <div v-show="!isCollapsed('threat-intel')" class="module-body">
                <div v-if="!threatIntel" class="ti-intro">
                  <p class="muted">
                    把本批日志中的公网 IP 与域名送到公开威胁情报库（ThreatFox / URLhaus / AbuseIPDB）比对。
                    功能默认关闭——查询会把指标发送到外部服务，需在 .env 开启
                    <code>THREAT_INTEL_ENABLED=true</code>。结果只作展示，不改变风险等级。
                  </p>
                  <button class="btn" :disabled="threatIntelLoading" @click="loadThreatIntel()">
                    {{ threatIntelLoading ? "查询中…" : "查询威胁情报" }}
                  </button>
                </div>
                <template v-else>
                  <p v-if="!threatIntel.enabled" class="muted">{{ threatIntel.note }}</p>
                  <template v-else>
                    <p class="muted ti-note">{{ threatIntel.note }}</p>
                    <div v-if="threatIntel.findings.length" class="table-wrap">
                      <table class="records-table compact">
                        <thead>
                          <tr>
                            <th>指标</th>
                            <th>类型</th>
                            <th>关联事件</th>
                            <th>综合结果</th>
                            <th>来源明细</th>
                          </tr>
                        </thead>
                        <tbody>
                          <tr
                            v-for="finding in threatIntel.findings"
                            :key="`${finding.indicator_type}-${finding.value}`"
                          >
                            <td class="cell-mono cell-nowrap">{{ finding.value }}</td>
                            <td class="cell-nowrap">{{ finding.indicator_type === "ip" ? "IP" : "域名" }}</td>
                            <td class="cell-nowrap tabular">{{ finding.related_events }}</td>
                            <td :class="{ 'ti-hit': finding.sources.some((item) => item.status === 'hit') }">
                              {{ finding.summary }}
                            </td>
                            <td>
                              <span
                                v-for="src in finding.sources"
                                :key="src.source"
                                class="ti-src"
                                :class="`ti-${src.status}`"
                                :title="src.detail"
                              >
                                {{ src.source }}：{{ threatIntelStatusText(src.status) }}<template v-if="src.confidence != null">（{{ Math.round(src.confidence * 100) }}%）</template>
                              </span>
                            </td>
                          </tr>
                        </tbody>
                      </table>
                    </div>
                    <div class="ti-foot">
                      <span class="muted">
                        已查询 {{ threatIntel.findings.length }} / 共 {{ threatIntel.indicators_total }} 个公网指标
                        <template v-if="threatIntel.generated_at"> · {{ threatIntel.generated_at }}</template>
                      </span>
                      <button class="btn btn-ghost" :disabled="threatIntelLoading" @click="loadThreatIntel(true)">
                        {{ threatIntelLoading ? "查询中…" : "强制重查（忽略缓存）" }}
                      </button>
                    </div>
                  </template>
                </template>
              </div>
            </section>

            <!-- AI 洞察：时间频次柱状图 + 攻击链（ATT&CK 风格） -->
            <section v-if="activeView === 'insights'" id="module-insights" class="module tier-insight">
              <header class="module-head">
                <span class="module-index">{{ moduleIndex("insights") }}</span>
                <div class="module-title">
                  <h2>AI 洞察</h2>
                  <p class="module-sub">
                    {{ insights?.timeseries.length || 0 }} 个时间段 ·
                    共 {{ chainsTotal }} 条攻击链<template v-if="chainsTruncated">
                      · 按风险从高到低展示前 {{ insights?.attack_chains.length || 0 }} 条</template
                    >
                  </p>
                </div>
                <div class="module-tools">
                  <span class="module-tier">{{ moduleTierLabel("insights") }}</span>
                  <button class="module-toggle" @click="toggleModule('insights')">
                    {{ isCollapsed("insights") ? "展开" : "收起" }}
                  </button>
                </div>
              </header>

              <div v-show="!isCollapsed('insights')" class="module-body">
                <!-- 时间频次柱状图 -->
                <div v-if="insightsSeries.length" class="insight-block">
                  <div class="insight-head">
                    <h3>时间频次柱状图</h3>
                    <span class="insight-note">柱高 = 记录频次，红色为峰值 · 便于对比攻击前后频次变化</span>
                  </div>
                  <div class="histogram" role="img" aria-label="时间频次柱状图">
                    <div
                      v-for="bucket in insightsSeries"
                      :key="bucket.start_iso"
                      class="hist-col"
                      :title="`${bucket.label} · 记录 ${bucket.count} · 独立 IP ${bucket.unique_source_ips} · 失败 ${bucket.failed_login} / 成功 ${bucket.successful_login}`"
                    >
                      <span v-if="bucket.count" class="hist-val">{{ bucket.count }}</span>
                      <div
                        class="hist-bar"
                        :class="{ peak: bucket === insightsSeries[insightsPeakIndex] }"
                        :style="{ height: `${Math.max(4, (bucket.count / insightsMax) * 100)}%` }"
                      ></div>
                    </div>
                  </div>
                  <div class="hist-axis">
                    <span
                      v-for="tick in insightsTicks"
                      :key="tick.index"
                      class="hist-axis-label"
                      :style="{ left: `${tick.left}%` }"
                    >{{ tick.label }}</span>
                  </div>
                  <div class="insight-foot">
                    <span>{{ insightsSeries[0]?.label }}</span>
                    <span v-if="insightsPeakIndex >= 0" class="hist-peak-tag">峰值 {{ insightsMax }} 条 · {{ insightsSeries[insightsPeakIndex]?.label }}</span>
                    <span>{{ insightsSeries[insightsSeries.length - 1]?.label }}</span>
                  </div>
                </div>

                <!-- 攻击链 -->
                <div v-if="insights?.attack_chains.length" class="insight-block">
                  <div class="insight-head">
                    <h3>攻击链（ATT&CK 风格）</h3>
                    <span class="insight-note">按来源 IP 串起可疑行为的前因后果，阶段按战术排序 · 链按风险从高到低排列</span>
                  </div>
                  <article v-for="chain in insights.attack_chains" :key="`${chain.kind}-${chain.key}`" class="chain">
                    <header class="chain-head">
                      <span class="badge badge-risk" :class="chain.risk_level">{{ riskText(chain.risk_level) }}</span>
                      <strong class="chain-key">{{ chainKindText(chain.kind) }} · {{ chain.key }}</strong>
                      <span class="chain-meta">{{ chain.stages.length }} 个阶段</span>
                    </header>
                    <div class="chain-flow">
                      <template v-for="(stage, index) in chain.stages" :key="`${chain.key}-${index}-${stage.event_type}`">
                        <div class="chain-stage" :class="`risk-${stage.risk_level}`">
                          <span class="stage-tactic">{{ stage.tactic }}</span>
                          <strong>{{ stage.name }}</strong>
                          <small>{{ stage.technique }}<template v-if="stage.first_seen"> · {{ stage.first_seen }}</template></small>
                        </div>
                        <span v-if="index < chain.stages.length - 1" class="chain-arrow" aria-hidden="true">→</span>
                      </template>
                    </div>
                  </article>
                  <button v-if="chainsTruncated" class="events-more" @click="loadMoreChains">
                    加载更多攻击链（已展示 {{ insights?.attack_chains.length || 0 }} / {{ chainsTotal }} 条）
                  </button>
                </div>

                <p v-if="!insightsSeries.length && !insights?.attack_chains.length" class="muted">
                  暂无足够的时序或事件信息用于生成洞察。
                </p>
              </div>
            </section>

            <!-- 03 AI 研判：语义分析、证据溯源与工具轨迹 -->
            <section v-if="activeView === 'ai'" id="module-ai" class="module tier-ai">
              <header class="module-head">
                <span class="module-index">{{ moduleIndex("ai") }}</span>
                <div class="module-title">
                  <h2>AI 研判</h2>
                  <p class="module-sub">
                    {{ result.structured_verdict ? "结构化研判 ✓ · " : "" }}
                    {{ result.ai_behaviors.length }} 条识别行为 ·
                    {{ aiToolCalls.length }} 次工具调用 ·
                    {{ result.ai_unsupported_claims.length ? `${result.ai_unsupported_claims.length} 条无证据声明` : "溯源通过" }}
                  </p>
                </div>
                <div class="module-tools">
                  <span class="module-tier">{{ moduleTierLabel("ai") }}</span>
                  <button class="btn btn-ghost btn-sm" :disabled="aiLoading" @click="analyzeWithAi">
                    {{ result.ai_status === "completed" ? "重新研判" : "开始研判" }}
                  </button>
                  <button
                    v-if="result.ai_status !== 'not_analyzed'"
                    class="btn btn-soft btn-sm"
                    @click="openAiLedger"
                  >
                    查看审查台账
                  </button>
                  <button class="module-toggle" @click="toggleModule('ai')">
                    {{ isCollapsed("ai") ? "展开" : "收起" }}
                  </button>
                </div>
              </header>

              <div v-show="!isCollapsed('ai')" class="module-body">
                <div class="ai-stack">
                  <!-- AI 强制结构化研判结论（标准化 → 富化 → AI 研判） -->
                  <div v-if="result.structured_verdict" class="structured-verdict">
                    <div class="structured-head">
                      <h3>AI 结构化研判</h3>
                      <span class="badge badge-risk" :class="result.structured_verdict.risk_level">{{ riskText(result.structured_verdict.risk_level) }}</span>
                    </div>
                    <dl class="structured-grid">
                      <template v-for="row in structuredRows" :key="row.label">
                        <dt>{{ row.label }}</dt>
                        <dd :class="row.cls">
                          <span v-if="row.kind === 'list'" class="sv-chip-list">
                            <span v-for="item in row.list" :key="item" class="sv-chip">{{ item }}</span>
                            <span v-if="!row.list.length" class="muted">—</span>
                          </span>
                          <span v-else-if="row.kind === 'success'" class="sv-success" :class="{ positive: row.positive }">{{ row.text }}</span>
                          <span v-else-if="row.kind === 'risk'"><span class="kind-tag" :class="`tone-${row.tone}`">{{ row.text }}</span></span>
                          <span v-else>{{ row.text }}</span>
                        </dd>
                      </template>
                    </dl>
                  </div>

                  <div v-if="result.ai_behaviors.length" class="ai-result">
                    <h3>AI 识别行为</h3>
                    <article v-for="behavior in result.ai_behaviors" :key="`${behavior.type}-${behavior.name}`">
                      <strong>{{ behavior.name }} · {{ Math.round(behavior.confidence * 100) }}%</strong>
                      <p>{{ behavior.analysis }}</p>
                      <div v-if="behavior.evidence_ids.length" class="ai-evidence-links">
                        <span>引用证据：</span>
                        <button
                          v-for="evidenceId in behavior.evidence_ids"
                          :key="evidenceId"
                          class="evidence-link"
                          @click="focusEvidence(result.events.flatMap((event) => event.evidence_items).find((item) => item.id === evidenceId)?.record_id ?? null)"
                        >
                          {{ evidenceId }}
                        </button>
                      </div>
                    </article>
                  </div>

                  <div v-if="result.ai_unsupported_claims.length" class="claim-warn">
                    <strong>以下 AI 说法未在日志证据中找到对应记录</strong>
                    <ul>
                      <li v-for="claim in result.ai_unsupported_claims" :key="claim">{{ claim }}</li>
                    </ul>
                  </div>
                  <div v-else-if="result.ai_status === 'completed'" class="grounding-ok">
                    溯源校验通过：AI 结论中的 IP、账号与记录编号均能在日志证据中对上，未发现编造引用。
                  </div>

                  <div v-if="result.ai_tool_trace.length" class="ai-trace">
                    <h3>AI 赋能流水线（日志 → 标准化 → 富化 → 研判 → 溯源）</h3>
                    <div class="enrich-pipeline">
                      <template v-for="(stage, index) in enrichmentStages" :key="stage.tool">
                        <div class="enrich-stage">
                          <span class="enrich-stage-name">{{ stage.stage }}</span>
                          <code>{{ stage.tool }}</code>
                          <small>{{ stage.detail }}</small>
                        </div>
                        <span v-if="index < enrichmentStages.length - 1" class="chain-arrow" aria-hidden="true">→</span>
                      </template>
                    </div>
                    <details class="trace-details">
                      <summary>工具调用轨迹（{{ aiToolCalls.length }} 次）</summary>
                      <ol>
                        <li v-for="(call, index) in aiToolCalls" :key="`${call.tool}-${index}`">
                          <div class="trace-head">
                            <code>{{ call.tool }}</code>
                            <span class="trace-source">{{ call.source === "auto" ? "自动执行" : "模型调用" }}</span>
                            <span v-if="formatArguments(call.arguments)" class="trace-args">
                              {{ formatArguments(call.arguments) }}
                            </span>
                          </div>
                          <p>{{ call.summary }}</p>
                        </li>
                      </ol>
                      <p v-if="aiUsageText" class="trace-usage">本次研判用量：{{ aiUsageText }}</p>
                    </details>
                  </div>

                  <p v-if="!result.ai_behaviors.length && !aiToolCalls.length" class="muted">
                    本次研判未产出 AI 语义结论，可点击上方「{{ result.ai_status === "completed" ? "重新研判" : "开始研判" }}」重试。
                  </p>

                  <!-- 人工确认：AI 推断必须由人落笔才进结论，导出按此分层 -->
                  <div class="human-review">
                    <div class="review-head">
                      <h3>人工确认</h3>
                      <span class="review-state" :class="`state-${humanReview?.status ?? 'pending'}`">{{ reviewStatusText }}</span>
                    </div>
                    <p class="review-hint">
                      上方结构化研判与识别行为均为模型推断。此处记录人工判定，导出报告会按「原始事实 / 规则命中 / AI 推断 / 人工确认」分层，避免把推断当成事实。
                    </p>
                    <div class="review-options">
                      <label
                        v-for="option in REVIEW_OPTIONS"
                        :key="option.value"
                        class="review-option"
                        :class="{ active: reviewForm.status === option.value }"
                      >
                        <input v-model="reviewForm.status" type="radio" :value="option.value" />
                        <span>{{ option.label }}</span>
                        <small>{{ option.hint }}</small>
                      </label>
                    </div>
                    <div class="review-inputs">
                      <input v-model="reviewForm.reviewer" class="review-input" placeholder="确认人（必填）" />
                      <input v-model="reviewForm.note" class="review-input review-input-wide" placeholder="备注（可选）" />
                      <button class="btn btn-soft btn-sm" :disabled="reviewSaving" @click="submitHumanReview">
                        {{ reviewSaving ? "保存中…" : "记录确认" }}
                      </button>
                    </div>
                    <div v-if="humanReview?.history.length" class="review-history">
                      <p class="review-history-title">确认历史（新→旧）</p>
                      <ol>
                        <li v-for="entry in [...(humanReview?.history ?? [])].reverse()" :key="entry.id">
                          <span class="review-state" :class="`state-${entry.status}`">{{ REVIEW_STATUS_LABELS[entry.status] }}</span>
                          <span class="review-who">{{ entry.reviewer }}</span>
                          <time>{{ entry.created_at }}</time>
                          <span v-if="entry.note" class="review-note-text">{{ entry.note }}</span>
                        </li>
                      </ol>
                    </div>
                  </div>
                </div>
              </div>
            </section>

            <!-- 04 日志模板 -->
            <section v-if="activeView === 'templates' && result.templates.length" id="module-templates" class="module tier-context">
              <header class="module-head">
                <span class="module-index">{{ moduleIndex("templates") }}</span>
                <div class="module-title">
                  <h2>日志模板</h2>
                  <p class="module-sub">
                    未匹配已知类型的日志已用模板挖掘提取固定结构；只出现一次的模板标记为罕见，优先查看
                  </p>
                </div>
                <div class="module-tools">
                  <span class="module-tier">{{ moduleTierLabel("templates") }}</span>
                  <button class="module-toggle" @click="toggleModule('templates')">
                    {{ isCollapsed("templates") ? "展开" : "收起" }}
                  </button>
                </div>
              </header>
              <div v-show="!isCollapsed('templates')" class="table-wrap">
                <table class="records-table compact">
                  <thead>
                    <tr>
                      <th>次数</th>
                      <th>占比</th>
                      <th>模板</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr v-for="(item, index) in result.templates" :key="`${index}-${item.template}`">
                      <td class="cell-nowrap tabular">{{ item.count }}</td>
                      <td class="cell-nowrap tabular">{{ Math.round(item.ratio * 100) }}%</td>
                      <td>
                        <span v-if="item.rare" class="badge medium" style="margin-right: 8px">罕见</span>
                        <span class="cell-mono">{{ item.template }}</span>
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </section>

            <!-- 进程树（仿 Zircolite Processes）：只连日志里真实存在的父子关系 -->
            <section v-if="activeView === 'processes'" id="module-processes" class="module tier-context">
              <header class="module-head">
                <span class="module-index">{{ moduleIndex("processes") }}</span>
                <div class="module-title">
                  <h2>进程树</h2>
                  <p class="module-sub">
                    {{ processTrees.length }} 个资产 ·
                    {{ processTrees.reduce((sum, tree) => sum + tree.total, 0) }} 个进程节点 ·
                    按日志中的 PID / 父 PID 连接，父进程不在本次日志中时标为根
                  </p>
                </div>
                <div class="module-tools">
                  <span class="module-tier">{{ moduleTierLabel("processes") }}</span>
                  <button class="module-toggle" @click="toggleModule('processes')">
                    {{ isCollapsed("processes") ? "展开" : "收起" }}
                  </button>
                </div>
              </header>

              <div v-show="!isCollapsed('processes')" class="module-body">
                <p v-if="!processTrees.length" class="muted">
                  本次日志没有可构建进程树的进程节点（需要 Sysmon EID 1 / Security 4688 这类进程创建记录）。
                </p>
                <template v-else>
                  <p v-if="processTrees.some((tree) => tree.total > PROCESS_AUTO_EXPAND_LIMIT)" class="muted">
                    节点较多的资产默认只展开根节点——点行首的三角逐层展开（避免一屏几百行）。
                  </p>
                  <ol class="proc-tree">
                    <li
                      v-for="row in processRows"
                      :key="row.node.key"
                      class="proc-row"
                      :class="`risk-${row.node.risk}`"
                      :style="{ paddingLeft: `${row.depth * 18}px` }"
                    >
                      <button
                        class="proc-toggle"
                        :class="{ 'is-hidden': !row.hasChildren }"
                        :title="row.hasChildren ? (isProcessExpanded(row.node) ? '收起子节点' : '展开子节点') : '没有子节点'"
                        @click="toggleProcessNode(row.node)"
                      >{{ isProcessExpanded(row.node) ? "▾" : "▸" }}</button>
                      <span class="badge badge-risk" :class="row.node.risk">{{ riskText(row.node.risk) }}</span>
                      <span class="proc-name">{{ processImageName(row.node.image) }}</span>
                      <span class="proc-pid">PID {{ row.node.pid }}<template v-if="row.node.ppid"> · 父 {{ row.node.ppid }}</template></span>
                      <span class="proc-kinds">
                        <span v-for="kind in row.node.kinds" :key="kind" class="proc-kind">{{ processKindText(kind) }}</span>
                      </span>
                      <span v-if="row.node.orphan" class="proc-orphan" title="该进程的父进程不在本次日志中，未猜测父节点">父进程不在日志中</span>
                      <span v-if="row.node.records.length" class="proc-evidence">
                        证据 {{ row.node.records.slice(0, 2).join("、") }}<template v-if="row.node.records.length > 2"> 等 {{ row.node.records.length }} 条</template>
                      </span>
                      <span class="proc-path" :title="row.node.image">{{ row.node.image }}</span>
                    </li>
                  </ol>
                </template>
              </div>
            </section>

            <!-- 05 实体关联 -->
            <section v-if="activeView === 'entities' && result.entities.length" id="module-entities" class="module tier-context">
              <header class="module-head">
                <span class="module-index">{{ moduleIndex("entities") }}</span>
                <div class="module-title">
                  <h2>实体关联</h2>
                  <p class="module-sub">
                    按来源 IP、目的 IP、账户串联；命中可疑事件或跨多份日志文件出现的实体会被列出
                  </p>
                </div>
                <div class="module-tools">
                  <span class="module-tier">{{ moduleTierLabel("entities") }}</span>
                  <button class="module-toggle" @click="toggleModule('entities')">
                    {{ isCollapsed("entities") ? "展开" : "收起" }}
                  </button>
                </div>
              </header>
              <div v-show="!isCollapsed('entities')" class="table-wrap">
                <table class="records-table compact">
                  <thead>
                    <tr>
                      <th>类型</th>
                      <th>实体</th>
                      <th>风险</th>
                      <th>关联事件</th>
                      <th>命中规则</th>
                      <th>首次 / 末次</th>
                      <th>调查</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr v-for="item in result.entities" :key="`${item.kind}-${item.value}`">
                      <td class="cell-nowrap">{{ entityKindText(item.kind) }}</td>
                      <td>
                        <div class="cell-mono">{{ item.value }}</div>
                        <small class="cell-note">{{ item.summary }}</small>
                      </td>
                      <td>
                        <span class="badge badge-risk" :class="item.risk_level">{{ riskText(item.risk_level) }}</span>
                      </td>
                      <td class="cell-nowrap tabular">{{ item.event_count }}</td>
                      <td>
                        <div v-for="rule in item.rule_ids" :key="rule" class="rule-code">{{ rule }}</div>
                        <span v-if="!item.rule_ids.length" class="muted">-</span>
                      </td>
                      <td class="cell-nowrap">
                        {{ item.first_seen ?? "-" }}
                        <br />
                        {{ item.last_seen ?? "-" }}
                      </td>
                      <td class="cell-nowrap">
                        <button
                          class="btn btn-ghost btn-sm"
                          @click="openEntityInvestigation(item.kind, item.value)"
                        >
                          查看记录
                        </button>
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </section>

            <!-- 06 统一时间线 -->
            <section v-if="activeView === 'timeline' && result.timeline.length" id="module-timeline" class="module tier-context">
              <header class="module-head">
                <span class="module-index">{{ moduleIndex("timeline") }}</span>
                <div class="module-title">
                  <h2>统一时间线</h2>
                  <p class="module-sub">可疑事件与其日志证据按时间合并，可据此还原行为发生的先后顺序</p>
                </div>
                <div class="module-tools">
                  <span class="module-tier">{{ moduleTierLabel("timeline") }}</span>
                  <button class="module-toggle" @click="toggleModule('timeline')">
                    {{ isCollapsed("timeline") ? "展开" : "收起" }}
                  </button>
                </div>
              </header>
              <ol v-show="!isCollapsed('timeline')" class="timeline-list">
                <li
                  v-for="(item, index) in result.timeline"
                  :key="`${item.timestamp_iso}-${index}`"
                  class="timeline-item"
                  :class="`is-${item.kind === 'event' ? item.risk_level : 'neutral'}`"
                >
                  <span class="timeline-time tabular">{{ item.timestamp ?? "-" }}</span>
                  <span class="timeline-dot"></span>
                  <div class="timeline-body">
                    <div class="timeline-head">
                      <span class="badge badge-kind" :class="item.kind === 'event' ? item.risk_level : 'neutral'">
                        {{ item.kind === "event" ? "事件" : "证据" }}
                      </span>
                      <strong>{{ item.title }}</strong>
                    </div>
                    <p class="timeline-meta">
                      <span v-if="item.rule_id">规则 <code>{{ item.rule_id }}</code></span>
                      <span v-if="item.source_ip" class="cell-mono">{{ item.source_ip }}</span>
                      <span v-if="item.username" class="cell-mono">{{ item.username }}</span>
                      <span v-if="item.source_file">{{ item.source_file }}</span>
                    </p>
                    <p v-if="item.kind === 'event' && item.detail" class="timeline-detail">{{ item.detail }}</p>
                  </div>
                </li>
              </ol>
            </section>

            <!-- 07 终端证据链 -->
            <section v-if="activeView === 'terminal-chains' && result.terminal_chains.length" id="module-terminal-chains" class="module tier-context">
              <header class="module-head">
                <span class="module-index">{{ moduleIndex("terminal-chains") }}</span>
                <div class="module-title">
                  <h2>终端证据链</h2>
                  <p class="module-sub">按目标资产和时间关联进程、文件、注册表、DNS 与外联记录；关联结果不等同于攻击结论</p>
                </div>
                <div class="module-tools">
                  <span class="module-tier">{{ moduleTierLabel("terminal-chains") }}</span>
                  <button class="module-toggle" @click="toggleModule('terminal-chains')">
                    {{ isCollapsed('terminal-chains') ? "展开" : "收起" }}
                  </button>
                </div>
              </header>
              <div v-show="!isCollapsed('terminal-chains')" class="terminal-chain-list">
                <article v-for="chain in result.terminal_chains" :key="chain.chain_id" class="terminal-chain">
                  <div class="terminal-chain-head">
                    <div>
                      <strong>{{ chain.target_asset || "未标识目标资产" }}</strong>
                      <p class="module-sub">{{ chain.summary }}</p>
                    </div>
                    <div class="terminal-chain-meta">
                      <span class="badge badge-risk" :class="chain.risk_level">{{ riskText(chain.risk_level) }}</span>
                      <span class="cell-note tabular">{{ chain.record_count }} 条证据</span>
                      <span class="cell-note">{{ chain.first_seen || "-" }} 至 {{ chain.last_seen || "-" }}</span>
                    </div>
                  </div>
                  <ol class="timeline-list terminal-chain-timeline">
                    <li v-for="node in chain.nodes" :key="`${chain.chain_id}-${node.evidence_id}-${node.kind}-${node.timestamp_iso}`" class="timeline-item">
                      <span class="timeline-time tabular">{{ node.timestamp || "-" }}</span>
                      <span class="timeline-dot"></span>
                      <div class="timeline-body">
                        <div class="timeline-head">
                          <span class="badge badge-kind neutral">{{ terminalNodeText(node.kind) }}</span>
                          <strong>{{ node.title }}</strong>
                        </div>
                        <p class="timeline-meta">
                          <button v-if="node.record_id" class="evidence-link" @click="focusEvidence(node.record_id)">
                            {{ node.evidence_id || node.record_id }}
                          </button>
                          <span v-if="node.source_file">{{ node.source_file }}</span>
                          <span v-if="node.event_id">事件 {{ node.event_id }}</span>
                        </p>
                      </div>
                    </li>
                  </ol>
                  <details v-if="chain.relationships?.length" class="chain-relations">
                    <summary>查看证据关联（{{ chain.relationships.length }} 条）</summary>
                    <div
                      v-for="relation in chain.relationships"
                      :key="`${relation.from_record_id}-${relation.to_record_id}-${relation.kind}`"
                      class="chain-relation"
                    >
                      <span class="badge neutral">{{ relation.confidence }}</span>
                      <button
                        v-if="relation.from_record_id"
                        class="evidence-link"
                        @click="focusEvidence(relation.from_record_id)"
                      >
                        {{ relation.from_evidence_id || relation.from_record_id }}
                      </button>
                      <span>→</span>
                      <button
                        v-if="relation.to_record_id"
                        class="evidence-link"
                        @click="focusEvidence(relation.to_record_id)"
                      >
                        {{ relation.to_evidence_id || relation.to_record_id }}
                      </button>
                      <span class="cell-note">{{ relation.basis }}</span>
                    </div>
                  </details>
                </article>
              </div>
            </section>

            <!-- 08 日志明细 -->
            <section v-if="activeView === 'records'" id="module-records" class="module tier-raw">
              <header class="module-head">
                <span class="module-index">{{ moduleIndex("records") }}</span>
                <div class="module-title">
                  <h2>日志明细</h2>
                  <p class="module-sub">按顶部「日志明细筛选」条件过滤，可导出为 CSV</p>
                </div>
                <div class="module-tools">
                  <span class="module-tier">{{ moduleTierLabel("records") }}</span>
                  <button class="module-toggle" @click="toggleModule('records')">
                    {{ isCollapsed("records") ? "展开" : "收起" }}
                  </button>
                </div>
              </header>
              <div v-show="!isCollapsed('records')" class="records-shell">
              <!-- 字段侧栏（仿 Zircolite Explore）：先看哪些字段可用，再一键加/排除筛选 -->
              <aside v-if="facets" class="facet-bar">
                <p class="facet-title">字段（{{ facets.fields.length }}）</p>
                <p class="facet-note">{{ facets.note }}</p>
                <div v-for="field in facets.fields" :key="field.name" class="facet-item">
                  <button class="facet-head" :class="{ 'is-empty': !field.present_records }" @click="toggleFacetField(field.name)">
                    <span class="facet-name">{{ field.label }}</span>
                    <span class="facet-coverage">{{ facetCoverageText(field) }}</span>
                    <span class="facet-caret">{{ expandedFacetFields.includes(field.name) ? "▾" : "▸" }}</span>
                  </button>
                  <div v-if="expandedFacetFields.includes(field.name)" class="facet-values">
                    <div v-for="value in field.values" :key="value.value" class="facet-value">
                      <span class="facet-value-text" :title="value.value">{{ value.value }}</span>
                      <span class="facet-value-count tabular">{{ value.count }}</span>
                      <button class="facet-op" title="只看这个取值" @click="applyFacetValue(field, value.value, false)">+</button>
                      <button class="facet-op" title="排除这个取值" @click="applyFacetValue(field, value.value, true)">−</button>
                    </div>
                    <p v-if="!field.values.length" class="muted">该字段没有取值。</p>
                    <p v-else-if="field.values_total > field.values.length" class="facet-more">
                      已展示 Top {{ field.values.length }} / 共 {{ field.values_total }} 个取值
                    </p>
                  </div>
                </div>
              </aside>
              <div class="records-main">
              <div class="table-wrap">
                <table class="records-table">
                  <thead>
                    <tr>
                      <th>记录 ID</th>
                      <th>证据编号</th>
                      <th>时间</th>
                      <th>来源文件</th>
                      <th>源 IP</th>
                      <th>目的 IP</th>
                      <th>路径</th>
                      <th>动作</th>
                      <th>状态</th>
                      <th>终端字段</th>
                      <th>原始日志</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr v-if="recordLoading">
                      <td colspan="11" class="muted">加载中…</td>
                    </tr>
                    <tr v-else-if="!records?.items.length">
                      <td colspan="11" class="muted">没有匹配的日志记录。</td>
                    </tr>
                    <tr
                      v-for="item in records?.items ?? []"
                      :id="`record-row-${item.record_id}`"
                      :key="item.record_id ?? `${item.timestamp_iso}-${item.raw}`"
                      :class="{ 'record-highlight': item.record_id === selectedRecordId }"
                    >
                      <td class="cell-nowrap tabular">{{ item.record_id ?? "-" }}</td>
                      <td class="cell-nowrap tabular">{{ item.evidence_id ?? "-" }}</td>
                      <td class="cell-nowrap tabular">{{ item.timestamp ?? "-" }}</td>
                      <td>{{ item.source_file ?? "-" }}</td>
                      <td class="cell-mono cell-ip">{{ item.source_ip ?? "-" }}</td>
                      <td class="cell-mono cell-ip">{{ item.destination_ip ?? "-" }}</td>
                      <td class="cell-truncate" :title="item.url ?? ''">{{ item.url ?? "-" }}</td>
                      <td>{{ item.action ?? "-" }}</td>
                      <td>{{ item.status ?? item.result ?? "-" }}</td>
                      <td class="record-fields">
                         <div v-if="item.process_image"><span>进程：</span>{{ item.process_image }}</div>
                         <div v-if="item.command_line"><span>命令：</span>{{ item.command_line }}</div>
                         <div v-if="item.process_id"><span>PID：</span>{{ item.process_id }}</div>
                         <div v-if="item.parent_process_id"><span>父 PID：</span>{{ item.parent_process_id }}</div>
                         <div v-if="item.parent_image"><span>父进程：</span>{{ item.parent_image }}</div>
                         <div v-if="item.target_filename"><span>文件：</span>{{ item.target_filename }}</div>
                         <div v-if="item.service_name"><span>服务：</span>{{ item.service_name }}<template v-if="item.service_state">（{{ item.service_state }}）</template></div>
                         <div v-if="item.registry_key"><span>注册表：</span>{{ item.registry_key }}</div>
                         <div v-if="item.query_name"><span>DNS：</span>{{ item.query_name }}</div>
                         <div v-if="item.query_results"><span>解析：</span>{{ item.query_results }}</div>
                        <div v-if="item.target_asset"><span>主机：</span>{{ item.target_asset }}</div>
                        <div v-if="item.destination_port"><span>端口：</span>{{ item.destination_port }}<span v-if="item.protocol"> / {{ item.protocol }}</span></div>
                        <div v-if="item.event_id"><span>事件：</span>{{ item.event_id }}</div>
                        <div v-if="item.whitelisted_by"><span>白名单：</span>{{ item.whitelisted_by }}（本条已跳过判定）</div>
                         <span v-if="!item.process_image && !item.command_line && !item.process_id && !item.parent_process_id && !item.parent_image && !item.target_filename && !item.service_name && !item.registry_key && !item.query_name && !item.query_results && !item.target_asset && !item.destination_port && !item.event_id">-</span>
                      </td>
                      <td class="cell-raw"><span>{{ item.raw ?? "-" }}</span></td>
                    </tr>
                  </tbody>
                </table>
              </div>
              <div class="pagination">
                <div class="page-size">
                  每页
                  <PickerSelect
                    v-model="recordPageSize"
                    name="record-page-size"
                    :options="recordPageSizeOptions"
                    aria-label="每页条数"
                    class="pager-select"
                  />
                  条
                </div>
                <span class="page-info">
                  第 {{ currentRecordPage }} / {{ Math.max(1, records?.total_pages ?? 0) }} 页 · 共 {{ records?.total ?? 0 }} 条
                </span>
                <div class="page-list">
                  <button class="page-btn" :disabled="currentRecordPage <= 1" @click="loadRecords(1)">首页</button>
                  <button class="page-btn" :disabled="currentRecordPage <= 1" @click="loadRecords(currentRecordPage - 1)">‹</button>
                  <template v-for="(page, index) in recordPageItems" :key="index">
                    <span v-if="page === 'gap'" class="page-gap">…</span>
                    <button v-else class="page-btn" :class="{ active: page === currentRecordPage }" @click="goToRecordPage(page)">{{ page }}</button>
                  </template>
                  <button class="page-btn" :disabled="currentRecordPage >= (records?.total_pages ?? 1)" @click="loadRecords(currentRecordPage + 1)">›</button>
                  <button class="page-btn" :disabled="currentRecordPage >= (records?.total_pages ?? 1)" @click="loadRecords(records?.total_pages ?? 1)">末页</button>
                </div>
              </div>
              </div>
              </div>
            </section>
            </div>
          </div>
          </template>
        </template>
      </main>
    </div>

    <!-- 上传日志弹窗 -->
    <div v-if="uploadOpen" class="overlay" @click.self="closeUpload">
      <section class="modal">
        <div class="modal-head">
          <div>
            <p class="eyebrow">Upload</p>
            <h2>上传日志文件</h2>
          </div>
          <button class="close-button" title="关闭" @click="closeUpload">×</button>
        </div>
        <div class="modal-body">
          <label
            class="dropzone"
            :class="{ 'is-active': dragActive }"
            @dragover.prevent="dragActive = true"
            @dragleave.prevent="dragActive = false"
            @drop.prevent="onDrop"
          >
            <input type="file" multiple accept=".log,.txt,.csv,.json,.xml,.evtx" @change="selectFile" />
            <span class="drop-icon">
              <svg width="18" height="18" viewBox="0 0 20 20" fill="none" aria-hidden="true">
                <path d="M10 13.5V3.8M6.6 7 10 3.6 13.4 7" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" />
                <path d="M3.5 13v2.2c0 .7.6 1.3 1.3 1.3h10.4c.7 0 1.3-.6 1.3-1.3V13" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" />
              </svg>
            </span>
            <strong>拖拽日志文件到此处，或点击选择文件</strong>
            <span>支持 SSH、Nginx/Apache、IIS、Windows 文本与 EVTX 本机日志、JSON/CSV、Firewall/WAF，可多选后统一关联分析</span>
          </label>

          <div v-if="demoLogs.length" class="demo-library">
            <div class="section-heading">
              <div>
                <strong>内置演示日志</strong>
                <span>无需准备文件，可先体验各类解析和检测</span>
              </div>
              <button class="btn btn-ghost btn-sm" :disabled="loading || !selectedDemoLogs.length" @click="analyzeDemoLogs">
                体验所选日志（{{ selectedDemoLogs.length }}）
              </button>
            </div>
            <div class="demo-list">
              <label v-for="item in demoLogs" :key="item.path" class="demo-item">
                <input
                  type="checkbox"
                  :checked="selectedDemoLogs.includes(item.path)"
                  @change="toggleDemoLog(item.path)"
                />
                <span class="demo-item-copy">
                  <strong>{{ item.name }}</strong>
                  <span>{{ item.description }}</span>
                </span>
              </label>
            </div>
          </div>

          <div v-if="files.length" class="file-chips">
            <div v-for="(file, index) in files" :key="`${file.name}-${index}`" class="file-chip">
              <span class="name">{{ file.name }}</span>
              <span class="size">{{ formatSize(file.size) }}</span>
              <button class="btn btn-danger btn-sm" @click="removeFile(index)">移除</button>
            </div>
          </div>
        </div>
        <div class="modal-foot">
          <button class="btn btn-ghost" @click="closeUpload">取消</button>
          <button class="btn" :disabled="!files.length || loading" @click="upload">
            <span v-if="loading" class="spinner"></span>
            {{ loading ? "分析中..." : files.length ? `开始分析（${files.length}）` : "开始分析" }}
          </button>
        </div>
      </section>
    </div>

    <!-- AI 审查台账 -->
    <div v-if="ledgerOpen" class="overlay" @click.self="ledgerOpen = false">
      <section class="modal ledger-modal">
        <div class="modal-head">
          <div>
            <p class="eyebrow">AI Ledger</p>
            <h2>AI 审查台账</h2>
          </div>
          <button class="close-button" title="关闭" @click="ledgerOpen = false">×</button>
        </div>
        <div v-if="ledgerLoading" class="modal-body empty-state">
          <span class="spinner spinner-dark"></span>
          <span>正在读取审查台账...</span>
        </div>
        <div v-else-if="aiLedger" class="modal-body">
          <div class="ledger-summary">
            <div><span>状态</span><strong>{{ aiLedger.status === "completed" ? "已完成" : "不可用" }}</strong></div>
            <div><span>模型</span><strong>{{ aiLedger.provider || "—" }} / {{ aiLedger.model || "—" }}</strong></div>
            <div><span>耗时</span><strong>{{ aiLedger.duration_ms.toLocaleString() }} ms</strong></div>
            <div><span>引用证据</span><strong>{{ aiLedger.evidence_ids.length }} 条</strong></div>
          </div>
          <div class="ledger-block">
            <h3>AI 为什么这样判断</h3>
            <p>{{ aiLedger.summary || "没有保存研判摘要。" }}</p>
          </div>
          <div class="ledger-block">
            <h3>引用的证据</h3>
            <div v-if="aiLedger.evidence_ids.length" class="sv-chip-list">
              <button
                v-for="evidenceId in aiLedger.evidence_ids"
                :key="evidenceId"
                class="evidence-link"
                @click="ledgerOpen = false; focusEvidence(result?.events.flatMap((event) => event.evidence_items).find((item) => item.id === evidenceId)?.record_id ?? null)"
              >
                {{ evidenceId }}
              </button>
            </div>
            <p v-else class="muted">本次台账没有记录证据编号。</p>
          </div>
          <div v-if="aiLedger.unsupported_claims.length" class="claim-warn ledger-block">
            <h3>未找到证据支撑的说法</h3>
            <ul>
              <li v-for="claim in aiLedger.unsupported_claims" :key="claim">{{ claim }}</li>
            </ul>
          </div>
          <div class="ledger-block">
            <h3>工具调用记录（{{ aiLedger.tool_trace.length }} 次）</h3>
            <ol v-if="aiLedger.tool_trace.length" class="ledger-trace">
              <li v-for="(call, index) in aiLedger.tool_trace" :key="`${call.tool}-${index}`">
                <div class="trace-head">
                  <code>{{ call.tool }}</code>
                  <span class="trace-source">{{ call.source === "auto" ? "自动执行" : "模型调用" }}</span>
                </div>
                <p>{{ call.summary }}</p>
              </li>
            </ol>
            <p v-else class="muted">没有工具调用记录。</p>
          </div>
        </div>
        <div v-if="aiLedger" class="modal-foot">
          <button class="btn btn-ghost" @click="exportAiLedger('json')">导出 JSON</button>
          <button class="btn btn-ghost" @click="exportAiLedger('csv')">导出 CSV</button>
          <button class="btn btn-soft" @click="exportAiLedger('html')">导出 HTML</button>
        </div>
      </section>
    </div>

    <!-- 实体调查：从「实体关联」表进入，看该实体的原始记录、关联事件与时间线 -->
    <div v-if="entityOpen" class="overlay" @click.self="entityOpen = false">
      <section class="modal entity-modal">
        <div class="modal-head">
          <div>
            <p class="eyebrow">Entity Investigation</p>
            <h2>实体调查 · {{ entityDetail?.value ?? "读取中" }}</h2>
          </div>
          <button class="close-button" title="关闭" @click="entityOpen = false">×</button>
        </div>

        <div v-if="entityLoading && !entityDetail" class="modal-body empty-state">
          <span class="spinner spinner-dark"></span>
          <span>正在读取关联记录...</span>
        </div>
        <div v-else-if="entityError" class="modal-body empty-state">
          <p class="muted">{{ entityError }}</p>
        </div>
        <div v-else-if="entityDetail" class="modal-body">
          <div class="ledger-summary">
            <div><span>实体类型</span><strong>{{ entityKindText(entityDetail.kind) }}</strong></div>
            <div><span>原始记录</span><strong>{{ entityDetail.records.total }} 条</strong></div>
            <div><span>关联事件</span><strong>{{ entityDetail.events_total }} 条</strong></div>
            <div><span>时间线条目</span><strong>{{ entityDetail.timeline_total }} 条</strong></div>
          </div>
          <p class="entity-note">
            实体值按精确匹配，不做模糊包含：这里的条数就是该实体自己的行为条数，不会混入相似值（查 10.0.0.8 不会带出 10.0.0.80）。
          </p>

          <div class="ledger-block">
            <h3>
              关联事件
              <small v-if="entityDetail.events_total > entityDetail.events.length">
                已展示 {{ entityDetail.events.length }} / 共 {{ entityDetail.events_total }} 条，按风险从高到低
              </small>
            </h3>
            <ul v-if="entityDetail.events.length" class="entity-events">
              <li v-for="event in entityDetail.events" :key="event.id">
                <span class="badge badge-risk" :class="event.risk_level">{{ riskText(event.risk_level) }}</span>
                <strong>{{ event.name }}</strong>
                <code v-if="event.rule_id">{{ event.rule_id }}</code>
                <span class="entity-count">×{{ event.count }}</span>
                <p>{{ event.summary }}</p>
              </li>
            </ul>
            <p v-else class="muted">该实体没有命中任何规则，因此没有关联事件。</p>
          </div>

          <div class="ledger-block">
            <h3>
              时间线
              <small v-if="entityDetail.timeline_total > entityDetail.timeline.length">
                已展示 {{ entityDetail.timeline.length }} / 共 {{ entityDetail.timeline_total }} 条
              </small>
            </h3>
            <ol v-if="entityDetail.timeline.length" class="entity-timeline">
              <li v-for="(entry, index) in entityDetail.timeline" :key="`${entry.record_id}-${index}`">
                <time>{{ entry.timestamp ?? entry.timestamp_iso ?? "时间未知" }}</time>
                <span class="kind-tag">{{ entry.kind === "event" ? "事件" : "证据" }}</span>
                <span class="entity-timeline-title">{{ entry.title }}</span>
              </li>
            </ol>
            <p v-else class="muted">
              没有可展示的时间线。时间线由事件与事件证据构成，该实体未命中规则时为空。
            </p>
          </div>

          <div class="ledger-block">
            <h3>
              原始记录
              <small>第 {{ entityDetail.records.page }} / {{ entityDetail.records.total_pages }} 页</small>
            </h3>
            <div v-if="entityDetail.records.items.length" class="table-wrap">
              <table class="records-table compact">
                <thead>
                  <tr>
                    <th>时间</th>
                    <th>来源 IP</th>
                    <th>账号</th>
                    <th>结果</th>
                    <th>原始内容</th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="(record, index) in entityDetail.records.items" :key="record.record_id ?? index">
                    <td class="cell-nowrap">{{ record.timestamp ?? "-" }}</td>
                    <td class="cell-mono">{{ record.source_ip ?? "-" }}</td>
                    <td class="cell-mono">{{ record.username ?? "-" }}</td>
                    <td class="cell-nowrap">{{ record.result ?? record.status ?? record.action ?? "-" }}</td>
                    <td class="cell-raw"><span>{{ record.raw ?? "-" }}</span></td>
                  </tr>
                </tbody>
              </table>
            </div>
            <p v-else class="muted">没有匹配到原始记录。</p>
          </div>
        </div>

        <div v-if="entityDetail && entityDetail.records.total_pages > 1" class="modal-foot">
          <button
            class="btn btn-ghost"
            :disabled="entityDetail.records.page <= 1 || entityLoading"
            @click="openEntityInvestigation(entityDetail.kind, entityDetail.value, entityDetail.records.page - 1)"
          >
            上一页
          </button>
          <span class="entity-page">第 {{ entityDetail.records.page }} / {{ entityDetail.records.total_pages }} 页</span>
          <button
            class="btn btn-ghost"
            :disabled="entityDetail.records.page >= entityDetail.records.total_pages || entityLoading"
            @click="openEntityInvestigation(entityDetail.kind, entityDetail.value, entityDetail.records.page + 1)"
          >
            下一页
          </button>
        </div>
      </section>
    </div>

    <!-- 规则试运行 -->
    <div v-if="previewOpen" class="overlay" @click.self="previewOpen = false">
      <section class="modal preview-modal">
        <div class="modal-head">
          <div>
            <p class="eyebrow">Rule Preview</p>
            <h2>规则试运行</h2>
          </div>
          <button class="close-button" title="关闭" @click="previewOpen = false">×</button>
        </div>
        <div class="modal-body">
          <label class="field">
            <span>规则 YAML</span>
            <textarea
              v-model="previewForm.yaml_text"
              class="preview-textarea preview-rule-input"
              placeholder="粘贴一条规则 YAML，例如：&#10;id: demo.rule&#10;name: 示例规则&#10;..."
              spellcheck="false"
            ></textarea>
          </label>
          <label class="field">
            <span>样例日志</span>
            <textarea
              v-model="previewForm.sample_log"
              class="preview-textarea"
              placeholder="粘贴要测试的日志内容，也可以使用右侧按钮读取本地文件。"
              spellcheck="false"
            ></textarea>
            <div class="preview-file-row">
              <label class="btn btn-ghost btn-sm">
                读取日志文件
                <input type="file" accept=".log,.txt,.csv,.json,.xml" hidden @change="importPreviewLog" />
              </label>
              <span class="muted">{{ previewForm.filename }}</span>
            </div>
          </label>
          <div v-if="previewError" class="alert alert-error">{{ previewError }}</div>
          <div v-if="previewReport" class="preview-result">
            <div class="preview-status" :class="previewReport.valid ? 'is-ok' : 'is-error'">
              <strong>{{ previewReport.valid ? "规则校验通过" : "规则校验未通过" }}</strong>
              <span>{{ previewReport.rollback_required ? "建议不要启用" : "可以继续评估" }}</span>
            </div>
            <div class="ledger-summary">
              <div><span>规则</span><strong>{{ previewReport.rule_ids.length }} 条</strong></div>
              <div><span>命中事件</span><strong>{{ previewReport.event_count }}</strong></div>
              <div><span>覆盖记录</span><strong>{{ previewReport.covered_records }}</strong></div>
              <div><span>误报 / 漏报</span><strong>{{ previewReport.false_positive }} / {{ previewReport.false_negative }}</strong></div>
            </div>
            <ul v-if="previewReport.errors.length" class="preview-errors">
              <li v-for="item in previewReport.errors" :key="item">{{ item }}</li>
            </ul>
            <div v-if="previewReport.events.length" class="preview-events">
              <h3>命中事件</h3>
              <article v-for="event in previewReport.events" :key="event.id" class="preview-event">
                <strong>{{ event.name }}</strong>
                <span>{{ event.summary }}</span>
              </article>
            </div>
          </div>
        </div>
        <div class="modal-foot">
          <button class="btn btn-ghost" @click="previewOpen = false">关闭</button>
          <button class="btn" :disabled="previewLoading || !previewForm.yaml_text.trim()" @click="runRulePreview">
            <span v-if="previewLoading" class="spinner"></span>
            {{ previewLoading ? "试运行中..." : "开始试运行" }}
          </button>
        </div>
      </section>
    </div>

    <!-- AI 研判进度浮层 -->
    <div v-if="aiLoading" class="overlay ai-progress-overlay" aria-live="polite" aria-busy="true">
      <section class="ai-progress-card">
        <div class="ai-progress-head">
          <span class="spinner spinner-dark"></span>
          <div>
            <h2>AI 研判中</h2>
            <p>{{ AI_PROGRESS_STEPS[aiProgressActive]?.desc ?? "正在处理..." }}</p>
          </div>
        </div>

        <div class="ai-progress-bar" role="progressbar" aria-label="AI 研判进度" :aria-valuenow="aiProgressPercent" aria-valuemin="0" aria-valuemax="100">
          <div class="progress-track">
            <div
              class="progress-fill"
              :class="{ running: aiLoading && aiProgressPercent < 100, complete: aiProgressPercent >= 100 }"
              :style="{ width: `${Math.min(100, Math.max(4, aiProgressPercent))}%` }"
            ></div>
          </div>
          <span class="progress-text">{{ aiProgressPercent }}%</span>
        </div>

        <div v-if="aiPartialText" class="ai-partial">
          <p class="ai-partial-label">模型实时输出（仅展示，最终结论以结构化校验后为准）</p>
          <pre class="ai-partial-text">{{ aiPartialText }}</pre>
        </div>

        <ol class="ai-progress-steps">
          <li
            v-for="(step, index) in AI_PROGRESS_STEPS"
            :key="step.label"
            class="ai-progress-step"
            :class="{ done: index < aiProgressActive, active: index === aiProgressActive }"
          >
            <span class="step-dot">
              <svg v-if="index < aiProgressActive" width="12" height="12" viewBox="0 0 12 12" fill="none" aria-hidden="true">
                <path d="m2.5 6 2 2 4-4.5" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" />
              </svg>
              <span v-else class="step-number">{{ index + 1 }}</span>
            </span>
            <span class="step-label">{{ step.label }}</span>
          </li>
        </ol>

        <p class="ai-progress-hint">分析过程中请勿关闭页面或切换任务</p>
      </section>
    </div>

    <!-- AI 配置弹窗 -->
    <div v-if="whitelistOpen" class="overlay" @click.self="whitelistOpen = false">
      <section class="modal">
        <div class="modal-head">
          <div>
            <p class="eyebrow">Whitelist</p>
            <h2>用户白名单</h2>
          </div>
          <button class="close-button" title="关闭" @click="whitelistOpen = false">×</button>
        </div>
        <div class="modal-body">
          <p class="whitelist-hint">
            命中白名单的记录不再参与规则判定（因此不告警），但原始日志仍保留在明细中作为证据，
            覆盖度里单独计数为「命中白名单已跳过」。
          </p>
          <div class="field">
            <span>新增条目</span>
            <div class="whitelist-form">
              <select v-model="whitelistForm.kind">
                <option v-for="(label, kind) in whitelistOverview.kinds" :key="kind" :value="kind">
                  {{ label }}
                </option>
              </select>
              <input v-model="whitelistForm.value" placeholder="如 192.168.1.0/24、/health、kube-probe" />
              <input v-model="whitelistForm.note" placeholder="备注（可选）" />
              <button class="whitelist-add" @click="addWhitelistEntry">添加</button>
            </div>
            <p v-if="whitelistError" class="whitelist-error">{{ whitelistError }}</p>
          </div>
          <div class="field">
            <span>生效条目（{{ whitelistOverview.entries.length }}）</span>
            <p v-if="!whitelistOverview.entries.length" class="whitelist-empty">暂无白名单条目</p>
            <div v-for="entry in whitelistOverview.entries" :key="entry.id" class="whitelist-row">
              <span class="whitelist-kind">{{ whitelistOverview.kinds[entry.kind] ?? entry.kind }}</span>
              <code class="whitelist-value">{{ entry.value }}</code>
              <span class="whitelist-note">{{ entry.note }}</span>
              <button class="whitelist-action" @click="toggleWhitelistEntry(entry.id, !entry.enabled)">
                {{ entry.enabled ? "停用" : "启用" }}
              </button>
              <button class="whitelist-action danger" @click="removeWhitelistEntry(entry.id)">删除</button>
            </div>
          </div>
          <div class="field">
            <span>变更历史（最近 {{ whitelistOverview.changes.length }} 条）</span>
            <p v-if="!whitelistOverview.changes.length" class="whitelist-empty">暂无变更记录</p>
            <div v-for="(change, index) in whitelistOverview.changes" :key="index" class="whitelist-change">
              <span class="whitelist-time">{{ change.created_at.replace("T", " ").slice(0, 19) }}</span>
              <span class="whitelist-action-name">{{ change.action }}</span>
              <code>{{ change.kind }}={{ change.value }}</code>
            </div>
          </div>
        </div>
      </section>
    </div>

    <div v-if="configOpen" class="overlay" @click.self="configOpen = false; closePickers()">
      <section class="modal">
        <div class="modal-head">
          <div>
            <p class="eyebrow">Provider</p>
            <h2>AI 配置</h2>
          </div>
          <button class="close-button" title="关闭" @click="configOpen = false">×</button>
        </div>
        <div class="modal-body">
          <div class="field">
            <span>Provider</span>
            <div class="picker" :class="{ open: picker === 'provider' }">
              <button type="button" class="picker-trigger" @click="togglePicker('provider')">
                <span
                  v-if="currentProviderOption"
                  class="picker-avatar"
                  :class="`tone-${currentProviderOption.tone}`"
                >
                  {{ currentProviderOption.initial }}
                </span>
                <span class="picker-value">{{ currentProviderOption?.label ?? configForm.provider }}</span>
                <span class="picker-code">{{ configForm.provider }}</span>
                <svg class="picker-chevron" width="14" height="14" viewBox="0 0 14 14" fill="none" aria-hidden="true">
                  <path d="M3.5 5.5 7 9l3.5-3.5" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" />
                </svg>
              </button>
              <div v-if="picker === 'provider'" class="picker-panel">
                <div class="picker-search">
                  <svg width="14" height="14" viewBox="0 0 14 14" fill="none" aria-hidden="true">
                    <circle cx="6.2" cy="6.2" r="4.2" stroke="currentColor" stroke-width="1.5" />
                    <path d="m9.6 9.6 2.4 2.4" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" />
                  </svg>
                  <input v-model="providerQuery" type="search" placeholder="搜索 Provider 或模型…" />
                </div>
                <div class="picker-list">
                  <button
                    v-for="item in filteredProviderOptions"
                    :key="item.value"
                    type="button"
                    class="picker-option"
                    :class="{ active: item.value === configForm.provider }"
                    @click="chooseProvider(item.value)"
                  >
                    <span class="picker-avatar" :class="`tone-${item.tone}`">{{ item.initial }}</span>
                    <span class="picker-option-body">
                      <strong>{{ item.label }}</strong>
                      <small>{{ item.hint }}</small>
                    </span>
                    <svg v-if="item.value === configForm.provider" class="picker-check" width="15" height="15" viewBox="0 0 15 15" fill="none" aria-hidden="true">
                      <path d="m3 7.8 3 3 6-6.4" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" />
                    </svg>
                  </button>
                  <p v-if="!filteredProviderOptions.length" class="picker-empty">没有匹配的 Provider</p>
                </div>
              </div>
            </div>
          </div>
          <label class="field">
            <span>Base URL</span>
            <input v-model="configForm.base_url" placeholder="选择 Provider 自动填充，也可自定义" />
          </label>
          <div class="field">
            <span>模型</span>
            <div v-if="!showModelInput" class="picker" :class="{ open: picker === 'model' }">
              <button type="button" class="picker-trigger" @click="togglePicker('model')">
                <span class="picker-value">{{ configForm.model || "选择模型" }}</span>
                <svg class="picker-chevron" width="14" height="14" viewBox="0 0 14 14" fill="none" aria-hidden="true">
                  <path d="M3.5 5.5 7 9l3.5-3.5" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" />
                </svg>
              </button>
              <div v-if="picker === 'model'" class="picker-panel">
                <div class="picker-list">
                  <button
                    v-for="model in selectedProviderPreset?.models ?? []"
                    :key="model"
                    type="button"
                    class="picker-option plain"
                    :class="{ active: model === configForm.model }"
                    @click="chooseModel(model)"
                  >
                    <span class="picker-option-body">
                      <strong>{{ model }}</strong>
                    </span>
                    <svg v-if="model === configForm.model" class="picker-check" width="15" height="15" viewBox="0 0 15 15" fill="none" aria-hidden="true">
                      <path d="m3 7.8 3 3 6-6.4" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" />
                    </svg>
                  </button>
                  <button type="button" class="picker-option plain" @click="chooseModel('__custom__')">
                    <span class="picker-option-body">
                      <strong>自定义模型…</strong>
                      <small>手动输入模型名称</small>
                    </span>
                  </button>
                </div>
              </div>
            </div>
            <input v-else v-model="configForm.model" placeholder="输入自定义模型名称" />
          </div>
          <label class="field">
            <span>API Key</span>
            <input v-model="configForm.api_key" type="password" placeholder="留空保持现有密钥" autocomplete="new-password" />
          </label>
          <label class="checkbox-label">
            <input v-model="configForm.clear_api_key" type="checkbox" />
            清除当前密钥
          </label>
          <p class="muted">密钥只保存在本机后端 `.env`，页面不会回显明文。</p>
          <div class="alert" :class="aiConnection ? (aiConnection.reachable ? 'alert-ok' : 'alert-error') : ''">
            <span>{{ aiConfig?.message ?? "正在检查配置..." }}</span>
            <span v-if="aiConnection"> · {{ aiConnection.message }}</span>
          </div>
        </div>
        <div class="modal-foot">
          <button class="btn btn-ghost" @click="refreshAiConfig">刷新配置</button>
          <button class="btn btn-ghost" :disabled="aiTesting || !aiConfig?.configured" @click="testAiConnection">
            {{ aiTesting ? "测试中..." : "测试连接" }}
          </button>
          <button class="btn" :disabled="configSaving" @click="saveConfig">{{ configSaving ? "保存中..." : "保存配置" }}</button>
        </div>
      </section>
    </div>
  </div>
</template>
