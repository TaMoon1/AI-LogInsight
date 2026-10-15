from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import shutil
import threading
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, File, HTTPException, Query, Response, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from . import runtime_paths
from .database import repository
from .models import (
    RISK_ORDER,
    AiConfigUpdate,
    AiLedger,
    AiToolCall,
    AiUsageHistory,
    AiUsagePoint,
    AttackCoverageReport,
    AnalysisResult,
    HumanReview,
    Insights,
    ReviewUpdate,
    RuleQualityReport,
    RulePreviewReport,
    RulePreviewRequest,
    SigmaImportReport,
    DemoAnalyzeRequest,
    LogRecordPage,
    EntityInvestigation,
    LogSummary,
    LogSummaryPage,
    ThreatIntelReport,
    AnalysisDashboard,
    DetectionsReport,
    AttackMatrix,
    SearchResult,
    LogFacets,
    UploadResponse,
    WhitelistCreateRequest,
    WhitelistEntryModel,
    WhitelistOverview,
    sort_events_by_risk,
)
from .services.ai import (
    check_ai_config,
    request_ai_judgement,
    save_ai_config,
    test_ai_connection,
)
from .services.analyzer import analyze_parsed_logs, assign_record_ids, collect_records
from .services.analytics import build_attack_chains, build_timeseries
from .services.ai_ledger import (
    ai_ledger_repository,
    build_ai_ledger,
    render_ledger_csv,
    render_ledger_html,
    render_ledger_json,
)
from .services.attack_coverage import evaluate_attack_coverage
from .services.attack_matrix import build_attack_matrix, build_navigator_layer
from .services.dashboard import build_dashboard
from .services.detections import build_detections
from .services.evtx import EvtxUnavailableError
from .services.facets import build_facets
from .services.memory_guard import check_upload_memory
from .services.parser import ParsedLog, parse_log, parse_upload
from .services.report import render_html_report, render_json_report
from .services.siem_export import SIEM_EXPORT_FORMATS
from .services.review import review_repository
from .services.rule_quality import evaluate
from .services.rule_governance import (
    parse_draft_rules,
    rule_governance_repository,
    score_preview,
)
from .services.rules_engine import build_rule, evaluate_rules_with_coverage
from .services.sigma_import import convert_uploaded
from .services.rules import get_rules
from .services.search import FIELD_ALIASES, search as search_records
from .services.threat_intel import enrich as enrich_threat_intel
from .services.whitelist import KIND_LABELS, WHITELIST_KINDS, whitelist_repository

def _positive_env_bytes(name: str, default: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default


MAX_UPLOAD_BYTES = _positive_env_bytes(
    "LOGINSIGHT_MAX_FILE_BYTES", 50 * 1024 * 1024
)
MAX_ANALYSIS_UPLOAD_BYTES = _positive_env_bytes(
    "LOGINSIGHT_MAX_ANALYSIS_BYTES", 200 * 1024 * 1024
)
MAX_UPLOAD_STORAGE_BYTES = _positive_env_bytes(
    "LOGINSIGHT_MAX_STORAGE_BYTES", 2 * 1024 * 1024 * 1024
)
DEMO_LOG_ROOT = runtime_paths.project_root() / "sample_logs"
UPLOAD_ROOT = Path(
    os.getenv("LOGINSIGHT_UPLOAD_ROOT") or str(runtime_paths.data_root() / "uploads")
)
DEMO_VISIBLE_FILES = {
    "ssh/auth.log",
    "iis/iis-access.log",
    "structured/auth-events-demo.csv",
    "firewall/firewall.log",
    "windows/security-rdp-export.xml",
    "generic/app.log",
    "database/mysql-general.log",
    "database/postgres.log",
    "database/mongodb.log",
    "database/mongodb-plain.log",
    "database/redis.log",
    "database/sqlserver.log",
    "database/oracle.log",
}
app = FastAPI(title="AI-LogInsight API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/rules")
def list_rules():
    return get_rules()


@app.get("/api/rules/quality", response_model=RuleQualityReport)
def rule_quality() -> RuleQualityReport:
    """在标注语料上评估规则的 TP / FP / FN，用于误报治理与回归把关。"""

    return evaluate()


@app.post("/api/rules/preview", response_model=RulePreviewReport)
def preview_rule(payload: RulePreviewRequest) -> RulePreviewReport:
    """校验规则草稿并可选试运行样本日志；不写入规则目录。"""

    try:
        drafts = parse_draft_rules(payload.yaml_text, payload.rule, payload.rules)
        draft_rules = [build_rule(item, source=str(item.get("source") or "preview")) for item in drafts]
    except Exception as exc:
        return RulePreviewReport(valid=False, errors=[str(exc)], rollback_required=False)

    events = []
    covered: set[str] = set()
    if payload.sample_log.strip():
        parsed = parse_log(payload.sample_log)
        records = assign_record_ids(collect_records([payload.filename], [parsed]))
        events, covered = evaluate_rules_with_coverage(records, draft_rules)
    return score_preview(
        {rule.id for rule in draft_rules},
        set(payload.expected_rule_ids),
        sort_events_by_risk(events),
        len(covered),
    )


@app.patch("/api/rules/{rule_id}/enabled")
def set_rule_enabled(rule_id: str, enabled: bool = Query(...)) -> dict[str, bool | str]:
    current = next((rule for rule in get_rules() if rule.id == rule_id), None)
    if current is None:
        raise HTTPException(status_code=404, detail="规则不存在")
    rule_governance_repository.set_enabled(rule_id, enabled, current.enabled)
    return {"rule_id": rule_id, "enabled": enabled}


@app.get("/api/rules/audit")
def rule_audit(limit: int = Query(100, ge=1, le=500)):
    return rule_governance_repository.audit(limit)


@app.post("/api/rules/audit/{entry_id}/rollback")
def rollback_rule_change(entry_id: int) -> dict[str, int | bool]:
    """把某条启用/停用记录回滚到变更前状态；回滚本身也留痕（审计链只增不改）。"""

    if not rule_governance_repository.rollback(entry_id):
        raise HTTPException(status_code=404, detail="审计记录不存在或不支持回滚")
    return {"entry_id": entry_id, "rolled_back": True}


@app.get("/api/rules/attack-coverage", response_model=AttackCoverageReport)
def attack_coverage() -> AttackCoverageReport:
    """返回 ATT&CK 基准技术覆盖度与未覆盖缺口。"""

    return evaluate_attack_coverage()


@app.post("/api/rules/sigma/preview", response_model=SigmaImportReport)
async def preview_sigma_rules(file: UploadFile = File(...)) -> SigmaImportReport:
    """预演 Sigma 规则导入：只做转换与报告，不写入规则目录。

    正式导入请使用 `backend/scripts/import_sigma.py --write`。
    """

    content = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"规则文件不能超过 {MAX_UPLOAD_BYTES // (1024 * 1024)} MB",
        )
    return convert_uploaded(Path(file.filename or "sigma.yml").name, content)


@app.get("/api/whitelist", response_model=WhitelistOverview)
def get_whitelist() -> WhitelistOverview:
    """用户白名单：命中的记录放过判定但保留证据，同时返回变更审计历史。"""

    return WhitelistOverview(
        kinds=KIND_LABELS,
        entries=[
            WhitelistEntryModel(
                id=entry.id,
                kind=entry.kind,
                value=entry.value,
                note=entry.note,
                enabled=entry.enabled,
                created_at=entry.created_at,
            )
            for entry in whitelist_repository.list_entries()
        ],
        changes=whitelist_repository.recent_changes(),
    )


@app.post("/api/whitelist", response_model=WhitelistEntryModel)
def add_whitelist(payload: WhitelistCreateRequest) -> WhitelistEntryModel:
    kind = payload.kind.strip().lower()
    if kind not in WHITELIST_KINDS:
        raise HTTPException(
            status_code=400,
            detail=f"不支持的维度「{payload.kind}」，可选：{', '.join(WHITELIST_KINDS)}",
        )
    value = payload.value.strip()
    if not value:
        raise HTTPException(status_code=400, detail="白名单取值不能为空")
    entry = whitelist_repository.add(kind, value, payload.note.strip())
    return WhitelistEntryModel(
        id=entry.id,
        kind=entry.kind,
        value=entry.value,
        note=entry.note,
        enabled=entry.enabled,
        created_at=entry.created_at,
    )


@app.patch("/api/whitelist/{entry_id}")
def toggle_whitelist(entry_id: int, enabled: bool = Query(...)) -> dict[str, bool]:
    if not whitelist_repository.set_enabled(entry_id, enabled):
        raise HTTPException(status_code=404, detail="白名单条目不存在")
    return {"enabled": enabled}


@app.delete("/api/whitelist/{entry_id}")
def delete_whitelist(entry_id: int) -> dict[str, bool]:
    if not whitelist_repository.remove(entry_id):
        raise HTTPException(status_code=404, detail="白名单条目不存在")
    return {"removed": True}


@app.get("/api/demo/logs")
def list_demo_logs() -> list[dict[str, str | int]]:
    descriptions = {
        "ssh": "SSH 认证失败、成功登录与高权限账户",
        "iis": "IIS Web 访问、敏感路径与 404 扫描",
        "windows": "Windows Security / RDP 登录失败与成功登录",
        "structured": "JSON 与 CSV 通用认证事件",
        "firewall": "Firewall 键值日志与多端口探测",
        "database": "MySQL / PostgreSQL / MongoDB / Redis / SQL Server / Oracle 认证与高危语句",
    }
    items: list[dict[str, str | int]] = []
    for path in sorted(DEMO_LOG_ROOT.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in {".log", ".json", ".csv", ".xml"}:
            continue
        relative = path.relative_to(DEMO_LOG_ROOT).as_posix()
        if relative not in DEMO_VISIBLE_FILES:
            continue
        category = relative.split("/", 1)[0]
        items.append(
            {
                "name": path.name,
                "path": relative,
                "category": category,
                "description": descriptions.get(category, "预置演示日志"),
                "size": path.stat().st_size,
            }
        )
    return items


def _analyze_parsed(filenames: list[str], parsed_logs: list[ParsedLog]) -> UploadResponse:
    analysis_id = str(uuid4())
    created_at = datetime.now(timezone.utc).isoformat()
    display_filename = filenames[0] if len(filenames) == 1 else f"{len(filenames)} 个日志文件"
    repository.create(analysis_id, display_filename, created_at)
    try:
        result = analyze_parsed_logs(filenames, parsed_logs).model_copy(
            update={"id": analysis_id, "created_at": created_at}
        )
        records = collect_records(filenames, parsed_logs)
        records = assign_record_ids(records)
        repository.complete(result, records)
    except Exception as exc:
        repository.fail(analysis_id, str(exc), datetime.now(timezone.utc).isoformat())
        raise HTTPException(status_code=500, detail="日志分析失败") from exc
    return UploadResponse(analysis_id=analysis_id, result=result)


def _persist_upload_files(analysis_id: str, uploads: list[tuple[str, bytes]]) -> None:
    """把用户上传的原始文件保存到 data/uploads/{analysis_id}/，供后续下载。

    演示日志不走这里（直接从 sample_logs 解析，无需重复落盘）。
    同名文件自动加序号前缀，避免相互覆盖。
    """

    directory = UPLOAD_ROOT / analysis_id
    directory.mkdir(parents=True, exist_ok=True)
    used: set[str] = set()
    manifest_files: list[dict[str, str | int]] = []
    for index, (filename, content) in enumerate(uploads, start=1):
        target_name = filename
        if target_name.lower() in used:
            stem = Path(filename).stem or "file"
            suffix = Path(filename).suffix or ".log"
            target_name = f"{index}-{stem}{suffix}"
        used.add(target_name.lower())
        target = directory / target_name
        target.write_bytes(content)
        try:
            target.chmod(0o444)
        except OSError:
            pass
        manifest_files.append(
            {
                "filename": target_name,
                "size_bytes": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
            }
        )
    manifest = {
        "analysis_id": analysis_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "files": manifest_files,
    }
    (directory / "evidence-manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def _read_evidence_manifest(analysis_id: str) -> dict[str, Any] | None:
    path = UPLOAD_ROOT / analysis_id / "evidence-manifest.json"
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _enrich_evidence_manifest(
    manifest: dict[str, Any],
    result: AnalysisResult,
    records: list[dict[str, str | None]],
) -> dict[str, Any]:
    """把解析记录、事件和证据编号写回案件清单，便于离线核验。"""

    manifest["record_count"] = len(records)
    manifest["record_ids"] = [
        record["record_id"] for record in records if record.get("record_id")
    ]
    manifest["evidence_ids"] = [
        record["evidence_id"] for record in records if record.get("evidence_id")
    ]
    manifest["events"] = [
        {
            "event_id": event.id,
            "rule_id": event.rule_id,
            "source_files": event.source_files,
            "evidence_ids": [item.id for item in event.evidence_items],
            "record_ids": [
                item.record_id for item in event.evidence_items if item.record_id
            ],
        }
        for event in result.events
    ]
    manifest["report"] = {
        "analysis_id": result.id,
        "json": f"loginsight-{result.id}.json",
        "html": f"loginsight-{result.id}.html",
        "event_count": len(result.events),
        "events_total": result.events_total or len(result.events),
    }
    return manifest


def _upload_storage_bytes() -> int:
    if not UPLOAD_ROOT.is_dir():
        return 0
    total = 0
    for path in UPLOAD_ROOT.rglob("*"):
        if path.is_file():
            try:
                total += path.stat().st_size
            except OSError:
                continue
    return total


def _validate_upload_capacity(uploads: list[tuple[str, bytes]]) -> None:
    analysis_bytes = sum(len(content) for _, content in uploads)
    if analysis_bytes > MAX_ANALYSIS_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=(
                f"本次分析文件总大小不能超过 "
                f"{MAX_ANALYSIS_UPLOAD_BYTES // (1024 * 1024)} MB"
            ),
        )
    # 内存预检：文本日志峰值实测为文件大小的 4.4 倍，超了会在解析中途把机器压到换页。
    # 宁可在这里拒绝并说清需要多少，也不要让用户等几分钟后看到进程被杀。
    memory_problem = check_upload_memory(analysis_bytes)
    if memory_problem:
        raise HTTPException(status_code=413, detail=memory_problem)
    current_bytes = _upload_storage_bytes()
    if current_bytes + analysis_bytes > MAX_UPLOAD_STORAGE_BYTES:
        raise HTTPException(
            status_code=507,
            detail="上传空间不足：当前上传目录已达到容量限制，请删除历史分析后重试",
        )


@app.post("/api/logs/upload", response_model=UploadResponse)
async def upload_log(
    file: UploadFile | None = File(None),
    files: list[UploadFile] | None = File(None),
) -> UploadResponse:
    upload_files = ([file] if file else []) + (files or [])
    if not upload_files or any(not item.filename for item in upload_files):
        raise HTTPException(status_code=400, detail="至少选择一个日志文件")

    uploads: list[tuple[str, bytes]] = []
    filenames: list[str] = []
    parsed_logs: list[ParsedLog] = []
    for upload_file in upload_files:
        content = await upload_file.read(MAX_UPLOAD_BYTES + 1)
        if len(content) > MAX_UPLOAD_BYTES:
            raise HTTPException(
                status_code=413,
                detail=(
                    f"文件 {upload_file.filename} 不能超过 "
                    f"{MAX_UPLOAD_BYTES // (1024 * 1024)} MB"
                ),
            )
        safe_name = Path(upload_file.filename or "unknown.log").name
        filenames.append(safe_name)
        uploads.append((safe_name, content))
    _validate_upload_capacity(uploads)
    for _, content in uploads:
        try:
            parsed_logs.append(parse_upload(content))
        except EvtxUnavailableError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    response = _analyze_parsed(filenames, parsed_logs)
    try:
        _persist_upload_files(response.analysis_id, uploads)
        records = repository.get_records(response.analysis_id) or []
        manifest = _read_evidence_manifest(response.analysis_id)
        if manifest is not None:
            _enrich_evidence_manifest(manifest, response.result, records)
            (UPLOAD_ROOT / response.analysis_id / "evidence-manifest.json").write_text(
                json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
    except Exception as exc:  # noqa: BLE001 - 落盘失败必须回滚，不能留下不一致的半成品
        # 分析结果已入库但原始文件没存住：删掉可能已写入的目录和这条记录。
        # 分析阶段自身的失败不走这里（那种情况保留 failed 记录以便追溯）。
        shutil.rmtree(UPLOAD_ROOT / response.analysis_id, ignore_errors=True)
        repository.delete(response.analysis_id)
        raise HTTPException(
            status_code=500, detail="原始文件保存失败，本次分析已回滚"
        ) from exc
    return response


@app.post("/api/demo/analyze", response_model=UploadResponse)
def analyze_demo_logs(payload: DemoAnalyzeRequest) -> UploadResponse:
    filenames: list[str] = []
    parsed_logs: list[ParsedLog] = []
    for relative in payload.files:
        candidate = (DEMO_LOG_ROOT / relative).resolve()
        if DEMO_LOG_ROOT not in candidate.parents or not candidate.is_file():
            raise HTTPException(status_code=400, detail=f"不支持的演示日志：{relative}")
        if candidate.suffix.lower() not in {".log", ".json", ".csv", ".xml"}:
            raise HTTPException(status_code=400, detail=f"不支持的演示文件：{relative}")
        filenames.append(f"demo-{candidate.name}")
        parsed_logs.append(parse_upload(candidate.read_bytes()))
    return _analyze_parsed(filenames, parsed_logs)


@app.get("/api/ai/config")
def get_ai_config():
    return check_ai_config()


@app.put("/api/ai/config")
def update_ai_config(payload: AiConfigUpdate):
    try:
        return save_ai_config(
            payload.provider,
            payload.base_url,
            payload.model,
            payload.api_key,
            payload.clear_api_key,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/ai/test")
def test_ai():
    return test_ai_connection()


# 详情响应里事件列表的上限：大记录曾返回 37 MB（7536 个事件），前端会卡在「正在加载」。
# 只裁 HTTP 响应，**不改存储**——HTML/JSON 报告直接读存储，因此报告仍然完整。
ANALYSIS_EVENT_LIMIT_DEFAULT = 200
ANALYSIS_EVENT_LIMIT_MAX = 1000


def _trim_events(result: AnalysisResult, limit: int, offset: int = 0) -> AnalysisResult:
    """按上限裁剪响应里的事件列表，并把真实总数写进 events_total。

    截取前先按风险从高到低排序：列表被截断时，最先看到的必须是等级最高的事件，
    而不是最先被规则产出的事件。排序放在读取侧是有意为之——历史记录落库时存的是
    检测产出顺序，不做这一步的话点开旧记录仍会看到「按规则顺序排」的前 200 条。
    """

    if result.events_total is None:
        result = result.model_copy(update={"events_total": len(result.events)})
    events = sort_events_by_risk(result.events)
    events = events[offset : offset + limit] if limit > 0 else events[offset:]
    if events == result.events:
        return result
    return result.model_copy(update={"events": events})


@app.get("/api/ai/usage-history", response_model=AiUsageHistory)
def ai_usage_history(
    limit: int = Query(30, ge=1, le=200),
) -> AiUsageHistory:
    """AI 研判的跨分析用量趋势（只读）。

    汇总只统计**确实有用量记录**的那些分析，并同时返回 `with_usage` / `total_points`，
    让前端能如实说明「N 条中有 M 条有账单」，而不是拿残缺样本冒充全量。
    """

    history = repository.ai_usage_history(limit)
    points = [AiUsagePoint.model_validate(item) for item in history]

    prompt_tokens = 0
    completion_tokens = 0
    hit_ratios: list[float] = []
    for point in points:
        usage = point.usage or {}
        if not isinstance(usage.get("prompt_tokens"), (int, float)):
            continue
        prompt_tokens += int(usage["prompt_tokens"])
        completion_tokens += int(usage.get("completion_tokens") or 0)
        if isinstance(usage.get("cache_hit_ratio"), (int, float)):
            hit_ratios.append(float(usage["cache_hit_ratio"]))

    with_usage = sum(
        1
        for point in points
        if point.usage and isinstance(point.usage.get("prompt_tokens"), (int, float))
    )
    return AiUsageHistory(
        points=points,
        with_usage=with_usage,
        total_points=len(points),
        avg_prompt_tokens=round(prompt_tokens / with_usage) if with_usage else 0,
        avg_completion_tokens=round(completion_tokens / with_usage) if with_usage else 0,
        avg_cache_hit_ratio=(
            round(sum(hit_ratios) / len(hit_ratios), 4) if hit_ratios else None
        ),
    )


@app.get("/api/analysis/{analysis_id}", response_model=AnalysisResult)
def get_analysis(
    analysis_id: str,
    event_limit: int = Query(
        ANALYSIS_EVENT_LIMIT_DEFAULT,
        ge=1,
        le=ANALYSIS_EVENT_LIMIT_MAX,
    ),
    event_offset: int = Query(0, ge=0),
) -> AnalysisResult:
    """读取分析结果。普通查询有硬上限，完整数据通过报告导出获取。"""

    result = repository.get(analysis_id)
    if result is None:
        raise HTTPException(status_code=404, detail="分析记录不存在")
    return _trim_events(result, event_limit, event_offset)


# AI 洞察里的攻击链上限：链数 = 来源 IP 数，认证导出可到 2000 条（实测 2.33 MB / 1999 条链），
# 前端会为每条链渲染一张卡片。只裁响应，真实条数在 attack_chains_total。
INSIGHTS_CHAIN_LIMIT_DEFAULT = 20
INSIGHTS_CHAIN_LIMIT_MAX = 100


@app.get("/api/analysis/{analysis_id}/insights", response_model=Insights)
def get_insights(
    analysis_id: str,
    chain_limit: int = Query(
        INSIGHTS_CHAIN_LIMIT_DEFAULT,
        ge=1,
        le=INSIGHTS_CHAIN_LIMIT_MAX,
    ),
    chain_offset: int = Query(0, ge=0),
) -> Insights:
    """AI 赋能洞察：时间频次柱状图 + 攻击链（ATT&CK 风格）。

    攻击链按「风险 → 阶段数 → 触发次数」排序后取前 `chain_limit` 条，
    保证截断时先看到的是最完整的攻击过程，而不是某个随机来源 IP。
    普通接口有硬上限；完整数据通过报告导出获取。
    """

    result = repository.get(analysis_id)
    records = repository.get_records(analysis_id)
    if result is None or records is None:
        raise HTTPException(status_code=404, detail="分析记录不存在")
    chains = build_attack_chains(result.events, result.entities)
    return Insights(
        timeseries=build_timeseries(records),
        attack_chains=chains[chain_offset : chain_offset + chain_limit],
        attack_chains_total=len(chains),
    )


@app.get("/api/analysis/{analysis_id}/dashboard", response_model=AnalysisDashboard)
def get_dashboard(analysis_id: str) -> AnalysisDashboard:
    """概览看板：严重度卡片、事件时间分布、ATT&CK 战术网格与 Top 榜单。

    纯展示层——全部由既有事件与记录推导，不新增判定、不改风险等级。
    注意 `events_total` 是事件数、`buckets[].count` 是记录数，两者不可混用。
    """

    result = repository.get(analysis_id)
    if result is None:
        raise HTTPException(status_code=404, detail="分析记录不存在")
    records = repository.get_records(analysis_id) or []
    return build_dashboard(analysis_id, result, records)


@app.get("/api/analysis/{analysis_id}/facets", response_model=LogFacets)
def get_facets(analysis_id: str) -> LogFacets:
    """字段概览：每个字段的覆盖率与取值 Top（日志明细的字段侧栏用）。

    低覆盖率只说明「这份日志基本没填这个字段」，不代表该字段没有异常。
    """

    result = repository.get(analysis_id)
    if result is None:
        raise HTTPException(status_code=404, detail="分析记录不存在")
    return build_facets(analysis_id, result, repository.get_records(analysis_id) or [])


@app.get("/api/analysis/{analysis_id}/search", response_model=SearchResult)
def search_analysis(
    analysis_id: str,
    q: str = Query("", description="查询串，例如 source_ip:10.0.0.8 -login"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=10, le=200),
) -> SearchResult:
    """搜索语法查询：字段:值 + 负号排除 + 裸词全文，一次定位相关记录与事件。

    不是 SQL 控制台——搜索只做只读筛选，作用域限于本次分析的记录与事件。
    """

    result = repository.get(analysis_id)
    if result is None:
        raise HTTPException(status_code=404, detail="分析记录不存在")
    return search_records(
        analysis_id,
        result,
        repository.get_records(analysis_id) or [],
        q,
        page=page,
        page_size=page_size,
    )


@app.get("/api/analysis/{analysis_id}/search-fields")
def search_fields() -> dict[str, list[str]]:
    """可用搜索字段（前端语法提示用），只返回别名，不暴露内部结构。"""

    return {"fields": sorted(FIELD_ALIASES)}


@app.get("/api/analysis/{analysis_id}/attack-navigator")
def export_attack_navigator(analysis_id: str) -> Response:
    """导出 ATT&CK Navigator 图层（layer v4.5 JSON），可直接在 Navigator 里打开。

    只导出本次真正命中的技术；未命中的不画，避免图层读起来像「全都被打过」。
    """

    result = repository.get(analysis_id)
    if result is None:
        raise HTTPException(status_code=404, detail="分析记录不存在")
    matrix = build_attack_matrix(analysis_id, result, repository.get_records(analysis_id) or [])
    layer = build_navigator_layer(matrix)
    return Response(
        content=json.dumps(layer, ensure_ascii=False, indent=2),
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="attack-navigator-{analysis_id[:8]}.json"'
        },
    )


@app.get("/api/analysis/{analysis_id}/attack-matrix", response_model=AttackMatrix)
def get_attack_matrix(analysis_id: str) -> AttackMatrix:
    """ATT&CK 战术 × 技术两级矩阵：本次命中的技术与对应规则。

    只做映射与计数，不新增判定。技术清单来自项目内置的覆盖标尺；
    清单外但本次命中的技术同样返回，并标 `in_benchmark=false`。
    """

    result = repository.get(analysis_id)
    if result is None:
        raise HTTPException(status_code=404, detail="分析记录不存在")
    return build_attack_matrix(analysis_id, result, repository.get_records(analysis_id) or [])


@app.get("/api/analysis/{analysis_id}/detections", response_model=DetectionsReport)
def get_detections(analysis_id: str) -> DetectionsReport:
    """检测视图：把事件按规则归组，附带规则来源、描述、标签与验证状态。

    只做归组与元数据补全，不合并风险等级、不改结论。
    注意 `event_count`（事件条数）与 `trigger_count`（触发次数合计）是两个口径。
    """

    result = repository.get(analysis_id)
    if result is None:
        raise HTTPException(status_code=404, detail="分析记录不存在")
    return build_detections(analysis_id, result, repository.get_records(analysis_id) or [])


@app.get("/api/analysis/{analysis_id}/threat-intel", response_model=ThreatIntelReport)
def get_threat_intel(
    analysis_id: str,
    refresh: bool = Query(False, description="忽略缓存强制重查"),
) -> ThreatIntelReport:
    """威胁情报富化：把分析中的公网 IP / 域名送到公开情报库比对。

    默认关闭（`THREAT_INTEL_ENABLED`），关闭时返回带说明的空报告、不发外部请求。
    结果独立于 `events` 与风险定级展示，不进入 AI 上下文。
    """

    result = repository.get(analysis_id)
    if result is None:
        raise HTTPException(status_code=404, detail="分析记录不存在")
    records = repository.get_records(analysis_id)
    return enrich_threat_intel(analysis_id, result, records, refresh=refresh)


@app.get("/api/analysis/{analysis_id}/records", response_model=LogRecordPage)
def get_analysis_records(
    analysis_id: str,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=10, le=200),
    source_ip: str | None = None,
    destination_ip: str | None = None,
    path: str | None = None,
    log_type: str | None = None,
    action: str | None = None,
    status: str | None = None,
    record_id: str | None = None,
) -> LogRecordPage:
    if repository.get(analysis_id) is None:
        raise HTTPException(status_code=404, detail="分析记录不存在")
    items, total = repository.get_record_page(
        analysis_id,
        page,
        page_size,
        source_ip,
        destination_ip,
        path,
        log_type,
        action,
        status,
        record_id,
    )
    return LogRecordPage(
        items=items,
        page=page,
        page_size=page_size,
        total=total,
        total_pages=(total + page_size - 1) // page_size if total else 0,
        available_log_types=sorted(
            {
                record.get("log_type")
                for record in (repository.get_records(analysis_id) or [])
                if record.get("log_type")
            }
        ),
    )


@app.get(
    "/api/analysis/{analysis_id}/entities/{kind}/{value}",
    response_model=EntityInvestigation,
)
def investigate_entity(
    analysis_id: str,
    kind: str,
    value: str,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    event_limit: int = Query(50, ge=1, le=200),
    timeline_limit: int = Query(100, ge=1, le=500),
) -> EntityInvestigation:
    """按实体查看关联记录、事件和时间线，供应急调查快速定位。

    实体值一律**精确匹配**（忽略大小写）。曾经用子串包含，结果查 `10.0.0.8`
    会连 `10.0.0.80` 一起返回、查账号 `root` 会连 `rootuser` 一起返回——
    取证视图里这是伪造关联。需要模糊查找请用日志明细的关键词筛选，两者语义不同。
    """

    result = repository.get(analysis_id)
    if result is None:
        raise HTTPException(status_code=404, detail="分析记录不存在")
    aliases = {
        "ip": {"source_ip", "destination_ip"},
        "source_ip": {"source_ip"},
        "destination_ip": {"destination_ip"},
        "account": {"username"},
        "username": {"username"},
        "host": {"target_asset"},
        "target_asset": {"target_asset"},
        "domain": {"query_name"},
        "process": {"process_image", "parent_image"},
    }
    normalized_kind = kind.lower()
    fields = aliases.get(normalized_kind)
    expected = value.strip()
    if not fields or not expected:
        raise HTTPException(
            status_code=400,
            detail="实体类型仅支持 ip、source_ip、destination_ip、account、host、domain、process",
        )
    target = expected.lower()
    all_records = repository.get_records(analysis_id) or []

    def matches(record: dict[str, str | None]) -> bool:
        return any((record.get(field) or "").lower() == target for field in fields)

    matched_records = [record for record in all_records if matches(record)]
    start = (page - 1) * page_size
    page_items = matched_records[start : start + page_size]
    record_ids = {
        record.get("record_id") for record in matched_records if record.get("record_id")
    }
    evidence_ids = {
        record.get("evidence_id")
        for record in matched_records
        if record.get("evidence_id")
    }
    matched_events = [
        event
        for event in result.events
        if any(
            item.record_id in record_ids or item.id in evidence_ids
            for item in event.evidence_items
        )
    ]
    # 截断前先按风险从高到低排：留下的是最严重的事件，而不是最早产出的事件
    events = sort_events_by_risk(matched_events)[:event_limit]
    # 只有 IP 类实体才比对 timeline 的 source_ip，否则拿账号值去比 IP 是无意义的巧合匹配
    compare_source_ip = normalized_kind in {"ip", "source_ip", "destination_ip"}
    matched_timeline = [
        item
        for item in result.timeline
        if item.record_id in record_ids
        or (compare_source_ip and (item.source_ip or "").lower() == target)
    ]
    matched_timeline.sort(key=lambda item: item.timestamp_iso or item.timestamp or "")
    available_log_types = sorted(
        {str(record.get("log_type")) for record in matched_records if record.get("log_type")}
    )
    return EntityInvestigation(
        kind=normalized_kind,
        value=value,
        records=LogRecordPage(
            items=page_items,
            page=page,
            page_size=page_size,
            total=len(matched_records),
            total_pages=max(1, (len(matched_records) + page_size - 1) // page_size),
            available_log_types=available_log_types,
        ),
        events=events,
        events_total=len(matched_events),
        timeline=matched_timeline[:timeline_limit],
        timeline_total=len(matched_timeline),
    )


@app.get("/api/analysis/{analysis_id}/records/export")
def export_analysis_records(
    analysis_id: str,
    source_ip: str | None = None,
    destination_ip: str | None = None,
    path: str | None = None,
    log_type: str | None = None,
    action: str | None = None,
    status: str | None = None,
) -> Response:
    if repository.get(analysis_id) is None:
        raise HTTPException(status_code=404, detail="分析记录不存在")
    items, _ = repository.get_record_page(
        analysis_id,
        1,
        200000,
        source_ip,
        destination_ip,
        path,
        log_type,
        action,
        status,
    )
    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "timestamp",
            "source_file",
            "log_type",
            "source_ip",
            "destination_ip",
            "url",
            "action",
            "status",
            "result",
            "raw",
        ],
        extrasaction="ignore",
    )
    writer.writeheader()
    writer.writerows(items)
    return Response(
        content=output.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="loginsight-{analysis_id}-records.csv"'
        },
    )


def _apply_ai_judgement(result: AnalysisResult, judgement: dict[str, Any]) -> AnalysisResult:
    """把 AI 研判结果合并进本地规则分析结果（取更高风险/置信度，追加建议）。"""

    local_rank = RISK_ORDER.index(result.risk_level)
    ai_rank = RISK_ORDER.index(judgement["risk_level"])
    risk_level = RISK_ORDER[max(local_rank, ai_rank)]
    recommendations = list(result.recommendations)
    for item in judgement["recommendations"]:
        if item not in recommendations:
            recommendations.append(item)
    return result.model_copy(
        update={
            "risk_level": risk_level,
            "confidence": max(result.confidence, judgement["confidence"]),
            "conclusion": judgement["conclusion"],
            "analysis_source": "rules_and_ai",
            "ai_status": "completed",
            "ai_error": None,
            "ai_behaviors": judgement["behaviors"],
            "ai_tool_trace": [
                AiToolCall.model_validate(item)
                for item in judgement.get("tool_trace", [])
            ],
            "ai_unsupported_claims": judgement.get("unsupported_claims", []),
            "ai_metrics": judgement.get("metrics"),
            "structured_verdict": judgement.get("structured_verdict"),
            "recommendations": recommendations[:10],
        }
    )


@app.post("/api/analysis/{analysis_id}/ai", response_model=AnalysisResult)
def analyze_with_ai(analysis_id: str) -> AnalysisResult:
    """同步 AI 研判（兼容旧客户端与测试）。前端已改用 /ai/start + 任务轮询。"""

    result = repository.get(analysis_id)
    records = repository.get_records(analysis_id)
    if result is None or records is None:
        raise HTTPException(status_code=404, detail="分析记录不存在")
    started_at = time.time()
    try:
        judgement = request_ai_judgement(result, records)
        updated = _apply_ai_judgement(result, judgement)
    except Exception as exc:
        updated = result.model_copy(
            update={
                "ai_status": "unavailable",
                "ai_error": str(exc),
                "analysis_source": "rules",
            }
        )
    repository.update_result(updated)
    ai_ledger_repository.save(
        build_ai_ledger(
            updated,
            updated.ai_status,
            duration_ms=int((time.time() - started_at) * 1000),
        )
    )
    # 老记录落库时是检测产出顺序，统一走一遍排序口径（0 = 不裁剪）
    return _trim_events(updated, 0)


# ---------- AI 异步研判任务（真实阶段进度） ----------

AI_TASKS: dict[str, dict[str, Any]] = {}
AI_TASK_LOCK = threading.Lock()
# 已结束的任务保留一段时间供前端拉取结果，之后清理；运行中的任务永不清理
AI_TASK_TTL_SECONDS = 1800
AI_TASK_MAX_ENTRIES = 200
# 模型增量输出只保留最新一段，且不逐块落盘（展示用，不入库压力太大）
AI_TASK_PARTIAL_LIMIT = 4000
AI_TASK_PARTIAL_SAVE_SECONDS = 2.0


def _prune_ai_tasks() -> None:
    """清理已结束的旧任务，避免 AI_TASKS 随分析次数无限增长（须在持有锁时调用）。"""

    now = time.time()
    for task_id, task in list(AI_TASKS.items()):
        if task["status"] != "running" and now - task["updated_at"] > AI_TASK_TTL_SECONDS:
            del AI_TASKS[task_id]
    overflow = len(AI_TASKS) - AI_TASK_MAX_ENTRIES
    if overflow <= 0:
        return
    finished = sorted(
        (task for task in AI_TASKS.values() if task["status"] != "running"),
        key=lambda task: task["updated_at"],
    )
    for task in finished[:overflow]:
        AI_TASKS.pop(task["task_id"], None)

def _prune_stored_ai_tasks() -> None:
    """按同样的 TTL 清理库里的已结束任务。

    刻意在锁外调用：持 `AI_TASK_LOCK` 期间做数据库 I/O 会连带阻塞进度查询。
    """

    cutoff = datetime.fromtimestamp(
        time.time() - AI_TASK_TTL_SECONDS, timezone.utc
    ).isoformat()
    try:
        repository.prune_ai_tasks(cutoff)
    except Exception:
        pass


# 阶段 → 进度百分比（前端据此驱动进度条）
AI_STAGE_PROGRESS: dict[str, int] = {
    "recovering": 5,
    "prepare_context": 10,
    "run_tools": 25,
    "call_model": 65,
    "parse_response": 85,
    "grounding": 95,
    "completed": 100,
}


def _persist_ai_task(task_id: str) -> None:
    """把任务状态落盘，供服务重启或其它 worker 查询。

    落盘失败只影响「重启后能否查到」，不影响研判本身：运行期内存里的状态仍是权威，
    因此这里不把异常抛给调用方（一次写锁冲突不该让几分钟的研判白跑）。
    """

    with AI_TASK_LOCK:
        task = AI_TASKS.get(task_id)
        snapshot = dict(task) if task else None
    if snapshot is None:
        return
    try:
        repository.save_ai_task(snapshot)
    except Exception:
        pass


def _run_ai_task(task_id: str, analysis_id: str) -> None:
    started_at = time.time()

    def report(stage: str) -> None:
        with AI_TASK_LOCK:
            task = AI_TASKS.get(task_id)
            if task is not None:
                task["stage"] = stage
                task["progress"] = AI_STAGE_PROGRESS.get(stage, task["progress"])
                task["updated_at"] = time.time()
        _persist_ai_task(task_id)

    last_partial_save = 0.0

    def report_delta(chunk: str) -> None:
        """把模型的增量输出写到任务上供前端实时展示。

        只影响展示：结论仍由完整文本经结构化与证据校验后得出，
        所以流式中断既不改动规则结果，也不改动结论。
        """

        nonlocal last_partial_save
        now = time.time()
        persist = now - last_partial_save >= AI_TASK_PARTIAL_SAVE_SECONDS
        if persist:
            last_partial_save = now
        with AI_TASK_LOCK:
            task = AI_TASKS.get(task_id)
            if task is None:
                return
            task["partial"] = (
                (task.get("partial") or "") + chunk
            )[-AI_TASK_PARTIAL_LIMIT:]
        if persist:
            _persist_ai_task(task_id)

    try:
        result = repository.get(analysis_id)
        records = repository.get_records(analysis_id)
        if result is None or records is None:
            raise ValueError("分析记录不存在")
        judgement = request_ai_judgement(
            result, records, progress_cb=report, delta_cb=report_delta
        )
        updated = _apply_ai_judgement(result, judgement)
        repository.update_result(updated)
        ai_ledger_repository.save(
            build_ai_ledger(
                updated,
                "completed",
                duration_ms=int((time.time() - started_at) * 1000),
            )
        )
        with AI_TASK_LOCK:
            task = AI_TASKS.get(task_id)
            if task is not None:
                task.update(
                    status="completed",
                    stage="completed",
                    progress=100,
                    result=_trim_events(updated, ANALYSIS_EVENT_LIMIT_DEFAULT),
                    error=None,
                    updated_at=time.time(),
                )
        _persist_ai_task(task_id)
    except Exception as exc:
        result = repository.get(analysis_id)
        if result is not None:
            failed = result.model_copy(
                update={
                    "ai_status": "unavailable",
                    "ai_error": str(exc),
                    "analysis_source": "rules",
                }
            )
            repository.update_result(failed)
            ai_ledger_repository.save(
                build_ai_ledger(
                    failed,
                    "unavailable",
                    duration_ms=int((time.time() - started_at) * 1000),
                )
            )
        with AI_TASK_LOCK:
            task = AI_TASKS.get(task_id)
            if task is not None:
                task.update(
                    status="failed", error=str(exc), updated_at=time.time()
                )
        _persist_ai_task(task_id)


def _start_ai_task_thread(task_id: str, analysis_id: str) -> None:
    threading.Thread(
        target=_run_ai_task, args=(task_id, analysis_id), daemon=True
    ).start()


def recover_running_ai_tasks() -> int:
    """接管服务重启前仍标记为 running 的任务并重新执行。"""

    recovered = 0
    for stored in repository.list_ai_tasks("running"):
        task_id = stored["task_id"]
        with AI_TASK_LOCK:
            if task_id in AI_TASKS:
                continue
            task = {
                **stored,
                "status": "running",
                "stage": "recovering",
                "progress": 5,
                "error": None,
                "updated_at": time.time(),
            }
            AI_TASKS[task_id] = task
            _prune_ai_tasks()
        if repository.get(stored["analysis_id"]) is None or repository.get_records(
            stored["analysis_id"]
        ) is None:
            with AI_TASK_LOCK:
                task["status"] = "failed"
                task["stage"] = "recovering"
                task["error"] = "服务重启后恢复失败：分析记录不存在"
                task["updated_at"] = time.time()
            _persist_ai_task(task_id)
            continue
        _persist_ai_task(task_id)
        _start_ai_task_thread(task_id, stored["analysis_id"])
        recovered += 1
    _prune_stored_ai_tasks()
    return recovered


@app.on_event("startup")
def _recover_ai_tasks_on_startup() -> None:
    recover_running_ai_tasks()


@app.post("/api/analysis/{analysis_id}/ai/start")
def start_ai_analysis(analysis_id: str) -> dict[str, str]:
    """启动后台 AI 研判任务，返回 task_id 供前端轮询进度。"""

    result = repository.get(analysis_id)
    records = repository.get_records(analysis_id)
    if result is None or records is None:
        raise HTTPException(status_code=404, detail="分析记录不存在")
    task_id = str(uuid4())
    created_at = datetime.now(timezone.utc).isoformat()
    with AI_TASK_LOCK:
        AI_TASKS[task_id] = {
            "task_id": task_id,
            "analysis_id": analysis_id,
            "status": "running",
            "stage": "prepare_context",
            "progress": 5,
            "error": None,
            "result": None,
            "partial": None,
            "created_at": created_at,
            "updated_at": time.time(),
        }
        # 先登记再清理：新任务是 running，不会被自己清掉，容量上限也就不会被越过
        _prune_ai_tasks()
    _prune_stored_ai_tasks()
    _persist_ai_task(task_id)
    _start_ai_task_thread(task_id, analysis_id)
    return {"task_id": task_id}


@app.get("/api/ai/tasks/{task_id}")
def get_ai_task(task_id: str) -> dict[str, Any]:
    """查询 AI 研判任务进度；完成时附带完整分析结果。

    内存里没有就回落到数据库：服务重启后、或多 worker 部署下请求落到别的进程时，
    任务状态依然查得到。
    """

    with AI_TASK_LOCK:
        task = AI_TASKS.get(task_id)
        payload = dict(task) if task else None
    if payload is None:
        payload = repository.get_ai_task(task_id)
    if payload is None:
        raise HTTPException(status_code=404, detail="任务不存在或已过期")
    return payload


def _get_ai_ledger(analysis_id: str) -> AiLedger:
    stored = ai_ledger_repository.get(analysis_id)
    if stored is not None:
        return stored
    result = repository.get(analysis_id)
    if result is None:
        raise HTTPException(status_code=404, detail="分析记录不存在")
    if result.ai_status == "not_analyzed":
        raise HTTPException(status_code=404, detail="该分析尚未执行 AI 研判")
    ledger = build_ai_ledger(result, result.ai_status)
    ai_ledger_repository.save(ledger)
    return ledger


@app.get("/api/analysis/{analysis_id}/ai/ledger", response_model=AiLedger)
def get_ai_ledger(analysis_id: str) -> AiLedger:
    return _get_ai_ledger(analysis_id)


@app.get("/api/analysis/{analysis_id}/ai/ledger/export")
def export_ai_ledger(analysis_id: str, format: str = "json") -> Response:
    ledger = _get_ai_ledger(analysis_id)
    if format == "json":
        return Response(
            content=render_ledger_json(ledger),
            media_type="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="loginsight-{analysis_id}-ai-ledger.json"'
            },
        )
    if format == "html":
        return Response(
            content=render_ledger_html(ledger),
            media_type="text/html",
            headers={
                "Content-Disposition": f'attachment; filename="loginsight-{analysis_id}-ai-ledger.html"'
            },
        )
    if format == "csv":
        return Response(
            content=render_ledger_csv(ledger),
            media_type="text/csv; charset=utf-8",
            headers={
                "Content-Disposition": f'attachment; filename="loginsight-{analysis_id}-ai-ledger.csv"'
            },
        )
    raise HTTPException(status_code=400, detail="format 只支持 json、html 或 csv")


@app.get("/api/analysis/{analysis_id}/review", response_model=HumanReview)
def get_human_review(analysis_id: str) -> HumanReview:
    if repository.get(analysis_id) is None:
        raise HTTPException(status_code=404, detail="分析记录不存在")
    return review_repository.get(analysis_id)


@app.post("/api/analysis/{analysis_id}/review", response_model=HumanReview)
def submit_human_review(analysis_id: str, payload: ReviewUpdate) -> HumanReview:
    """记录人工对 AI 结论的确认状态。追加式留痕，不覆盖历史。"""

    if repository.get(analysis_id) is None:
        raise HTTPException(status_code=404, detail="分析记录不存在")
    reviewer = payload.reviewer.strip()
    if not reviewer:
        raise HTTPException(status_code=400, detail="确认人不能为空")
    return review_repository.record(
        analysis_id, payload.status, reviewer, payload.note.strip()
    )


@app.get("/api/analysis/{analysis_id}/report")
def export_report(analysis_id: str, format: str = "json") -> Response:
    stored = repository.get(analysis_id)
    if stored is None:
        raise HTTPException(status_code=404, detail="分析记录不存在")
    # 报告仍是全量（0 = 不裁剪），但顺序与界面一致：老记录也按风险从高到低补排一遍
    result = _trim_events(stored, 0)
    if format in SIEM_EXPORT_FORMATS:
        # SIEM 平台模板：只导出检测结果（事件），字段映射见 siem_export
        renderer, media_type, suffix = SIEM_EXPORT_FORMATS[format]
        return Response(
            content=renderer(result.events),
            media_type=media_type,
            headers={
                "Content-Disposition": (
                    f'attachment; filename="loginsight-{analysis_id}-{suffix}"'
                )
            },
        )
    manifest = _read_evidence_manifest(analysis_id)
    review = review_repository.get(analysis_id)
    if format == "json":
        payload = json.loads(render_json_report(result, review))
        if manifest is not None:
            payload["evidence_manifest"] = manifest
        return Response(
            content=json.dumps(payload, ensure_ascii=False, indent=2),
            media_type="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="loginsight-{analysis_id}.json"'
            },
        )
    if format == "html":
        return Response(
            content=render_html_report(result, review),
            media_type="text/html",
            headers={
                "Content-Disposition": f'attachment; filename="loginsight-{analysis_id}.html"'
            },
        )
    raise HTTPException(
        status_code=400,
        detail="format 只支持 json、html、splunk、elastic、opensearch、timesketch 或 sarif",
    )


@app.get("/api/analysis/{analysis_id}/download")
def download_analysis_files(analysis_id: str) -> Response:
    """下载用户上传的原始日志：单文件直接下载，多文件打包 zip。

    演示日志不落盘（直接解析自 sample_logs），因此无原始文件时返回 404。
    """

    if repository.get(analysis_id) is None:
        raise HTTPException(status_code=404, detail="分析记录不存在")
    directory = UPLOAD_ROOT / analysis_id
    if not directory.is_dir():
        raise HTTPException(status_code=404, detail="原始日志文件不存在（演示日志不支持下载）")
    files = sorted(
        path
        for path in directory.iterdir()
        if path.is_file() and path.name != "evidence-manifest.json"
    )
    if not files:
        raise HTTPException(status_code=404, detail="原始日志文件不存在（演示日志不支持下载）")
    manifest_path = directory / "evidence-manifest.json"
    if len(files) == 1:
        return FileResponse(
            files[0],
            filename=files[0].name,
            headers={"Content-Disposition": f'attachment; filename="{files[0].name}"'},
        )
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in files:
            archive.write(path, arcname=path.name)
        if manifest_path.is_file():
            archive.write(manifest_path, arcname=manifest_path.name)
    return Response(
        content=buffer.getvalue(),
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="loginsight-{analysis_id}-logs.zip"'
        },
    )


@app.get("/api/analysis/{analysis_id}/evidence-manifest")
def get_evidence_manifest(analysis_id: str) -> Response:
    if repository.get(analysis_id) is None:
        raise HTTPException(status_code=404, detail="分析记录不存在")
    manifest_path = UPLOAD_ROOT / analysis_id / "evidence-manifest.json"
    if not manifest_path.is_file():
        raise HTTPException(status_code=404, detail="原始文件清单不存在（演示日志不支持）")
    return Response(
        content=manifest_path.read_text(encoding="utf-8"),
        media_type="application/json",
    )


@app.get("/api/analysis/{analysis_id}/case-package")
def download_case_package(analysis_id: str) -> Response:
    """导出一次性案件包：原始日志、哈希清单和完整 JSON/HTML 报告。"""

    stored = repository.get(analysis_id)
    if stored is None:
        raise HTTPException(status_code=404, detail="分析记录不存在")
    directory = UPLOAD_ROOT / analysis_id
    files = sorted(
        path
        for path in directory.iterdir()
        if path.is_file()
        and path.name != "evidence-manifest.json"
    ) if directory.is_dir() else []
    if not files:
        raise HTTPException(status_code=404, detail="原始日志文件不存在（演示日志不支持案件包）")
    result = _trim_events(stored, 0)
    manifest = _read_evidence_manifest(analysis_id) or {
        "analysis_id": analysis_id,
        "files": [],
    }
    review = review_repository.get(analysis_id)
    report_json = render_json_report(result, review)
    report_html = render_html_report(result, review)
    package_entries: dict[str, bytes] = {
        **{f"evidence/{path.name}": path.read_bytes() for path in files},
        "report.json": report_json.encode("utf-8"),
        "report.html": report_html.encode("utf-8"),
    }
    manifest["package_integrity"] = [
        {
            "path": name,
            "size_bytes": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
        }
        for name, content in sorted(package_entries.items())
    ]
    manifest["package_files"] = [
        *[entry["path"] for entry in manifest["package_integrity"]],
        "evidence-manifest.json",
    ]
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in package_entries.items():
            archive.writestr(name, content)
        archive.writestr(
            "evidence-manifest.json",
            json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        )
    return Response(
        content=buffer.getvalue(),
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="loginsight-{analysis_id}-case.zip"'
        },
    )


@app.get("/api/logs", response_model=list[LogSummary] | LogSummaryPage)
def list_logs(
    page: int | None = Query(None, ge=1),
    page_size: int | None = Query(None, ge=1, le=200),
    log_type: str | None = None,
    risk_level: str | None = None,
    status: str | None = None,
    keyword: str | None = None,
    sort: str = "created_desc",
) -> list[LogSummary] | LogSummaryPage:
    # 无参数时保留旧的数组响应，便于旧版脚本和 API 客户端继续工作。
    if page is None and page_size is None and not any(
        (log_type, risk_level, status, keyword)
    ):
        return repository.list()
    current_page = page or 1
    current_page_size = page_size or 20
    items, total, available_types = repository.list_page(
        current_page, current_page_size, log_type, risk_level, status, keyword, sort
    )
    return LogSummaryPage(
        items=items,
        page=current_page,
        page_size=current_page_size,
        total=total,
        total_pages=(total + current_page_size - 1) // current_page_size if total else 0,
        available_log_types=available_types,
    )


@app.delete("/api/analysis/{analysis_id}", status_code=204)
def delete_analysis(analysis_id: str) -> Response:
    if not repository.delete(analysis_id):
        raise HTTPException(status_code=404, detail="分析记录不存在")
    review_repository.delete(analysis_id)
    shutil.rmtree(UPLOAD_ROOT / analysis_id, ignore_errors=True)
    return Response(status_code=204)


# ---------- 前端静态托管（便携版单进程运行）----------
# 开发时前端仍走 Vite dev server（vite.config.ts 把 /api 代理到本服务）；打包版由本服务
# 直接托管 frontend/dist，双击 exe 即可打开界面。挂载放在所有 API 路由**之后**，
# 保证 /api/* 与 /docs 优先匹配；前端未构建（dist 不存在）时跳过，纯 API 模式照常可用。
_FRONTEND_DIST = runtime_paths.project_root() / "frontend" / "dist"
if _FRONTEND_DIST.is_dir():
    app.mount("/", StaticFiles(directory=_FRONTEND_DIST, html=True), name="frontend")
