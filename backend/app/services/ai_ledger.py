from __future__ import annotations

import csv
import html
import io
import json
import sqlite3
from datetime import datetime
from pathlib import Path

from ..database import DATABASE_PATH
from ..models import AiLedger, AiToolCall, AnalysisResult
from .ai import check_ai_config


def _now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def build_ai_ledger(
    result: AnalysisResult,
    status: str,
    duration_ms: int = 0,
    created_at: str | None = None,
) -> AiLedger:
    config = check_ai_config()
    evidence_ids = sorted(
        {
            evidence_id
            for behavior in result.ai_behaviors
            for evidence_id in behavior.evidence_ids
        }
    )
    usage = next(
        (item.usage for item in result.ai_tool_trace if item.tool == "usage" and item.usage),
        None,
    )
    return AiLedger(
        analysis_id=result.id,
        created_at=created_at or _now(),
        status="completed" if status == "completed" else "unavailable",
        provider=config.provider,
        model=config.model,
        duration_ms=duration_ms,
        tool_trace=list(result.ai_tool_trace),
        evidence_ids=evidence_ids,
        unsupported_claims=list(result.ai_unsupported_claims),
        usage=usage,
        metrics=result.ai_metrics,
        summary=result.conclusion,
    )


class AiLedgerRepository:
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
                CREATE TABLE IF NOT EXISTS ai_ledgers (
                    analysis_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    status TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    model TEXT NOT NULL,
                    duration_ms INTEGER NOT NULL DEFAULT 0,
                    payload_json TEXT NOT NULL
                )
                """
            )
            connection.commit()

    def save(self, ledger: AiLedger) -> None:
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO ai_ledgers
                (analysis_id, created_at, status, provider, model, duration_ms, payload_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(analysis_id) DO UPDATE SET
                    created_at = excluded.created_at,
                    status = excluded.status,
                    provider = excluded.provider,
                    model = excluded.model,
                    duration_ms = excluded.duration_ms,
                    payload_json = excluded.payload_json
                """,
                (
                    ledger.analysis_id,
                    ledger.created_at,
                    ledger.status,
                    ledger.provider,
                    ledger.model,
                    ledger.duration_ms,
                    ledger.model_dump_json(),
                ),
            )
            connection.commit()

    def get(self, analysis_id: str) -> AiLedger | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT payload_json FROM ai_ledgers WHERE analysis_id = ?",
                (analysis_id,),
            ).fetchone()
        if row is None:
            return None
        return AiLedger.model_validate_json(row["payload_json"])


def render_ledger_json(ledger: AiLedger) -> str:
    return ledger.model_dump_json(indent=2)


def render_ledger_html(ledger: AiLedger) -> str:
    tools = "".join(
        "<li>"
        f"{html.escape(item.tool)} "
        f"({html.escape(item.source)}): {html.escape(item.summary)}"
        "</li>"
        for item in ledger.tool_trace
    )
    unsupported = "".join(
        f"<li>{html.escape(item)}</li>" for item in ledger.unsupported_claims
    )
    evidence = ", ".join(html.escape(item) for item in ledger.evidence_ids) or "-"
    usage = html.escape(json.dumps(ledger.usage, ensure_ascii=False)) if ledger.usage else "-"
    # 成本 × 质量联合指标：只记不展示等于没记，台账是它唯一的人读出口。
    # 摘要里明确标出「估算」——上下文体量是分摊值，不是服务端账单。
    metrics = (
        html.escape(json.dumps(ledger.metrics, ensure_ascii=False, indent=2))
        if ledger.metrics
        else "-"
    )
    return f"""<!doctype html>
<meta charset="utf-8">
<title>AI 研判审查台账</title>
<h1>AI 研判审查台账</h1>
<p>分析 ID：{html.escape(ledger.analysis_id)}</p>
<p>状态：{html.escape(ledger.status)} · 模型：{html.escape(ledger.provider)} / {html.escape(ledger.model)}</p>
<p>耗时：{ledger.duration_ms} ms</p>
<h2>结论摘要</h2>
<p>{html.escape(ledger.summary)}</p>
<h2>引用证据</h2>
<p>{evidence}</p>
<h2>工具调用</h2>
<ul>{tools}</ul>
<h2>被拦截的无效引用</h2>
<ul>{unsupported}</ul>
<h2>用量</h2>
<pre>{usage}</pre>
<h2>成本 × 质量指标</h2>
<p>其中 <code>context.estimated_input_tokens</code> 与 <code>event_tokens</code> /
<code>evidence_tokens</code> 是**按上下文体量估算**的分摊值，不是服务端账单；
<code>tokens</code> 与 <code>cost</code> 才是账单口径（未配置单价时 cost 为 null）。</p>
<pre>{metrics}</pre>
"""


def render_ledger_csv(ledger: AiLedger) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        [
            "analysis_id",
            "created_at",
            "status",
            "provider",
            "model",
            "duration_ms",
            "tool",
            "source",
            "summary",
        ]
    )
    if not ledger.tool_trace:
        writer.writerow(
            [
                ledger.analysis_id,
                ledger.created_at,
                ledger.status,
                ledger.provider,
                ledger.model,
                ledger.duration_ms,
                "",
                "",
                ledger.summary,
            ]
        )
    for item in ledger.tool_trace:
        writer.writerow(
            [
                ledger.analysis_id,
                ledger.created_at,
                ledger.status,
                ledger.provider,
                ledger.model,
                ledger.duration_ms,
                item.tool,
                item.source,
                item.summary,
            ]
        )
    return buffer.getvalue()


ai_ledger_repository = AiLedgerRepository()
