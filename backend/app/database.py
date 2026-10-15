from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import runtime_paths
from .models import AnalysisResult, LogSummary

STATUS_PROCESSING = "processing"
STATUS_COMPLETED = "completed"
STATUS_FAILED = "failed"

DATABASE_PATH = Path(
    os.getenv("LOGINSIGHT_DB_PATH") or runtime_paths.data_root() / "loginsight.db"
)


class AnalysisRepository:
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
                CREATE TABLE IF NOT EXISTS analyses (
                    id TEXT PRIMARY KEY,
                    filename TEXT NOT NULL,
                    status TEXT NOT NULL,
                    risk_level TEXT NOT NULL,
                    log_type TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    result_json TEXT,
                    records_json TEXT,
                    error_message TEXT
                )
                """
            )
            # AI 任务状态落盘：进程内存版在服务重启后查不到、多 worker 之间也互相看不见
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS ai_tasks (
                    task_id TEXT PRIMARY KEY,
                    analysis_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    stage TEXT NOT NULL,
                    progress INTEGER NOT NULL,
                    error TEXT,
                    result_json TEXT,
                    partial_text TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            connection.commit()

    def create(
        self,
        analysis_id: str,
        filename: str,
        created_at: str,
    ) -> None:
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO analyses
                (id, filename, status, risk_level, log_type, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (analysis_id, filename, STATUS_PROCESSING, "info", "unknown", created_at, created_at),
            )
            connection.commit()

    def complete(
        self,
        result: AnalysisResult,
        records: list[dict[str, str | None]],
    ) -> None:
        now = result.created_at
        with self.connect() as connection:
            connection.execute(
                """
                UPDATE analyses
                SET status = ?, risk_level = ?, log_type = ?, updated_at = ?,
                    result_json = ?, records_json = ?, error_message = NULL
                WHERE id = ?
                """,
                (
                    STATUS_COMPLETED,
                    result.risk_level,
                    result.metadata.log_type,
                    now,
                    result.model_dump_json(),
                    json.dumps(records, ensure_ascii=False),
                    result.id,
                ),
            )
            connection.commit()

    def fail(self, analysis_id: str, error_message: str, updated_at: str) -> None:
        with self.connect() as connection:
            connection.execute(
                """
                UPDATE analyses
                SET status = ?, updated_at = ?, error_message = ?
                WHERE id = ?
                """,
                (STATUS_FAILED, updated_at, error_message, analysis_id),
            )
            connection.commit()

    def get(self, analysis_id: str) -> AnalysisResult | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT result_json FROM analyses WHERE id = ? AND status = ?",
                (analysis_id, STATUS_COMPLETED),
            ).fetchone()
        if not row or not row["result_json"]:
            return None
        return AnalysisResult.model_validate_json(row["result_json"])

    def get_records(self, analysis_id: str) -> list[dict[str, str | None]] | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT records_json FROM analyses WHERE id = ? AND status = ?",
                (analysis_id, STATUS_COMPLETED),
            ).fetchone()
        if not row or not row["records_json"]:
            return None
        return json.loads(row["records_json"])

    def get_record_page(
        self,
        analysis_id: str,
        page: int,
        page_size: int,
        source_ip: str | None = None,
        destination_ip: str | None = None,
        path: str | None = None,
        log_type: str | None = None,
        action: str | None = None,
        status: str | None = None,
        record_id: str | None = None,
    ) -> tuple[list[dict[str, str | None]], int]:
        records = self.get_records(analysis_id) or []
        result = self.get(analysis_id)
        if result is None:
            return [], 0
        def matches(record: dict[str, str | None]) -> bool:
            checks = (
                (source_ip, "source_ip"),
                (destination_ip, "destination_ip"),
                (action, "action"),
            )
            for expected, field in checks:
                if expected and expected.lower() not in (record.get(field) or "").lower():
                    return False
            if status:
                # status 同时兼容 Web 状态码与 SSH 等日志的 result（success / failure）
                haystack = f"{record.get('status') or ''} {record.get('result') or ''}".lower()
                if status.lower() not in haystack:
                    return False
            if path and path.lower() not in (record.get("url") or "").lower():
                return False
            if log_type and log_type.lower() != (record.get("log_type") or "").lower():
                return False
            if record_id and record_id != record.get("record_id"):
                return False
            return True

        filtered = [record for record in records if matches(record)]
        start = (page - 1) * page_size
        return filtered[start : start + page_size], len(filtered)

    def update_result(self, result: AnalysisResult) -> None:
        with self.connect() as connection:
            connection.execute(
                """
                UPDATE analyses
                SET risk_level = ?, updated_at = ?, result_json = ?
                WHERE id = ? AND status = ?
                """,
                (
                    result.risk_level,
                    result.created_at,
                    result.model_dump_json(),
                    result.id,
                    STATUS_COMPLETED,
                ),
            )
            connection.commit()

    def list(self) -> list[LogSummary]:
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT id, filename, status, risk_level, log_type, created_at,
                       updated_at, error_message
                FROM analyses
                ORDER BY created_at DESC
                """
            ).fetchall()
        return [LogSummary.model_validate(dict(row)) for row in rows]

    def ai_usage_history(self, limit: int = 50) -> list[dict[str, Any]]:
        """取最近的 AI 研判用量，用于前端展示跨分析的消耗趋势。

        **不做全表反序列化**：`result_json` 单条可达数百 KB，只为读一个用量字段
        而把 50 条完整结果读进内存既慢又浪费。这里用 SQLite 的 `json_each` 直接在
        库内定位 `ai_tool_trace` 里 `tool == "usage"` 的那一条，只把用量取出来。

        用量可能缺失（历史上降级路径会丢 trace），此时如实返回该条 `usage = None`，
        由前端跳过——不用 0 填充，避免把「没记录」画成「消耗为 0」。
        """

        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT a.id, a.filename, a.log_type, a.created_at,
                       (
                           SELECT je.value
                           FROM json_each(a.result_json, '$.ai_tool_trace') AS je
                           WHERE json_extract(je.value, '$.tool') = 'usage'
                           LIMIT 1
                       ) AS usage_json
                FROM analyses AS a
                WHERE a.status = ?
                  AND a.result_json IS NOT NULL
                  AND json_valid(a.result_json)
                ORDER BY a.created_at DESC
                LIMIT ?
                """,
                (STATUS_COMPLETED, limit),
            ).fetchall()

        history: list[dict[str, Any]] = []
        for row in rows:
            usage = None
            raw_usage = row["usage_json"]
            if raw_usage:
                try:
                    parsed = json.loads(raw_usage)
                except ValueError:
                    parsed = None
                if isinstance(parsed, dict):
                    usage = parsed.get("usage") if "usage" in parsed else parsed
            history.append(
                {
                    "analysis_id": row["id"],
                    "filename": row["filename"],
                    "log_type": row["log_type"],
                    "created_at": row["created_at"],
                    "usage": usage if isinstance(usage, dict) else None,
                }
            )
        return history

    def list_page(
        self,
        page: int,
        page_size: int,
        log_type: str | None = None,
        risk_level: str | None = None,
        status: str | None = None,
        keyword: str | None = None,
        sort: str = "created_desc",
    ) -> tuple[list[LogSummary], int, list[str]]:
        conditions: list[str] = []
        values: list[str] = []
        for field, value in (
            ("log_type", log_type),
            ("risk_level", risk_level),
            ("status", status),
        ):
            if value:
                conditions.append(f"{field} = ?")
                values.append(value)
        if keyword:
            conditions.append("(filename LIKE ? OR id LIKE ? OR log_type LIKE ?)")
            pattern = f"%{keyword}%"
            values.extend([pattern, pattern, pattern])
        where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
        offset = (page - 1) * page_size
        order_by = {
            "created_asc": "created_at ASC",
            "risk_desc": "CASE risk_level WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END ASC, created_at DESC",
            "risk_asc": "CASE risk_level WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END DESC, created_at DESC",
        }.get(sort, "created_at DESC")
        with self.connect() as connection:
            total = connection.execute(
                f"SELECT COUNT(*) FROM analyses{where}", values
            ).fetchone()[0]
            rows = connection.execute(
                f"""
                SELECT id, filename, status, risk_level, log_type, created_at,
                       updated_at, error_message
                FROM analyses
                {where}
                ORDER BY {order_by}
                LIMIT ? OFFSET ?
                """,
                [*values, page_size, offset],
            ).fetchall()
            available_types = [
                row[0]
                for row in connection.execute(
                    "SELECT DISTINCT log_type FROM analyses WHERE log_type != '' ORDER BY log_type"
                ).fetchall()
            ]
        return [LogSummary.model_validate(dict(row)) for row in rows], total, available_types

    def delete(self, analysis_id: str) -> bool:
        with self.connect() as connection:
            cursor = connection.execute(
                "DELETE FROM analyses WHERE id = ?", (analysis_id,)
            )
            connection.commit()
        return cursor.rowcount > 0

    def save_ai_task(self, task: dict[str, Any]) -> None:
        """写入 / 更新 AI 任务状态（同库另表，任何 worker 都能读到）。

        内存里的 `updated_at` 是 epoch 秒（按 TTL 清理用），落盘统一转成 ISO 字符串，
        保证 ``updated_at < cutoff`` 这种比较在同一口径下成立。
        """

        result = task.get("result")
        if isinstance(result, AnalysisResult):
            result_json = result.model_dump_json()
        elif result is None:
            result_json = None
        else:
            result_json = json.dumps(result, ensure_ascii=False)
        updated_at = task["updated_at"]
        if isinstance(updated_at, (int, float)):
            updated_at = datetime.fromtimestamp(updated_at, timezone.utc).isoformat()
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO ai_tasks
                (task_id, analysis_id, status, stage, progress, error, result_json,
                 partial_text, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(task_id) DO UPDATE SET
                    status = excluded.status,
                    stage = excluded.stage,
                    progress = excluded.progress,
                    error = excluded.error,
                    result_json = excluded.result_json,
                    partial_text = excluded.partial_text,
                    updated_at = excluded.updated_at
                """,
                (
                    task["task_id"],
                    task["analysis_id"],
                    task["status"],
                    task["stage"],
                    int(task.get("progress") or 0),
                    task.get("error"),
                    result_json,
                    task.get("partial") or None,
                    task["created_at"],
                    updated_at,
                ),
            )
            connection.commit()

    def get_ai_task(self, task_id: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM ai_tasks WHERE task_id = ?", (task_id,)
            ).fetchone()
        if row is None:
            return None
        return self._ai_task_from_row(row)

    @staticmethod
    def _ai_task_from_row(row: sqlite3.Row) -> dict[str, Any]:
        result: AnalysisResult | None = None
        if row["result_json"]:
            result = AnalysisResult.model_validate_json(row["result_json"])
        return {
            "task_id": row["task_id"],
            "analysis_id": row["analysis_id"],
            "status": row["status"],
            "stage": row["stage"],
            "progress": row["progress"],
            "error": row["error"],
            "result": result,
            "partial": row["partial_text"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def list_ai_tasks(self, status: str | None = None) -> list[dict[str, Any]]:
        query = "SELECT * FROM ai_tasks"
        values: tuple[str, ...] = ()
        if status:
            query += " WHERE status = ?"
            values = (status,)
        query += " ORDER BY updated_at ASC"
        with self.connect() as connection:
            rows = connection.execute(query, values).fetchall()
        return [self._ai_task_from_row(row) for row in rows]

    def prune_ai_tasks(self, cutoff: str) -> int:
        """删除已结束且更新时间早于截止时间的任务；运行中的任务永不删除。"""

        with self.connect() as connection:
            cursor = connection.execute(
                "DELETE FROM ai_tasks WHERE status != 'running' AND updated_at < ?",
                (cutoff,),
            )
            connection.commit()
        return cursor.rowcount


repository = AnalysisRepository()
