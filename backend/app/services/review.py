from __future__ import annotations

import sqlite3
from datetime import datetime
from pathlib import Path

from ..database import DATABASE_PATH
from ..models import HumanReview, ReviewEntry, ReviewStatus

# 导出与界面共用的中文标签；只在这里维护一份，避免两处对不上。
REVIEW_LABELS: dict[str, str] = {
    "pending": "未确认",
    "confirmed": "确认",
    "rejected": "否定",
    "needs_review": "需复核",
}


def _now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


class ReviewRepository:
    """AI 结论的人工确认记录。

    追加式写入：每次确认新增一行，当前状态取最新一行。刻意不做「覆盖式更新」——
    「谁在什么时候把结论从确认改成了否定」本身就是要留证的研判过程，不能丢。
    """

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
                CREATE TABLE IF NOT EXISTS analysis_reviews (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    analysis_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    reviewer TEXT NOT NULL,
                    note TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_analysis_reviews_analysis "
                "ON analysis_reviews(analysis_id, id)"
            )
            connection.commit()

    def record(
        self, analysis_id: str, status: ReviewStatus, reviewer: str, note: str = ""
    ) -> HumanReview:
        with self.connect() as connection:
            connection.execute(
                "INSERT INTO analysis_reviews "
                "(analysis_id, status, reviewer, note, created_at) VALUES (?, ?, ?, ?, ?)",
                (analysis_id, status, reviewer, note, _now()),
            )
            connection.commit()
        return self.get(analysis_id)

    def get(self, analysis_id: str) -> HumanReview:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT id, status, reviewer, note, created_at FROM analysis_reviews "
                "WHERE analysis_id = ? ORDER BY id",
                (analysis_id,),
            ).fetchall()
        history = [
            ReviewEntry(
                id=row["id"],
                status=row["status"],
                reviewer=row["reviewer"],
                note=row["note"],
                created_at=row["created_at"],
            )
            for row in rows
        ]
        latest = history[-1] if history else None
        return HumanReview(
            analysis_id=analysis_id,
            status=latest.status if latest else "pending",
            reviewer=latest.reviewer if latest else "",
            note=latest.note if latest else "",
            updated_at=latest.created_at if latest else None,
            history=history,
        )

    def delete(self, analysis_id: str) -> None:
        with self.connect() as connection:
            connection.execute(
                "DELETE FROM analysis_reviews WHERE analysis_id = ?", (analysis_id,)
            )
            connection.commit()


review_repository = ReviewRepository()
