"""用户白名单：放过可信来源，但不删除证据。

命中白名单的记录不参与规则匹配（因此不产生告警），但原始记录仍保留在日志明细中，
并在检测覆盖度里单独计数为「已白名单」——不删证据，也不把「跳过判定」说成「没问题」。
"""

from __future__ import annotations

import ipaddress
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from ..database import DATABASE_PATH

# 白名单维度 → 记录字段
WHITELIST_KINDS: dict[str, str] = {
    "ip": "source_ip",
    "username": "username",
    "user_agent": "user_agent",
    "domain": "query_name",
    "process": "process_image",
    "path": "url",
    "port": "destination_port",
}

KIND_LABELS: dict[str, str] = {
    "ip": "IP / 网段",
    "username": "账号",
    "user_agent": "User-Agent",
    "domain": "域名",
    "process": "进程",
    "path": "路径",
    "port": "端口",
}


@dataclass(frozen=True)
class WhitelistEntry:
    id: int
    kind: str
    value: str
    note: str
    enabled: bool
    created_at: str


def _now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def match_value(kind: str, pattern: str, candidate: str) -> bool:
    """按维度比较。各维度语义不同，集中在这里定义以免口径漂移。"""

    pattern = pattern.strip()
    candidate = candidate.strip()
    if not pattern or not candidate:
        return False
    if kind == "ip":
        if "/" in pattern:
            try:
                network = ipaddress.ip_network(pattern, strict=False)
            except ValueError:
                return False
            try:
                return ipaddress.ip_address(candidate) in network
            except ValueError:
                return False
        return pattern == candidate
    if kind == "port":
        return pattern == candidate
    if kind == "path":
        # 前缀匹配：/health 同时覆盖 /health 与 /health/z，但不覆盖 /healthz
        base = pattern.rstrip("/")
        return candidate == base or candidate.startswith(base + "/")
    if kind == "domain":
        lowered = candidate.lower()
        base = pattern.lower().lstrip(".")
        return lowered == base or lowered.endswith("." + base)
    if kind == "process":
        # 进程白名单按路径尾部匹配，避免写死完整安装路径
        return candidate.lower().endswith(pattern.lower())
    if kind == "username":
        # 精确匹配：'admin' 不应连 'administrator' 一起放过
        return pattern.lower() == candidate.lower()
    # user_agent：包含匹配（UA 串很长，写全不现实）
    return pattern.lower() in candidate.lower()


class WhitelistMatcher:
    """编译后的白名单；逐记录返回命中的条目描述（用于展示与统计）。"""

    def __init__(self, entries: list[WhitelistEntry]) -> None:
        self._entries = [entry for entry in entries if entry.enabled]

    def __bool__(self) -> bool:
        return bool(self._entries)

    def match(self, record: dict[str, str | None]) -> str | None:
        for entry in self._entries:
            field = WHITELIST_KINDS.get(entry.kind)
            if not field:
                continue
            candidate = record.get(field)
            if candidate and match_value(entry.kind, entry.value, candidate):
                return f"{KIND_LABELS.get(entry.kind, entry.kind)}={entry.value}"
        return None


class WhitelistRepository:
    """白名单条目与变更审计的持久化。"""

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
                CREATE TABLE IF NOT EXISTS whitelist_entries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    kind TEXT NOT NULL,
                    value TEXT NOT NULL,
                    note TEXT NOT NULL DEFAULT '',
                    enabled INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS whitelist_changes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    action TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    value TEXT NOT NULL,
                    note TEXT NOT NULL DEFAULT '',
                    actor TEXT NOT NULL DEFAULT 'console',
                    created_at TEXT NOT NULL
                )
                """
            )
            connection.commit()

    def list_entries(self) -> list[WhitelistEntry]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT id, kind, value, note, enabled, created_at FROM whitelist_entries ORDER BY id DESC"
            ).fetchall()
        return [
            WhitelistEntry(
                id=row["id"],
                kind=row["kind"],
                value=row["value"],
                note=row["note"],
                enabled=bool(row["enabled"]),
                created_at=row["created_at"],
            )
            for row in rows
        ]

    def _audit(
        self,
        connection: sqlite3.Connection,
        action: str,
        kind: str,
        value: str,
        note: str = "",
    ) -> None:
        connection.execute(
            """
            INSERT INTO whitelist_changes (action, kind, value, note, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (action, kind, value, note, _now()),
        )

    def add(self, kind: str, value: str, note: str = "") -> WhitelistEntry:
        created_at = _now()
        with self.connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO whitelist_entries (kind, value, note, enabled, created_at)
                VALUES (?, ?, ?, 1, ?)
                """,
                (kind, value, note, created_at),
            )
            self._audit(connection, "add", kind, value, note)
            connection.commit()
            entry_id = int(cursor.lastrowid or 0)
        return WhitelistEntry(
            id=entry_id, kind=kind, value=value, note=note, enabled=True, created_at=created_at
        )

    def remove(self, entry_id: int) -> bool:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT kind, value, note FROM whitelist_entries WHERE id = ?", (entry_id,)
            ).fetchone()
            if row is None:
                return False
            connection.execute("DELETE FROM whitelist_entries WHERE id = ?", (entry_id,))
            self._audit(connection, "remove", row["kind"], row["value"], row["note"])
            connection.commit()
        return True

    def set_enabled(self, entry_id: int, enabled: bool) -> bool:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT kind, value, note FROM whitelist_entries WHERE id = ?", (entry_id,)
            ).fetchone()
            if row is None:
                return False
            connection.execute(
                "UPDATE whitelist_entries SET enabled = ? WHERE id = ?",
                (1 if enabled else 0, entry_id),
            )
            self._audit(
                connection, "enable" if enabled else "disable", row["kind"], row["value"], row["note"]
            )
            connection.commit()
        return True

    def recent_changes(self, limit: int = 50) -> list[dict[str, str]]:
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT action, kind, value, note, actor, created_at
                FROM whitelist_changes ORDER BY id DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]


# 与 database.repository 保持同一模式：进程内单例，测试通过 env 指向临时库
whitelist_repository = WhitelistRepository()
