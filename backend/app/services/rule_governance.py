from __future__ import annotations

import sqlite3
from dataclasses import replace
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

from ..database import DATABASE_PATH
from ..models import RuleAuditEntry, RulePreviewReport


def _now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


class RuleGovernanceRepository:
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
                CREATE TABLE IF NOT EXISTS rule_overrides (
                    rule_id TEXT PRIMARY KEY,
                    enabled INTEGER NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS rule_changes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    action TEXT NOT NULL,
                    rule_id TEXT NOT NULL,
                    before_value TEXT NOT NULL DEFAULT '',
                    after_value TEXT NOT NULL DEFAULT '',
                    actor TEXT NOT NULL DEFAULT 'console',
                    note TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL
                )
                """
            )
            connection.commit()

    def overrides(self) -> dict[str, bool]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT rule_id, enabled FROM rule_overrides"
            ).fetchall()
        return {row["rule_id"]: bool(row["enabled"]) for row in rows}

    def set_enabled(
        self, rule_id: str, enabled: bool, before: bool, actor: str = "console"
    ) -> None:
        now = _now()
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO rule_overrides (rule_id, enabled, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(rule_id) DO UPDATE SET
                    enabled = excluded.enabled,
                    updated_at = excluded.updated_at
                """,
                (rule_id, 1 if enabled else 0, now),
            )
            connection.execute(
                """
                INSERT INTO rule_changes
                (action, rule_id, before_value, after_value, actor, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                ("enable" if enabled else "disable", rule_id, str(before), str(enabled), actor, now),
            )
            connection.commit()

    def audit(self, limit: int = 100) -> list[RuleAuditEntry]:
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT id, action, rule_id, before_value AS before, after_value AS after,
                       actor, note, created_at
                FROM rule_changes
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [RuleAuditEntry.model_validate(dict(row)) for row in rows]

    def rollback(self, entry_id: int, actor: str = "console") -> bool:
        """把某条启用/停用记录回滚到它记下的「变更前」状态。

        只支持 `enable` / `disable` 两类：它们的 `before_value` 是布尔串，语义明确。
        回滚本身**追加**一条新记录而不是改写旧记录——审计链只增不改，才谈得上可追溯。
        """

        with self.connect() as connection:
            row = connection.execute(
                "SELECT action, rule_id, before_value, after_value FROM rule_changes WHERE id = ?",
                (entry_id,),
            ).fetchone()
            if row is None or row["action"] not in {"enable", "disable"}:
                return False
            enabled = row["before_value"] == "True"
            now = _now()
            connection.execute(
                """
                INSERT INTO rule_overrides (rule_id, enabled, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(rule_id) DO UPDATE SET
                    enabled = excluded.enabled,
                    updated_at = excluded.updated_at
                """,
                (row["rule_id"], 1 if enabled else 0, now),
            )
            connection.execute(
                """
                INSERT INTO rule_changes
                (action, rule_id, before_value, after_value, actor, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                ("rollback", row["rule_id"], row["after_value"], row["before_value"], actor, now),
            )
            connection.commit()
        return True


rule_governance_repository = RuleGovernanceRepository()


def apply_rule_overrides(rules: list[Any]) -> list[Any]:
    overrides = rule_governance_repository.overrides()
    if not overrides:
        return rules
    return [
        replace(rule, enabled=overrides[rule.id])
        if rule.id in overrides
        else rule
        for rule in rules
    ]


def _draft_rules(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        raise ValueError("规则草稿必须是 YAML/JSON 对象")
    if isinstance(payload.get("rules"), list):
        return payload["rules"]
    if isinstance(payload.get("rule"), dict):
        return [payload["rule"]]
    if payload.get("id"):
        return [payload]
    raise ValueError("规则草稿需要包含 rule、rules 或单条规则 id")


def parse_draft_rules(
    yaml_text: str | None,
    rule: dict[str, Any] | None,
    rules: list[dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    if yaml_text:
        loaded = yaml.safe_load(yaml_text) or {}
        return _draft_rules(loaded)
    if rules is not None:
        return rules
    if rule is not None:
        return [rule]
    raise ValueError("请提供 yaml_text、rule 或 rules")


def score_preview(
    rule_ids: set[str], expected: set[str], events: list[Any], covered_records: int
) -> RulePreviewReport:
    actual = {event.rule_id for event in events if event.rule_id}
    return RulePreviewReport(
        valid=True,
        rule_ids=sorted(rule_ids),
        event_count=len(events),
        covered_records=covered_records,
        true_positive=len(actual & expected) if expected else 0,
        false_positive=len(actual - expected) if expected else 0,
        false_negative=len(expected - actual) if expected else 0,
        rollback_required=False,
        events=events,
    )
