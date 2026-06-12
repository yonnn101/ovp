"""SQLite persistence for OVP attack attempts and assessments."""

from __future__ import annotations

import sqlite3
from datetime import datetime

from Core.evidence import AssessmentReport
from Core.verdict import Verdict

DB_PATH = "Analytics/ovp_dataset.db"

_RAW_RESPONSE_LIMIT = 1000


class AnalyticsStore:
    """Persist assessments and individual attack attempts to SQLite."""

    def __init__(self, db_path: str = DB_PATH) -> None:
        self.db_path = db_path
        # A single long-lived connection so that an in-memory database
        # (":memory:") survives across method calls — a fresh connection
        # would get its own empty in-memory DB.
        self._conn = sqlite3.connect(db_path)
        self._conn.row_factory = sqlite3.Row
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        return self._conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS assessments (
                    id TEXT PRIMARY KEY,
                    finding_id TEXT,
                    finding_type TEXT,
                    target_url TEXT,
                    severity TEXT,
                    final_verdict TEXT,
                    confidence TEXT,
                    score REAL,
                    modules_run INTEGER,
                    duration_s REAL,
                    created_at TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS attack_attempts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    assessment_id TEXT,
                    module_name TEXT,
                    payload_id TEXT,
                    payload_category TEXT,
                    payload_content TEXT,
                    verdict TEXT,
                    confidence TEXT,
                    score REAL,
                    reasoning TEXT,
                    judge_used TEXT,
                    latency_ms REAL,
                    raw_response TEXT,
                    created_at TEXT,
                    FOREIGN KEY(assessment_id) REFERENCES assessments(id)
                )
                """
            )

    def save_assessment(self, report: AssessmentReport) -> None:
        """Persist an assessment and all of its attack attempts atomically."""
        final = report.final_verdict
        assessment_row = (
            report.assessment_id,
            report.finding.id,
            report.finding.type,
            report.finding.target_url,
            report.finding.severity,
            final.verdict.value,
            final.confidence.value,
            final.score,
            len(report.module_reports),
            report.duration_s,
            report.created_at.isoformat(),
        )

        attempt_rows = []
        for module in report.module_reports:
            for result in module.results:
                v = result.verdict
                raw_response = (result.raw_response or "")[:_RAW_RESPONSE_LIMIT]
                attempt_rows.append(
                    (
                        report.assessment_id,
                        module.module_name,
                        result.payload.id,
                        result.payload.category,
                        result.payload.content,
                        v.verdict.value,
                        v.confidence.value,
                        v.score,
                        v.reasoning,
                        v.judge_used,
                        result.latency_ms,
                        raw_response,
                        result.timestamp.isoformat(),
                    )
                )

        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO assessments (
                    id, finding_id, finding_type, target_url, severity,
                    final_verdict, confidence, score, modules_run,
                    duration_s, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                assessment_row,
            )
            conn.executemany(
                """
                INSERT INTO attack_attempts (
                    assessment_id, module_name, payload_id, payload_category,
                    payload_content, verdict, confidence, score, reasoning,
                    judge_used, latency_ms, raw_response, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                attempt_rows,
            )

    def get_summary(self) -> dict:
        """Return cumulative metrics across all stored attack attempts."""
        exploitable = Verdict.EXPLOITABLE.value

        with self._connect() as conn:
            total_assessments = conn.execute(
                "SELECT COUNT(*) FROM assessments"
            ).fetchone()[0]

            total_payloads = conn.execute(
                "SELECT COUNT(*) FROM attack_attempts"
            ).fetchone()[0]

            exploitable_count = conn.execute(
                "SELECT COUNT(*) FROM attack_attempts WHERE verdict = ?",
                (exploitable,),
            ).fetchone()[0]

            most_effective_row = conn.execute(
                """
                SELECT payload_id, COUNT(*) AS hits
                FROM attack_attempts
                WHERE verdict = ?
                GROUP BY payload_id
                ORDER BY hits DESC, payload_id ASC
                LIMIT 1
                """,
                (exploitable,),
            ).fetchone()

            most_vulnerable_row = conn.execute(
                """
                SELECT a.target_url, COUNT(*) AS hits
                FROM attack_attempts t
                JOIN assessments a ON a.id = t.assessment_id
                WHERE t.verdict = ?
                GROUP BY a.target_url
                ORDER BY hits DESC, a.target_url ASC
                LIMIT 1
                """,
                (exploitable,),
            ).fetchone()

            module_rows = conn.execute(
                """
                SELECT
                    module_name,
                    COUNT(*) AS total,
                    SUM(CASE WHEN verdict = ? THEN 1 ELSE 0 END) AS exploitable
                FROM attack_attempts
                GROUP BY module_name
                ORDER BY module_name ASC
                """,
                (exploitable,),
            ).fetchall()

        exploit_rate = (
            exploitable_count / total_payloads * 100 if total_payloads else 0.0
        )

        by_module: dict[str, dict] = {}
        for row in module_rows:
            total = row["total"] or 0
            hits = row["exploitable"] or 0
            by_module[row["module_name"]] = {
                "total": total,
                "exploitable": hits,
                "rate": (hits / total * 100 if total else 0.0),
            }

        return {
            "total_assessments": total_assessments,
            "total_payloads": total_payloads,
            "exploitable_count": exploitable_count,
            "exploit_rate": exploit_rate,
            "most_effective_payload": (
                most_effective_row["payload_id"] if most_effective_row else "N/A"
            ),
            "most_vulnerable_target": (
                most_vulnerable_row["target_url"] if most_vulnerable_row else "N/A"
            ),
            "by_module": by_module,
        }
