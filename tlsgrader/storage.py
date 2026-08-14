from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from .utils import is_current_methodology, json_dumps, utc_now_iso


class Storage:
    def __init__(self, database_path: Path):
        self.database_path = database_path
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self._write_lock = threading.Lock()
        self.initialize()

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.database_path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA foreign_keys=ON")
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def initialize(self) -> None:
        schema = """
        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            hostname TEXT NOT NULL,
            port INTEGER NOT NULL,
            country TEXT NOT NULL DEFAULT '',
            sector TEXT NOT NULL DEFAULT '',
            source TEXT NOT NULL DEFAULT 'manual',
            status TEXT NOT NULL,
            scan_time TEXT NOT NULL,
            overall_score REAL NOT NULL DEFAULT 0,
            grade TEXT NOT NULL DEFAULT 'F',
            certificate_score REAL,
            configuration_score REAL,
            assessment_version TEXT NOT NULL DEFAULT '',
            evidence_schema_version INTEGER,
            data_json TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_scans_time ON scans(scan_time DESC);
        CREATE INDEX IF NOT EXISTS idx_scans_group ON scans(country, sector);

        CREATE TABLE IF NOT EXISTS jobs (
            id TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            status TEXT NOT NULL,
            total INTEGER NOT NULL,
            completed INTEGER NOT NULL DEFAULT 0,
            failed INTEGER NOT NULL DEFAULT 0,
            current_target TEXT,
            message TEXT,
            payload_json TEXT NOT NULL,
            result_ids_json TEXT NOT NULL DEFAULT '[]'
        );

        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value_json TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS metadata (
            key TEXT PRIMARY KEY,
            integer_value INTEGER NOT NULL
        );
        """
        with self.connect() as connection:
            connection.executescript(schema)
            connection.execute(
                "INSERT OR IGNORE INTO metadata (key, integer_value) VALUES ('analysis_revision', 0)"
            )
            scan_columns = {
                row["name"] for row in connection.execute("PRAGMA table_info(scans)").fetchall()
            }
            for name, definition in {
                "certificate_score": "REAL",
                "configuration_score": "REAL",
                "assessment_version": "TEXT NOT NULL DEFAULT ''",
                "evidence_schema_version": "INTEGER",
            }.items():
                if name not in scan_columns:
                    connection.execute(f"ALTER TABLE scans ADD COLUMN {name} {definition}")
            job_columns = {
                row["name"] for row in connection.execute("PRAGMA table_info(jobs)").fetchall()
            }
            for name, definition in {
                "cancelled": "INTEGER NOT NULL DEFAULT 0",
                "inconclusive": "INTEGER NOT NULL DEFAULT 0",
                "next_index": "INTEGER NOT NULL DEFAULT 0",
                "first_error_code": "TEXT NOT NULL DEFAULT ''",
                "current_error_code": "TEXT NOT NULL DEFAULT ''",
                "first_error": "TEXT NOT NULL DEFAULT ''",
                "current_error": "TEXT NOT NULL DEFAULT ''",
                "diagnostic": "TEXT NOT NULL DEFAULT ''",
            }.items():
                if name not in job_columns:
                    connection.execute(f"ALTER TABLE jobs ADD COLUMN {name} {definition}")
            if "is_demo" in scan_columns:
                connection.execute("DELETE FROM scans WHERE is_demo = 1")
                connection.execute("ALTER TABLE scans DROP COLUMN is_demo")
            connection.execute(
                """UPDATE jobs
                   SET status = 'invalidated',
                       message = 'Invalidated: created before the batch progress callback fix; no network scan was performed',
                       updated_at = ?
                   WHERE status = 'completed_with_errors'
                     AND completed = 0
                     AND failed = total
                     AND result_ids_json = '[]'
                     AND message = 'Job finished'""",
                (utc_now_iso(),),
            )
            connection.execute("PRAGMA optimize")

    @staticmethod
    def _decorate_scan(data: dict[str, Any]) -> dict[str, Any]:
        data["methodology_status"] = (
            "current" if is_current_methodology(data) else "legacy_methodology"
        )
        return data

    @staticmethod
    def _bump_analysis_revision(connection: sqlite3.Connection) -> None:
        connection.execute(
            "UPDATE metadata SET integer_value = integer_value + 1 WHERE key = 'analysis_revision'"
        )

    def analysis_revision(self) -> int:
        """Return the transactionally maintained analysis/evidence revision."""
        with self.connect() as connection:
            row = connection.execute(
                "SELECT integer_value FROM metadata WHERE key = 'analysis_revision'"
            ).fetchone()
        return int(row[0])

    def save_scan(self, result: dict[str, Any]) -> str:
        scan_id = result.get("id") or str(uuid.uuid4())
        result["id"] = scan_id
        scores = result.get("scores", {})
        overall = scores.get("overall")
        row = (
            scan_id,
            result.get("hostname", ""),
            int(result.get("port", 443)),
            result.get("country", ""),
            result.get("sector", ""),
            result.get("source", "manual"),
            result.get("status", "completed"),
            result.get("scan_time", utc_now_iso()),
            float(overall) if isinstance(overall, (int, float)) else 0.0,
            scores.get("grade") or "N/A",
            scores.get("certificate") if isinstance(scores.get("certificate"), (int, float)) else None,
            scores.get("configuration") if isinstance(scores.get("configuration"), (int, float)) else None,
            str(result.get("assessment_version") or ""),
            result.get("evidence_schema_version") if isinstance(result.get("evidence_schema_version"), int) else None,
            json_dumps(result),
        )
        with self._write_lock, self.connect() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO scans
                (id, hostname, port, country, sector, source, status, scan_time,
                 overall_score, grade, certificate_score, configuration_score,
                 assessment_version, evidence_schema_version, data_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                row,
            )
            self._bump_analysis_revision(connection)
        return scan_id

    def list_scans(
        self,
        *,
        limit: int = 500,
        country: str = "",
        sector: str = "",
        search: str = "",
    ) -> list[dict[str, Any]]:
        conditions, parameters = [], []
        if country:
            conditions.append("country = ?")
            parameters.append(country)
        if sector:
            conditions.append("sector = ?")
            parameters.append(sector)
        if search:
            conditions.append("hostname LIKE ?")
            parameters.append(f"%{search}%")
        where = " WHERE " + " AND ".join(conditions) if conditions else ""
        query = f"SELECT * FROM scans{where} ORDER BY scan_time DESC"
        if int(limit) > 0:
            parameters.append(int(limit))
            query += " LIMIT ?"
        with self.connect() as connection:
            rows = connection.execute(query, parameters).fetchall()
        items = []
        for row in rows:
            data = json.loads(row["data_json"])
            items.append(self._decorate_scan(data))
        return items

    def list_scan_summaries(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        country: str = "",
        sector: str = "",
        search: str = "",
    ) -> dict[str, Any]:
        """Return lightweight scan rows and page metadata without parsing evidence JSON."""
        limit = max(1, min(int(limit), 1000))
        offset = max(0, int(offset))
        conditions: list[str] = []
        parameters: list[Any] = []
        if country:
            conditions.append("country = ?")
            parameters.append(country)
        if sector:
            conditions.append("sector = ?")
            parameters.append(sector)
        if search:
            conditions.append("hostname LIKE ?")
            parameters.append(f"%{search}%")
        where = " WHERE " + " AND ".join(conditions) if conditions else ""
        with self.connect() as connection:
            total = int(connection.execute(f"SELECT COUNT(*) FROM scans{where}", parameters).fetchone()[0])
            rows = connection.execute(
                f"""SELECT id, hostname, port, country, sector, source, status, scan_time,
                           overall_score, grade, certificate_score, configuration_score,
                           assessment_version, evidence_schema_version
                    FROM scans{where} ORDER BY scan_time DESC LIMIT ? OFFSET ?""",
                [*parameters, limit, offset],
            ).fetchall()
            countries = [
                row[0]
                for row in connection.execute(
                    "SELECT DISTINCT country FROM scans WHERE country <> '' ORDER BY country COLLATE NOCASE"
                ).fetchall()
            ]
            sectors = [
                row[0]
                for row in connection.execute(
                    "SELECT DISTINCT sector FROM scans WHERE sector <> '' ORDER BY sector COLLATE NOCASE"
                ).fetchall()
            ]
        items = []
        for row in rows:
            version = row["assessment_version"] or None
            items.append(
                {
                    "id": row["id"],
                    "hostname": row["hostname"],
                    "port": row["port"],
                    "country": row["country"],
                    "sector": row["sector"],
                    "source": row["source"],
                    "status": row["status"],
                    "scan_time": row["scan_time"],
                    "scores": {
                        "overall": row["overall_score"] if row["status"] == "completed" else None,
                        "grade": row["grade"],
                        "certificate": row["certificate_score"],
                        "configuration": row["configuration_score"],
                    },
                    "assessment_version": version,
                    "evidence_schema_version": row["evidence_schema_version"],
                    "methodology_status": (
                        "current"
                        if is_current_methodology(
                            {
                                "assessment_version": version,
                                "evidence_schema_version": row["evidence_schema_version"],
                            }
                        )
                        else "legacy_methodology"
                    ),
                }
            )
        return {
            "items": items,
            "count": len(items),
            "total": total,
            "limit": limit,
            "offset": offset,
            "available_labels": {"country": countries, "sector": sectors},
        }

    def get_scan(self, scan_id: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if not row:
            return None
        data = json.loads(row["data_json"])
        return self._decorate_scan(data)

    def delete_scan(self, scan_id: str) -> bool:
        with self._write_lock, self.connect() as connection:
            cursor = connection.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
            if cursor.rowcount:
                self._bump_analysis_revision(connection)
        return cursor.rowcount > 0

    def clear_scans(self) -> int:
        query = "DELETE FROM scans"
        with self._write_lock, self.connect() as connection:
            cursor = connection.execute(query)
            if cursor.rowcount:
                self._bump_analysis_revision(connection)
        return cursor.rowcount

    def reset_all(self) -> dict[str, int]:
        """Remove all user-created project state while preserving the database schema."""
        with self._write_lock, self.connect() as connection:
            counts = {
                "scans": connection.execute("SELECT COUNT(*) FROM scans").fetchone()[0],
                "jobs": connection.execute("SELECT COUNT(*) FROM jobs").fetchone()[0],
                "settings": connection.execute("SELECT COUNT(*) FROM settings").fetchone()[0],
            }
            connection.execute("DELETE FROM scans")
            connection.execute("DELETE FROM jobs")
            connection.execute("DELETE FROM settings")
            if counts["scans"]:
                self._bump_analysis_revision(connection)
        return counts

    def recover_interrupted_jobs(self) -> int:
        """Mark work left by a stopped server; background threads cannot resume it."""
        with self._write_lock, self.connect() as connection:
            cursor = connection.execute(
                """UPDATE jobs
                   SET status = 'interrupted',
                       message = 'Interrupted by a server stop or restart; resume from the saved checkpoint',
                       current_target = '',
                       updated_at = ?
                   WHERE status IN ('queued', 'running', 'cancelling')""",
                (utc_now_iso(),),
            )
        return cursor.rowcount

    def create_job(self, payload: dict[str, Any], total: int) -> str:
        job_id = str(uuid.uuid4())
        now = utc_now_iso()
        with self._write_lock, self.connect() as connection:
            connection.execute(
                """INSERT INTO jobs
                (id, created_at, updated_at, status, total, completed, failed,
                 current_target, message, payload_json, result_ids_json)
                VALUES (?, ?, ?, 'queued', ?, 0, 0, '', 'Queued', ?, '[]')""",
                (job_id, now, now, total, json_dumps(payload)),
            )
        return job_id

    def update_job(self, job_id: str, **changes: Any) -> None:
        allowed = {
            "status", "completed", "failed", "cancelled", "inconclusive", "next_index",
            "first_error_code", "current_error_code", "diagnostic", "current_target", "message",
            "first_error", "current_error",
            "result_ids_json", "payload_json",
        }
        fields, values = [], []
        for key, value in changes.items():
            if key in allowed:
                fields.append(f"{key} = ?")
                values.append(json_dumps(value) if key in {"result_ids_json", "payload_json"} and not isinstance(value, str) else value)
        if not fields:
            return
        fields.append("updated_at = ?")
        values.append(utc_now_iso())
        values.append(job_id)
        with self._write_lock, self.connect() as connection:
            connection.execute(f"UPDATE jobs SET {', '.join(fields)} WHERE id = ?", values)

    def get_job(self, job_id: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
        if not row:
            return None
        data = dict(row)
        data["payload"] = json.loads(data.pop("payload_json"))
        data["result_ids"] = json.loads(data.pop("result_ids_json"))
        terminal = data["completed"] + data["failed"] + data.get("cancelled", 0) + data.get("inconclusive", 0)
        data["percent"] = round(terminal / max(1, data["total"]) * 100, 1)
        data["cancellable"] = data["status"] in {"queued", "running"}
        data["resumable"] = data["status"] in {"cancelled", "interrupted"}
        return data

    def list_jobs(self, limit: int = 20) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute("SELECT id FROM jobs ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        return [job for row in rows if (job := self.get_job(row["id"]))]

    def set_setting(self, key: str, value: Any) -> None:
        with self._write_lock, self.connect() as connection:
            connection.execute(
                "INSERT OR REPLACE INTO settings (key, value_json, updated_at) VALUES (?, ?, ?)",
                (key, json_dumps(value), utc_now_iso()),
            )

    def get_setting(self, key: str, default: Any = None) -> Any:
        with self.connect() as connection:
            row = connection.execute("SELECT value_json FROM settings WHERE key = ?", (key,)).fetchone()
        return json.loads(row["value_json"]) if row else default
