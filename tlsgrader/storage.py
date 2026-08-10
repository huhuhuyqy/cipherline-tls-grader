from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from .utils import json_dumps, utc_now_iso


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
        """
        with self.connect() as connection:
            connection.executescript(schema)
            scan_columns = {
                row["name"] for row in connection.execute("PRAGMA table_info(scans)").fetchall()
            }
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

    def analysis_revision(self) -> str:
        """Return a compact fingerprint of columns that can change analysis output."""
        with self.connect() as connection:
            rows = connection.execute(
                """SELECT id, scan_time, country, sector, status, overall_score
                   FROM scans ORDER BY id"""
            ).fetchall()
        digest = hashlib.sha256()
        for row in rows:
            digest.update(json_dumps(tuple(row)).encode("utf-8"))
        return digest.hexdigest()

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
            json_dumps(result),
        )
        with self._write_lock, self.connect() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO scans
                (id, hostname, port, country, sector, source, status, scan_time,
                 overall_score, grade, data_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                row,
            )
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
            items.append(data)
        return items

    def get_scan(self, scan_id: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if not row:
            return None
        data = json.loads(row["data_json"])
        return data

    def delete_scan(self, scan_id: str) -> bool:
        with self._write_lock, self.connect() as connection:
            cursor = connection.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        return cursor.rowcount > 0

    def clear_scans(self) -> int:
        query = "DELETE FROM scans"
        with self._write_lock, self.connect() as connection:
            cursor = connection.execute(query)
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
        return counts

    def recover_interrupted_jobs(self) -> int:
        """Mark work left by a stopped server; background threads cannot resume it."""
        with self._write_lock, self.connect() as connection:
            cursor = connection.execute(
                """UPDATE jobs
                   SET status = 'interrupted',
                       message = 'Interrupted by a server stop or restart; submit this batch again',
                       current_target = '',
                       updated_at = ?
                   WHERE status IN ('queued', 'running')""",
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
        allowed = {"status", "completed", "failed", "current_target", "message", "result_ids_json"}
        fields, values = [], []
        for key, value in changes.items():
            if key in allowed:
                fields.append(f"{key} = ?")
                values.append(json_dumps(value) if key == "result_ids_json" and not isinstance(value, str) else value)
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
        data["percent"] = round((data["completed"] + data["failed"]) / max(1, data["total"]) * 100, 1)
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
