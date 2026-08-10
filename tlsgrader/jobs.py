from __future__ import annotations

import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from .scanner import scan_target
from .scoring import score_scan
from .storage import Storage
from .utils import normalize_host, safe_port, utc_now_iso


class JobManager:
    """Small local job queue. Scans are deliberately serial inside each job."""

    def __init__(self, storage: Storage, workers: int = 2):
        self.storage = storage
        self.executor = ThreadPoolExecutor(max_workers=max(1, min(workers, 4)), thread_name_prefix="tls-scan")
        self._lock = threading.Lock()
        self._running: set[str] = set()

    def submit(self, targets: list[dict[str, Any]], *, timeout: float = 5.0) -> str:
        if not targets:
            raise ValueError("A job must contain at least one target")
        mode = "full"
        cleaned = []
        for raw in targets:
            host = normalize_host(str(raw.get("hostname") or raw.get("host") or ""))
            cleaned.append(
                {
                    "hostname": host,
                    "port": safe_port(raw.get("port", 443)),
                    "country": str(raw.get("country", "")).strip(),
                    "sector": str(raw.get("sector", "")).strip(),
                    "source": str(raw.get("source", "manual")).strip() or "manual",
                }
            )
        payload = {"targets": cleaned, "mode": mode, "timeout": max(2.0, min(float(timeout), 15.0))}
        with self._lock:
            if self._running:
                raise ValueError("Another scan job is already running. Wait for it to finish before submitting a new batch.")
            job_id = self.storage.create_job(payload, len(cleaned))
            self._running.add(job_id)
        try:
            self.executor.submit(self._run, job_id, payload)
        except Exception:
            with self._lock:
                self._running.discard(job_id)
            raise
        return job_id

    def _run(self, job_id: str, payload: dict[str, Any]) -> None:
        completed = failed = 0
        result_ids: list[str] = []
        first_error = ""
        self.storage.update_job(job_id, status="running", message="Starting TLS scan")
        try:
            for index, target in enumerate(payload["targets"], 1):
                host = target["hostname"]

                def progress(message: str, percent: int = 0, *, _index: int = index, _host: str = host) -> None:
                    self.storage.update_job(
                        job_id,
                        current_target=_host,
                        message=f"[{_index}/{len(payload['targets'])}] {message} · {percent}%",
                    )

                try:
                    result = scan_target(
                        host,
                        port=target["port"],
                        mode=payload["mode"],
                        timeout=payload["timeout"],
                        country=target["country"],
                        sector=target["sector"],
                        source=target["source"],
                        progress=progress,
                    )
                    result_id = self.storage.save_scan(result)
                    result_ids.append(result_id)
                    if result.get("status") == "completed":
                        completed += 1
                    else:
                        failed += 1
                        if not first_error:
                            first_error = "; ".join(result.get("errors", [])[:1]) or "Target scan failed"
                except Exception as exc:  # A bad target must not stop a batch.
                    failed += 1
                    first_error = first_error or f"{type(exc).__name__}: {exc}"
                    failure = score_scan(
                        {
                            "id": str(uuid.uuid4()),
                            "hostname": host,
                            "port": target["port"],
                            "country": target["country"],
                            "sector": target["sector"],
                            "source": target["source"],
                            "mode": payload["mode"],
                            "scan_time": utc_now_iso(),
                            "status": "failed",
                            "certificate": {"trust_valid": None, "hostname_valid": None, "revocation_status": "unknown"},
                            "protocols": {},
                            "key_exchange": {},
                            "ciphers": {},
                            "errors": [first_error],
                        }
                    )
                    result_ids.append(self.storage.save_scan(failure))
                    progress(f"Failed: {type(exc).__name__}: {exc}", 100)
                self.storage.update_job(
                    job_id,
                    completed=completed,
                    failed=failed,
                    result_ids_json=result_ids,
                )
            status = "completed" if failed == 0 else "completed_with_errors"
            message = f"Job finished: {completed} completed, {failed} failed"
            if first_error:
                message += f" · first error: {first_error}"
            self.storage.update_job(job_id, status=status, current_target="", message=message)
        except Exception as exc:
            self.storage.update_job(job_id, status="failed", message=f"Job failed: {exc}")
        finally:
            with self._lock:
                self._running.discard(job_id)

    def active_count(self) -> int:
        with self._lock:
            return len(self._running)

    def shutdown(self) -> None:
        self.executor.shutdown(wait=True, cancel_futures=True)
