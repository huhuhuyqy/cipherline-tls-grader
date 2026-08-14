from __future__ import annotations

import inspect
import threading
import time
import uuid
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from typing import Any

from .scanner import scan_target
from .scoring import score_scan
from .storage import Storage
from .utils import normalize_host, safe_port, utc_now_iso


class JobManager:
    """One-job queue with bounded target concurrency and ordered durable checkpoints."""

    def __init__(self, storage: Storage, workers: int = 2, *, target_budget: float = 90.0):
        self.storage = storage
        self.workers = max(1, min(int(workers), 4))
        self.executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="tls-job")
        self.target_budget = max(2.0, float(target_budget))
        self._lock = threading.RLock()
        self._running: set[str] = set()
        self._cancel_events: dict[str, threading.Event] = {}
        self._accepting = True
        self._mutation_lock = threading.RLock()

    @property
    def mutation_lock(self) -> threading.RLock:
        return self._mutation_lock

    def submit(self, targets: list[dict[str, Any]], *, timeout: float = 5.0) -> str:
        if not targets:
            raise ValueError("A job must contain at least one target")
        cleaned = []
        for raw in targets:
            if not isinstance(raw, dict):
                raise ValueError("Every target must be an object")
            cleaned.append(
                {
                    "hostname": normalize_host(str(raw.get("hostname") or raw.get("host") or "")),
                    "port": safe_port(raw.get("port", 443)),
                    "country": str(raw.get("country", "")).strip(),
                    "sector": str(raw.get("sector", "")).strip(),
                    "source": str(raw.get("source", "manual")).strip() or "manual",
                }
            )
        payload = {
            "targets": cleaned,
            "mode": "full",
            "timeout": max(2.0, min(float(timeout), 15.0)),
            "target_budget": self.target_budget,
        }
        with self._mutation_lock, self._lock:
            if not self._accepting:
                raise RuntimeError("Job manager is shutting down and no longer accepts submissions")
            if self._running:
                raise ValueError("Another scan job is already running. Wait for it to finish before submitting a new batch.")
            job_id = self.storage.create_job(payload, len(cleaned))
            self._schedule(job_id, payload)
        return job_id

    def _schedule(self, job_id: str, payload: dict[str, Any]) -> None:
        event = threading.Event()
        self._cancel_events[job_id] = event
        self._running.add(job_id)
        try:
            self.executor.submit(self._run, job_id, payload, event)
        except Exception:
            self._cancel_events.pop(job_id, None)
            self._running.discard(job_id)
            raise

    def cancel(self, job_id: str) -> bool:
        with self._mutation_lock, self._lock:
            event = self._cancel_events.get(job_id)
            if not event:
                return False
            job = self.storage.get_job(job_id)
            if (
                not job
                or job.get("status") not in {"queued", "running"}
                or int(job.get("next_index", 0)) >= int(job.get("total", 0))
            ):
                return False
            event.set()
            self.storage.update_job(job_id, status="cancelling", message="Cancellation requested")
            return True

    def resume(self, job_id: str) -> str:
        with self._mutation_lock, self._lock:
            if not self._accepting:
                raise RuntimeError("Job manager is shutting down and cannot resume work")
            if self._running:
                raise ValueError("Another scan job is already running. Wait for it to finish before resuming.")
            job = self.storage.get_job(job_id)
            if not job or not job.get("resumable"):
                raise ValueError("Only cancelled or interrupted jobs can be resumed")
            payload = job["payload"]
            self.storage.update_job(
                job_id,
                status="queued",
                cancelled=0,
                current_error_code="",
                current_error="",
                current_target="",
                message="Queued for resume",
            )
            self._schedule(job_id, payload)
        return job_id

    @staticmethod
    def _failure(host: str, target: dict[str, Any], diagnostic: str) -> dict[str, Any]:
        return score_scan(
            {
                "id": str(uuid.uuid4()),
                "hostname": host,
                "port": target["port"],
                "country": target["country"],
                "sector": target["sector"],
                "source": target["source"],
                "mode": "full",
                "assessment_version": "2.3",
                "evidence_schema_version": 2,
                "scan_time": utc_now_iso(),
                "status": "failed",
                "error_code": "SCAN_EXCEPTION",
                "diagnostic": diagnostic,
                "certificate": {"trust_valid": None, "hostname_valid": None, "revocation_status": "unknown"},
                "protocols": {},
                "key_exchange": {},
                "ciphers": {},
                "errors": ["The target assessment failed unexpectedly."],
            }
        )

    @staticmethod
    def _scan_kwargs(target: dict[str, Any], payload: dict[str, Any], progress, event: threading.Event) -> dict[str, Any]:
        kwargs = {
            "port": target["port"],
            "mode": payload["mode"],
            "timeout": payload["timeout"],
            "country": target["country"],
            "sector": target["sector"],
            "source": target["source"],
            "progress": progress,
        }
        try:
            parameters = inspect.signature(scan_target).parameters
        except (TypeError, ValueError):
            parameters = {}
        supports_extra = any(item.kind == inspect.Parameter.VAR_KEYWORD for item in parameters.values())
        if supports_extra or "deadline" in parameters:
            kwargs["deadline"] = time.monotonic() + float(payload.get("target_budget", 90.0))
        if supports_extra or "cancel" in parameters:
            kwargs["cancel"] = event.is_set
        return kwargs

    def _assess_target(
        self,
        job_id: str,
        zero_index: int,
        total: int,
        target: dict[str, Any],
        payload: dict[str, Any],
        event: threading.Event,
    ) -> dict[str, Any] | None:
        """Collect one target without persisting it; the coordinator commits in order."""
        if event.is_set():
            return None
        index = zero_index + 1
        host = target["hostname"]

        def progress(message: str, percent: int = 0) -> None:
            if not event.is_set():
                self.storage.update_job(
                    job_id,
                    current_target=host,
                    message=f"[{index}/{total}] {message} · {percent}%",
                )

        current_error_code = ""
        current_error = ""
        diagnostic = ""
        try:
            result = scan_target(host, **self._scan_kwargs(target, payload, progress, event))
        except Exception as exc:  # A bad target must not stop a batch.
            diagnostic = f"{type(exc).__name__}: {exc}"
            current_error_code = "SCAN_EXCEPTION"
            current_error = "Target assessment failed unexpectedly."
            result = self._failure(host, target, diagnostic)
        return {
            "result": result,
            "current_error_code": current_error_code,
            "current_error": current_error,
            "diagnostic": diagnostic,
        }

    def _run(self, job_id: str, payload: dict[str, Any], event: threading.Event) -> None:
        job = self.storage.get_job(job_id) or {}
        completed = int(job.get("completed", 0))
        failed = int(job.get("failed", 0))
        inconclusive = int(job.get("inconclusive", 0))
        result_ids = list(job.get("result_ids", []))
        first_error_code = str(job.get("first_error_code", ""))
        first_error = str(job.get("first_error", ""))
        next_index = int(job.get("next_index", 0))
        self.storage.update_job(job_id, status="running", message="Starting TLS scan")
        try:
            targets = payload["targets"]
            total = len(targets)
            next_to_submit = next_index
            next_to_persist = next_index
            buffered: dict[int, dict[str, Any]] = {}
            inflight: dict[Future, int] = {}

            with ThreadPoolExecutor(max_workers=self.workers, thread_name_prefix="tls-target") as target_pool:
                def fill_window() -> None:
                    nonlocal next_to_submit
                    window_end = min(total, next_to_persist + self.workers)
                    while (
                        not event.is_set()
                        and next_to_submit < window_end
                        and len(inflight) < self.workers
                    ):
                        zero_index = next_to_submit
                        future = target_pool.submit(
                            self._assess_target,
                            job_id,
                            zero_index,
                            total,
                            targets[zero_index],
                            payload,
                            event,
                        )
                        inflight[future] = zero_index
                        next_to_submit += 1

                fill_window()
                while inflight:
                    finished, _ = wait(tuple(inflight), return_when=FIRST_COMPLETED)
                    for future in finished:
                        zero_index = inflight.pop(future)
                        assessment = future.result()
                        if assessment is None or assessment["result"].get("status") == "cancelled":
                            event.set()
                        else:
                            buffered[zero_index] = assessment

                    if event.is_set():
                        for future in inflight:
                            future.cancel()
                        break

                    while next_to_persist in buffered:
                        assessment = buffered.pop(next_to_persist)
                        result = assessment["result"]
                        status = result.get("status")
                        current_error_code = assessment["current_error_code"]
                        current_error = assessment["current_error"]
                        diagnostic = assessment["diagnostic"]
                        # The job/position identity makes a checkpoint retry idempotent if
                        # the process stops after the scan row is committed but before the
                        # job checkpoint is committed.
                        result["id"] = str(
                            uuid.uuid5(uuid.NAMESPACE_URL, f"cipherline-job:{job_id}:{next_to_persist}")
                        )
                        result_id = self.storage.save_scan(result)
                        result_ids.append(result_id)
                        if status == "completed":
                            completed += 1
                        elif status == "inconclusive":
                            inconclusive += 1
                            current_error_code = str(result.get("error_code") or "ASSESSMENT_INCONCLUSIVE")
                            current_error = "Target assessment was inconclusive."
                            diagnostic = "; ".join(result.get("errors", [])[:1])
                        else:
                            failed += 1
                            current_error_code = current_error_code or str(result.get("error_code") or "SCAN_FAILED")
                            current_error = current_error or "Target assessment failed."
                            diagnostic = diagnostic or "; ".join(result.get("errors", [])[:1])
                        first_error_code = first_error_code or current_error_code
                        first_error = first_error or current_error
                        next_to_persist += 1
                        self.storage.update_job(
                            job_id,
                            completed=completed,
                            failed=failed,
                            inconclusive=inconclusive,
                            next_index=next_to_persist,
                            first_error_code=first_error_code,
                            current_error_code=current_error_code,
                            first_error=first_error,
                            current_error=current_error,
                            diagnostic=diagnostic,
                            result_ids_json=result_ids,
                        )
                    fill_window()

            if event.is_set():
                remaining = max(0, total - next_to_persist)
                self.storage.update_job(
                    job_id,
                    status="cancelled",
                    current_target="",
                    cancelled=remaining,
                    message=f"Job cancelled: {next_to_persist} of {total} target(s) checkpointed",
                )
                return
            job = self.storage.get_job(job_id) or {}
            failed_total = int(job.get("failed", 0))
            inconclusive_total = int(job.get("inconclusive", 0))
            status = "completed" if failed_total == 0 and inconclusive_total == 0 else "completed_with_errors"
            message = f"Job finished: {completed} completed, {failed_total} failed, {inconclusive_total} inconclusive"
            self.storage.update_job(job_id, status=status, current_target="", message=message)
        except Exception as exc:
            self.storage.update_job(
                job_id,
                status="failed",
                current_error_code="JOB_EXCEPTION",
                first_error_code=first_error_code or "JOB_EXCEPTION",
                first_error=first_error or "The job failed unexpectedly.",
                current_error="The job failed unexpectedly.",
                diagnostic=f"{type(exc).__name__}: {exc}",
                message="Job failed unexpectedly",
            )
        finally:
            with self._lock:
                self._cancel_events.pop(job_id, None)
                self._running.discard(job_id)

    def active_count(self) -> int:
        with self._lock:
            return len(self._running)

    def shutdown(self) -> None:
        with self._mutation_lock, self._lock:
            self._accepting = False
            for event in self._cancel_events.values():
                event.set()
        self.executor.shutdown(wait=True, cancel_futures=True)
