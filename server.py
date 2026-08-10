from __future__ import annotations

import argparse
import json
import mimetypes
import threading
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from tlsgrader import __version__
from tlsgrader.analysis import analyse
from tlsgrader.jobs import JobManager
from tlsgrader.reporting import report_html, scans_csv
from tlsgrader.scanner import scanner_capabilities
from tlsgrader.storage import Storage
from tlsgrader.utils import ensure_directories, json_dumps


ROOT = Path(__file__).resolve().parent
WEB_ROOT = ROOT / "web"
DATA_ROOT = ROOT / "data"
EXPORT_ROOT = ROOT / "exports"
ensure_directories(ROOT)


class LocalApp:
    def __init__(self, database_path: Path):
        self.storage = Storage(database_path)
        self.storage.recover_interrupted_jobs()
        self.jobs = JobManager(self.storage)
        self._analysis_cache: dict[tuple[Any, ...], dict[str, Any]] = {}
        self._analysis_lock = threading.Lock()

    def get_analysis(
        self,
        *,
        compare_field: str = "",
        group_a: str = "",
        group_b: str = "",
        strata: tuple[str, ...] | None = None,
    ) -> dict[str, Any]:
        revision = self.storage.analysis_revision()
        key = (revision, compare_field, group_a, group_b, strata)
        with self._analysis_lock:
            cached = self._analysis_cache.get(key)
        if cached is not None:
            return cached
        scans = self.storage.list_scans(limit=0)
        result = analyse(
            scans,
            compare_field=compare_field,
            group_a=group_a,
            group_b=group_b,
            strata=strata,
        )
        with self._analysis_lock:
            if len(self._analysis_cache) >= 32:
                self._analysis_cache.clear()
            self._analysis_cache[key] = result
        return result


APP = LocalApp(DATA_ROOT / "tls_grader.db")


class Handler(BaseHTTPRequestHandler):
    server_version = "TLSGraderLocal/1.3.2"

    def log_message(self, format: str, *args) -> None:
        print(f"[{self.log_date_time_string()}] {format % args}")

    def _headers(self, status: int, content_type: str, length: int, *, attachment: str = "") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", "no-store" if content_type.startswith("application/json") else "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; img-src 'self' data:; connect-src 'self'")
        if attachment:
            self.send_header("Content-Disposition", f'attachment; filename="{attachment}"')
        self.end_headers()

    def _bytes(self, body: bytes, content_type: str, status: int = 200, attachment: str = "") -> None:
        self._headers(status, content_type, len(body), attachment=attachment)
        self.wfile.write(body)

    def _json(self, data, status: int = 200) -> None:
        self._bytes(json_dumps(data).encode("utf-8"), "application/json; charset=utf-8", status)

    def _error(self, status: int, message: str) -> None:
        self._json({"error": message, "status": status}, status)

    def _body(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValueError("Invalid Content-Length") from exc
        if length > 20_000_000:
            raise ValueError("Request body exceeds 20 MB")
        raw = self.rfile.read(length)
        if not raw:
            return {}
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError("Malformed JSON body") from exc
        if not isinstance(value, dict):
            raise ValueError("JSON body must be an object")
        return value

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path, query = parsed.path, parse_qs(parsed.query)
        try:
            if path == "/api/health":
                return self._json({"status": "ok", "version": __version__, "local_only": True, "active_jobs": APP.jobs.active_count()})
            if path == "/api/capabilities":
                return self._json(scanner_capabilities())
            if path == "/api/scans":
                scans = APP.storage.list_scans(
                    limit=int(query.get("limit", [500])[0]),
                    country=query.get("country", [""])[0], sector=query.get("sector", [""])[0],
                    search=query.get("search", [""])[0],
                )
                return self._json({"items": scans, "count": len(scans)})
            if path.startswith("/api/scans/"):
                item = APP.storage.get_scan(path.rsplit("/", 1)[-1])
                return self._json(item) if item else self._error(404, "Scan not found")
            if path == "/api/jobs":
                return self._json({"items": APP.storage.list_jobs()})
            if path.startswith("/api/jobs/"):
                job = APP.storage.get_job(path.rsplit("/", 1)[-1])
                return self._json(job) if job else self._error(404, "Job not found")
            if path == "/api/analysis":
                return self._json(
                    APP.get_analysis(
                        compare_field=query.get("compare_field", [""])[0],
                        group_a=query.get("group_a", [""])[0],
                        group_b=query.get("group_b", [""])[0],
                        strata=tuple(query.get("stratum", [])),
                    )
                )
            if path in {"/api/export.csv", "/api/export.html"}:
                scans = APP.storage.list_scans(limit=0)
                analysis = APP.get_analysis(
                    compare_field=query.get("compare_field", [""])[0],
                    group_a=query.get("group_a", [""])[0],
                    group_b=query.get("group_b", [""])[0],
                    strata=tuple(query.get("stratum", [])),
                )
                if path.endswith(".csv"):
                    return self._bytes(scans_csv(scans).encode("utf-8-sig"), "text/csv; charset=utf-8", attachment="tls-results.csv")
                return self._bytes(report_html(scans, analysis).encode("utf-8"), "text/html; charset=utf-8", attachment="tls-research-report.html")
            return self._serve_static(path)
        except (ValueError, TypeError) as exc:
            return self._error(400, str(exc))
        except Exception as exc:
            return self._error(500, f"Internal error: {exc}")

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        try:
            body = self._body()
            if path == "/api/scan":
                job_id = APP.jobs.submit([body], timeout=body.get("timeout", 5))
                return self._json({"job_id": job_id}, HTTPStatus.ACCEPTED)
            if path == "/api/jobs":
                targets = body.get("targets")
                if not isinstance(targets, list):
                    raise ValueError("targets must be a list")
                job_id = APP.jobs.submit(targets, timeout=body.get("timeout", 5))
                return self._json({"job_id": job_id}, HTTPStatus.ACCEPTED)
            if path == "/api/data/clear":
                if body.get("confirm") != "DELETE ALL":
                    raise ValueError('Confirmation must be exactly "DELETE ALL"')
                if APP.jobs.active_count():
                    raise ValueError("A scan is still running. Wait for it to finish before resetting the project.")
                return self._json({"reset": APP.storage.reset_all()})
            return self._error(404, "Route not found")
        except (ValueError, TypeError) as exc:
            return self._error(400, str(exc))
        except Exception as exc:
            return self._error(500, f"Internal error: {exc}")

    def do_DELETE(self) -> None:
        path = urlparse(self.path).path
        if path.startswith("/api/scans/"):
            deleted = APP.storage.delete_scan(path.rsplit("/", 1)[-1])
            return self._json({"deleted": deleted}) if deleted else self._error(404, "Scan not found")
        return self._error(404, "Route not found")

    def _serve_static(self, path: str) -> None:
        relative = "index.html" if path in {"", "/"} else path.lstrip("/")
        target = (WEB_ROOT / relative).resolve()
        if WEB_ROOT.resolve() not in target.parents and target != WEB_ROOT.resolve():
            return self._error(403, "Forbidden")
        if not target.is_file():
            target = WEB_ROOT / "index.html" if "." not in relative else target
        if not target.is_file():
            return self._error(404, "File not found")
        mime = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        if mime.startswith("text/") or mime in {"application/javascript", "application/json"}:
            mime += "; charset=utf-8"
        self._bytes(target.read_bytes(), mime)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the local P3 TLS Grader research console")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address; keep 127.0.0.1 for local-only use")
    parser.add_argument("--port", type=int, default=8843)
    parser.add_argument("--open", action="store_true", help="Open the dashboard in the default browser")
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    url = f"http://{args.host}:{args.port}"
    print(f"CIPHERLINE v{__version__} is running locally at {url}")
    print("Press Ctrl+C to stop. Scan data stays in data/tls_grader.db")
    if args.open:
        threading.Timer(0.7, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping local server.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
