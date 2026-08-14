from __future__ import annotations

import argparse
import ipaddress
import json
import mimetypes
import secrets
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


def _is_loopback(host: str) -> bool:
    if host.casefold() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class LocalApp:
    def __init__(self, database_path: Path, *, recover: bool = True):
        self.storage = Storage(database_path)
        if recover:
            self.storage.recover_interrupted_jobs()
        self.jobs = JobManager(self.storage)
        self.csrf_token = secrets.token_urlsafe(32)
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
        result = analyse(
            self.storage.list_scans(limit=0),
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

    def shutdown(self) -> None:
        self.jobs.shutdown()


class AppServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(
        self,
        address,
        handler,
        *,
        app: LocalApp,
        bind_host: str,
    ):
        self.app = app
        self.bind_host = bind_host
        self.local_only = True
        super().__init__(address, handler)


class Handler(BaseHTTPRequestHandler):
    server_version = f"TLSGraderLocal/{__version__}"

    @property
    def app(self) -> LocalApp:
        return self.server.app  # type: ignore[attr-defined]

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

    def _json(self, data: Any, status: int = 200) -> None:
        self._bytes(json_dumps(data).encode("utf-8"), "application/json; charset=utf-8", status)

    def _error(self, status: int, code: str, message: str, *, diagnostic: str = "") -> None:
        payload: dict[str, Any] = {"error": {"code": code, "message": message}, "status": status}
        if diagnostic:
            payload["diagnostic"] = diagnostic
        self._json(payload, status)

    def _allowed_host(self) -> bool:
        value = self.headers.get("Host", "").strip()
        if not value or any(character in value for character in "\r\n/@"):
            return False
        hostname = value
        if value.startswith("["):
            hostname = value[1:value.find("]")] if "]" in value else ""
        elif value.count(":") <= 1:
            hostname = value.rsplit(":", 1)[0] if ":" in value else value
        hostname = hostname.casefold().rstrip(".")
        return _is_loopback(hostname)

    def _validate_request(self, *, mutating: bool = False) -> bool:
        if not self._allowed_host():
            self._error(421, "HOST_NOT_ALLOWED", "The request Host is not allowed")
            return False
        if not mutating:
            return True
        if self.headers.get_content_type() != "application/json":
            self._error(415, "CONTENT_TYPE_REQUIRED", "Mutating requests require application/json")
            return False
        supplied_csrf = self.headers.get("X-CSRF-Token", "")
        if not supplied_csrf or not secrets.compare_digest(supplied_csrf, self.app.csrf_token):
            self._error(403, "CSRF_TOKEN_INVALID", "The CSRF session token is missing or invalid")
            return False
        origin = self.headers.get("Origin")
        if origin and origin.rstrip("/").casefold() != f"http://{self.headers.get('Host')}".casefold():
            self._error(403, "ORIGIN_NOT_ALLOWED", "The request Origin does not match this local service")
            return False
        return True

    def _body(self) -> dict[str, Any]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValueError("Invalid Content-Length") from exc
        if length < 0 or length > 20_000_000:
            raise ValueError("Request body must not exceed 20 MB")
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
        if not self._validate_request():
            return
        parsed = urlparse(self.path)
        path, query = parsed.path, parse_qs(parsed.query)
        try:
            if path == "/api/health":
                return self._json(
                    {
                        "status": "ok",
                        "version": __version__,
                        "local_only": self.server.local_only,  # type: ignore[attr-defined]
                        "active_jobs": self.app.jobs.active_count(),
                        "csrf_token": self.app.csrf_token,
                    }
                )
            if path == "/api/capabilities":
                return self._json(scanner_capabilities())
            if path == "/api/scans":
                country = query.get("country", [""])[0]
                sector = query.get("sector", [""])[0]
                search = query.get("search", [""])[0]
                if query.get("summary", [""])[0] in {"1", "true"}:
                    return self._json(
                        self.app.storage.list_scan_summaries(
                            limit=int(query.get("limit", [100])[0]),
                            offset=int(query.get("offset", [0])[0]),
                            country=country,
                            sector=sector,
                            search=search,
                        )
                    )
                scans = self.app.storage.list_scans(
                    limit=int(query.get("limit", [500])[0]),
                    country=country,
                    sector=sector,
                    search=search,
                )
                return self._json({"items": scans, "count": len(scans)})
            if path.startswith("/api/scans/"):
                item = self.app.storage.get_scan(path.rsplit("/", 1)[-1])
                return self._json(item) if item else self._error(404, "SCAN_NOT_FOUND", "Scan not found")
            if path == "/api/jobs":
                return self._json({"items": self.app.storage.list_jobs()})
            if path.startswith("/api/jobs/"):
                job = self.app.storage.get_job(path.rsplit("/", 1)[-1])
                return self._json(job) if job else self._error(404, "JOB_NOT_FOUND", "Job not found")
            if path == "/api/analysis":
                return self._json(
                    self.app.get_analysis(
                        compare_field=query.get("compare_field", [""])[0],
                        group_a=query.get("group_a", [""])[0],
                        group_b=query.get("group_b", [""])[0],
                        strata=tuple(query.get("stratum", [])),
                    )
                )
            if path in {"/api/export.csv", "/api/export.html"}:
                scans = self.app.storage.list_scans(limit=0)
                analysis = self.app.get_analysis(
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
            return self._error(400, "INVALID_REQUEST", "The request parameters are invalid", diagnostic=f"{type(exc).__name__}: {exc}")
        except Exception as exc:
            return self._error(500, "INTERNAL_ERROR", "The local service could not complete the request", diagnostic=f"{type(exc).__name__}: {exc}")

    def do_POST(self) -> None:
        if not self._validate_request(mutating=True):
            return
        path = urlparse(self.path).path
        try:
            body = self._body()
            if path == "/api/scan":
                job_id = self.app.jobs.submit([body], timeout=body.get("timeout", 5))
                return self._json({"job_id": job_id, "status": "queued"}, HTTPStatus.ACCEPTED)
            if path == "/api/jobs":
                targets = body.get("targets")
                if not isinstance(targets, list):
                    raise ValueError("targets must be a list")
                if not all(isinstance(target, dict) for target in targets):
                    raise ValueError("every target must be an object")
                job_id = self.app.jobs.submit(targets, timeout=body.get("timeout", 5))
                return self._json({"job_id": job_id, "status": "queued"}, HTTPStatus.ACCEPTED)
            if path.startswith("/api/jobs/") and path.endswith("/cancel"):
                job_id = path.split("/")[-2]
                if not self.app.jobs.cancel(job_id):
                    return self._error(409, "JOB_NOT_CANCELLABLE", "The job is not currently cancellable")
                return self._json({"job_id": job_id, "status": "cancelling"}, HTTPStatus.ACCEPTED)
            if path.startswith("/api/jobs/") and path.endswith("/resume"):
                job_id = path.split("/")[-2]
                resumed = self.app.jobs.resume(job_id)
                return self._json({"job_id": resumed, "status": "queued"}, HTTPStatus.ACCEPTED)
            if path == "/api/data/clear":
                if body.get("confirm") != "DELETE ALL":
                    return self._error(400, "RESET_CONFIRMATION_INVALID", 'Confirmation must be exactly "DELETE ALL"')
                with self.app.jobs.mutation_lock:
                    if self.app.jobs.active_count():
                        return self._error(409, "JOB_ACTIVE", "A scan is still running; cancel or finish it before reset")
                    return self._json({"reset": self.app.storage.reset_all()})
            return self._error(404, "ROUTE_NOT_FOUND", "Route not found")
        except (ValueError, TypeError) as exc:
            return self._error(400, "INVALID_REQUEST", "The request body is invalid", diagnostic=f"{type(exc).__name__}: {exc}")
        except RuntimeError as exc:
            return self._error(503, "SERVICE_STOPPING", "The service is not accepting work", diagnostic=f"{type(exc).__name__}: {exc}")
        except Exception as exc:
            return self._error(500, "INTERNAL_ERROR", "The local service could not complete the request", diagnostic=f"{type(exc).__name__}: {exc}")

    def do_DELETE(self) -> None:
        if not self._validate_request(mutating=True):
            return
        path = urlparse(self.path).path
        if path.startswith("/api/scans/"):
            deleted = self.app.storage.delete_scan(path.rsplit("/", 1)[-1])
            return self._json({"deleted": deleted}) if deleted else self._error(404, "SCAN_NOT_FOUND", "Scan not found")
        return self._error(404, "ROUTE_NOT_FOUND", "Route not found")

    def _serve_static(self, path: str) -> None:
        relative = "index.html" if path in {"", "/"} else path.lstrip("/")
        target = (WEB_ROOT / relative).resolve()
        if WEB_ROOT.resolve() not in target.parents and target != WEB_ROOT.resolve():
            return self._error(403, "PATH_FORBIDDEN", "Forbidden path")
        if not target.is_file():
            target = WEB_ROOT / "index.html" if "." not in relative else target
        if not target.is_file():
            return self._error(404, "FILE_NOT_FOUND", "File not found")
        mime = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        if mime.startswith("text/") or mime in {"application/javascript", "application/json"}:
            mime += "; charset=utf-8"
        self._bytes(target.read_bytes(), mime)


def create_app(database_path: Path, *, recover: bool = False) -> LocalApp:
    """Create isolated application state; importing this module never opens the production DB."""
    return LocalApp(Path(database_path), recover=recover)


def create_server(
    database_path: Path,
    *,
    host: str = "127.0.0.1",
    port: int = 8843,
    auth_token: str | None = None,
    allowed_hosts: set[str] | None = None,
    recover: bool = False,
) -> AppServer:
    if not _is_loopback(host):
        raise ValueError("CIPHERLINE only supports a loopback bind address")
    app = create_app(database_path, recover=recover)
    try:
        return AppServer(
            (host, port),
            Handler,
            app=app,
            bind_host=host,
        )
    except Exception:
        app.shutdown()
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the local P3 TLS Grader research console")
    parser.add_argument("--host", default="127.0.0.1", help="Loopback bind address")
    parser.add_argument("--port", type=int, default=8843)
    parser.add_argument("--open", action="store_true", help="Open the dashboard in the default browser")
    args = parser.parse_args()
    ensure_directories(ROOT)
    server = create_server(
        DATA_ROOT / "tls_grader.db",
        host=args.host,
        port=args.port,
        recover=True,
    )
    url = f"http://{args.host}:{args.port}"
    print(f"CIPHERLINE v{__version__} is running at {url}")
    print("Press Ctrl+C to stop. Scan data stays in data/tls_grader.db")
    if args.open:
        threading.Timer(0.7, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping local server.")
    finally:
        server.app.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
