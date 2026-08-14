from __future__ import annotations

import ipaddress
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


CURRENT_ASSESSMENT_VERSION = "2.3"
CURRENT_EVIDENCE_SCHEMA_VERSION = 2


def is_current_methodology(value: dict[str, Any]) -> bool:
    """Return whether evidence matches the complete current assessment contract."""
    return (
        value.get("assessment_version") == CURRENT_ASSESSMENT_VERSION
        and value.get("evidence_schema_version") == CURRENT_EVIDENCE_SCHEMA_VERSION
    )


HOST_RE = re.compile(
    r"^(?=.{1,253}\.?$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.?$"
)


def utc_now_iso() -> str:
    # Microsecond precision keeps rapid rescans ordered while remaining ISO 8601
    # and lexicographically sortable in SQLite and exported evidence.
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def normalize_host(value: str) -> str:
    """Return an ASCII hostname without scheme, path, brackets, or trailing dot."""
    raw = (value or "").strip()
    if not raw:
        raise ValueError("Hostname is required")
    parsed = urlparse(raw if "://" in raw else f"//{raw}", scheme="https")
    host = parsed.hostname or ""
    host = host.rstrip(".")
    if not host:
        raise ValueError("Could not parse hostname")
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Invalid internationalized hostname") from exc
    if not HOST_RE.fullmatch(ascii_host):
        raise ValueError("Invalid hostname")
    return ascii_host.lower()


def safe_port(value: Any) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("Port must be an integer") from exc
    if not 1 <= port <= 65535:
        raise ValueError("Port must be between 1 and 65535")
    return port


def clamp(value: float, low: float = 0.0, high: float = 100.0) -> float:
    return max(low, min(high, value))


def json_dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)


def ensure_directories(root: Path) -> None:
    for name in ("data", "exports", "logs"):
        (root / name).mkdir(parents=True, exist_ok=True)
