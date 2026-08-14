from __future__ import annotations

import os
import http.client
import ipaddress
import queue
import re
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urljoin, urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa
from cryptography.x509 import ocsp
from cryptography.x509 import AuthorityInformationAccessOID, ExtensionOID

from .scoring import score_scan
from .utils import (
    CURRENT_ASSESSMENT_VERSION,
    CURRENT_EVIDENCE_SCHEMA_VERSION,
    normalize_host,
    safe_port,
    utc_now_iso,
)


ProgressCallback = Callable[[str, int], None]
CancelCallback = Callable[[], bool]

ASSESSMENT_VERSION = CURRENT_ASSESSMENT_VERSION
EVIDENCE_SCHEMA_VERSION = CURRENT_EVIDENCE_SCHEMA_VERSION
SCANNER_METHOD_VERSION = "2.3"

PROTOCOL_VERSIONS: list[tuple[str, str]] = [
    ("TLS 1.3", "TLSv1_3"),
    ("TLS 1.2", "TLSv1_2"),
    ("TLS 1.1", "TLSv1_1"),
    ("TLS 1.0", "TLSv1"),
]


def _notify(callback: ProgressCallback | None, message: str, percent: int) -> None:
    if callback:
        callback(message, percent)


def _remaining(deadline: float | None, fallback: float) -> float:
    if deadline is None:
        return max(0.001, fallback)
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("Network operation deadline expired")
    return max(0.001, min(fallback, remaining))


def _getaddrinfo_with_budget(
    host: str,
    port: int,
    *,
    deadline: float | None,
    cancel: CancelCallback | None,
) -> list[tuple[Any, ...]]:
    """Resolve in a daemon worker so a stuck OS resolver cannot exceed budget."""
    result: queue.Queue[tuple[bool, Any]] = queue.Queue(maxsize=1)

    def resolve() -> None:
        try:
            value = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            result.put_nowait((True, value))
        except BaseException as exc:
            try:
                result.put_nowait((False, exc))
            except queue.Full:
                pass

    threading.Thread(target=resolve, name="tlsgrader-dns", daemon=True).start()
    while True:
        if cancel is not None and cancel():
            raise InterruptedError("DNS resolution cancelled")
        if deadline is not None and time.monotonic() >= deadline:
            raise TimeoutError("DNS resolution deadline expired")
        wait = 0.05 if deadline is None else min(0.05, max(0.001, deadline - time.monotonic()))
        try:
            ok, value = result.get(timeout=wait)
        except queue.Empty:
            continue
        if ok:
            return value
        raise value


def _read_response_body(
    response: Any,
    *,
    max_bytes: int,
    deadline: float | None,
    cancel: CancelCallback | None,
    sock: socket.socket | ssl.SSLSocket | None = None,
) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        if cancel is not None and cancel():
            raise InterruptedError("HTTP response reading cancelled")
        remaining = _remaining(deadline, 1.0)
        if sock is not None:
            sock.settimeout(remaining)
        chunk = response.read(min(64 * 1024, max_bytes + 1 - total))
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        total += len(chunk)
        if total > max_bytes:
            raise ValueError(f"HTTP response exceeded the {max_bytes}-byte safety limit")


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(
        self,
        hostname: str,
        pinned_ip: str,
        port: int,
        timeout: float,
        *,
        deadline: float | None,
        cancel: CancelCallback | None,
    ):
        super().__init__(hostname, port=port, timeout=timeout)
        self._pinned_ip = pinned_ip
        self._operation_timeout = timeout
        self._deadline = deadline
        self._cancel = cancel

    def connect(self) -> None:
        if self._cancel is not None and self._cancel():
            raise InterruptedError("HTTP connection cancelled")
        self.sock = socket.create_connection(
            (self._pinned_ip, self.port),
            _remaining(self._deadline, self._operation_timeout),
        )


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(
        self,
        hostname: str,
        pinned_ip: str,
        port: int,
        timeout: float,
        *,
        deadline: float | None,
        cancel: CancelCallback | None,
    ):
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        super().__init__(hostname, port=port, timeout=timeout, context=context)
        self._pinned_ip = pinned_ip
        self._operation_timeout = timeout
        self._deadline = deadline
        self._cancel = cancel

    def connect(self) -> None:
        if self._cancel is not None and self._cancel():
            raise InterruptedError("HTTPS connection cancelled")
        raw = socket.create_connection(
            (self._pinned_ip, self.port),
            _remaining(self._deadline, self._operation_timeout),
        )
        try:
            # The socket goes to the validated IP, while SNI and certificate
            # identity remain the original URL hostname.
            if self._cancel is not None and self._cancel():
                raise InterruptedError("HTTPS handshake cancelled")
            raw.settimeout(_remaining(self._deadline, self._operation_timeout))
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except Exception:
            raw.close()
            raise


def _http_request_pinned(
    *,
    scheme: str,
    hostname: str,
    pinned_ip: str,
    port: int,
    path: str,
    method: str,
    body: bytes | None,
    headers: dict[str, str],
    timeout: float,
    deadline: float | None,
    cancel: CancelCallback | None,
    max_bytes: int,
) -> tuple[int, dict[str, str], bytes]:
    operation_timeout = _remaining(deadline, timeout)
    connection: http.client.HTTPConnection
    if scheme == "https":
        connection = _PinnedHTTPSConnection(
            hostname,
            pinned_ip,
            port,
            operation_timeout,
            deadline=deadline,
            cancel=cancel,
        )
    else:
        connection = _PinnedHTTPConnection(
            hostname,
            pinned_ip,
            port,
            operation_timeout,
            deadline=deadline,
            cancel=cancel,
        )

    def prepare_phase() -> None:
        if cancel is not None and cancel():
            raise InterruptedError("HTTP request cancelled")
        phase_timeout = _remaining(deadline, timeout)
        if connection.sock is not None:
            connection.sock.settimeout(phase_timeout)

    try:
        connection.connect()
        prepare_phase()
        connection.request(method, path, body=body, headers=headers)
        prepare_phase()
        response = connection.getresponse()
        prepare_phase()
        response_headers = {key.lower(): value for key, value in response.getheaders()}
        response_body = _read_response_body(
            response,
            max_bytes=max_bytes,
            deadline=deadline,
            cancel=cancel,
            sock=connection.sock,
        )
        return response.status, response_headers, response_body
    finally:
        connection.close()


def _safe_http_fetch(
    url: str,
    *,
    timeout: float,
    deadline: float | None = None,
    cancel: CancelCallback | None = None,
    method: str = "GET",
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
    max_bytes: int = 2_000_000,
    max_redirects: int = 3,
) -> tuple[bytes, str]:
    """Fetch from a public pinned IP and manually validate every redirect hop."""
    operation_deadline = time.monotonic() + max(0.001, timeout)
    if deadline is not None:
        operation_deadline = min(operation_deadline, deadline)
    current_url = url
    request_method = method.upper()
    request_body = body
    for redirect_count in range(max_redirects + 1):
        if cancel is not None and cancel():
            raise InterruptedError("HTTP fetch cancelled")
        _remaining(operation_deadline, timeout)
        parsed = urlsplit(current_url)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            raise ValueError("unsupported or malformed HTTP(S) URL")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("URL user information is not permitted")
        scheme = parsed.scheme.lower()
        hostname = parsed.hostname.rstrip(".")
        port = parsed.port or (443 if scheme == "https" else 80)
        try:
            literal = ipaddress.ip_address(hostname)
            addresses = [str(literal)]
        except ValueError:
            answers = _getaddrinfo_with_budget(
                hostname,
                port,
                deadline=operation_deadline,
                cancel=cancel,
            )
            addresses = sorted(
                {item[4][0] for item in answers},
                key=lambda value: (ipaddress.ip_address(value).version, int(ipaddress.ip_address(value))),
            )
        if not addresses:
            raise ValueError("hostname resolution returned no address")
        non_public = [address for address in addresses if not ipaddress.ip_address(address).is_global]
        if non_public:
            raise ValueError("non-public address blocked: " + ", ".join(non_public))
        pinned_ip = addresses[0]
        default_port = 443 if scheme == "https" else 80
        host_value = f"[{hostname}]" if ":" in hostname else hostname
        if port != default_port:
            host_value = f"{host_value}:{port}"
        request_headers = {
            "User-Agent": "TLSGraderLocal/2.3",
            "Accept": "*/*",
            "Connection": "close",
            **(headers or {}),
            "Host": host_value,
        }
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        status, response_headers, response_body = _http_request_pinned(
            scheme=scheme,
            hostname=hostname,
            pinned_ip=pinned_ip,
            port=port,
            path=path,
            method=request_method,
            body=request_body,
            headers=request_headers,
            timeout=_remaining(operation_deadline, timeout),
            deadline=operation_deadline,
            cancel=cancel,
            max_bytes=max_bytes,
        )
        if status in {301, 302, 303, 307, 308}:
            location = response_headers.get("location")
            if not location:
                raise ValueError("redirect response omitted Location")
            if request_method != "GET" and status not in {307, 308}:
                raise ValueError("unsafe redirect for non-GET revocation request")
            if redirect_count >= max_redirects:
                raise ValueError("too many revocation-service redirects")
            current_url = urljoin(current_url, location)
            continue
        if not 200 <= status < 300:
            raise ValueError(f"revocation service returned HTTP {status}")
        return response_body, current_url
    raise ValueError("too many revocation-service redirects")


def locate_openssl() -> str | None:
    configured = os.environ.get("OPENSSL_BINARY")
    candidates = [
        configured,
        shutil.which("openssl"),
        r"C:\Program Files\Git\usr\bin\openssl.exe",
        r"C:\Program Files\OpenSSL-Win64\bin\openssl.exe",
        "/usr/bin/openssl",
        "/opt/homebrew/bin/openssl",
    ]
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return str(Path(candidate))
    return None


def scanner_capabilities() -> dict[str, Any]:
    openssl_binary = locate_openssl()
    openssl_version = None
    if openssl_binary:
        try:
            openssl_version = subprocess.run(
                [openssl_binary, "version"],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            ).stdout.strip()
        except Exception:
            openssl_version = "Detected, version query failed"
    paths = ssl.get_default_verify_paths()
    return {
        "python_ssl": ssl.OPENSSL_VERSION,
        "openssl_binary": openssl_binary,
        "openssl_version": openssl_version,
        "trust_store": paths.cafile or paths.openssl_cafile or "system default",
        "scanner_method_version": SCANNER_METHOD_VERSION,
        "protocol_probe": ["TLS 1.3", "TLS 1.2", "TLS 1.1", "TLS 1.0", "SSL 3.0", "SSL 2.0"],
        "protocol_probe_capabilities": {
            "TLS 1.3": "python_ssl" if hasattr(ssl.TLSVersion, "TLSv1_3") else "not_available",
            "TLS 1.2": "python_ssl" if hasattr(ssl.TLSVersion, "TLSv1_2") else "not_available",
            "TLS 1.1": "openssl_s_client" if openssl_binary else "not_available",
            "TLS 1.0": "openssl_s_client" if openssl_binary else "not_available",
            "SSL 3.0": "raw_client_hello",
            "SSL 2.0": "raw_client_hello",
        },
        "ssl2_ssl3": "raw_client_hello_probe",
        "full_cipher_enumeration_limit": None,
        "cipher_candidate_method": "All TLS <=1.2 cipher candidates configurable by the local Python ssl provider via ALL:eNULL:@SECLEVEL=0",
        "cipher_candidate_provider": ssl.OPENSSL_VERSION,
        "probe_provider": openssl_version or "Python ssl sockets where applicable",
        "provider_alignment": (
            "same_version" if openssl_version and ssl.OPENSSL_VERSION in openssl_version
            else "candidate and command-line probe providers may differ; versions are recorded with each observation"
        ),
        "active_alpn_offer": ["h2", "http/1.1"],
        "compression_probe": "not_tested_by_modern_client",
        "secure_renegotiation_probe": "observed_only",
        "certificate_chain_without_time_probe": (
            "openssl_s_client_verify_return_error_no_check_time"
            if openssl_binary else "not_available"
        ),
    }


def _connect(
    host: str,
    port: int,
    timeout: float,
    *,
    verify: bool,
    minimum: ssl.TLSVersion | None = None,
    maximum: ssl.TLSVersion | None = None,
    cipher: str | None = None,
    server_hostname: str | None = None,
) -> tuple[ssl.SSLSocket, socket.socket]:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # Chain validation and hostname identity are separate evidence dimensions.
    context.check_hostname = False
    context.verify_mode = ssl.CERT_REQUIRED if verify else ssl.CERT_NONE
    if verify:
        context.load_default_certs()
    context.set_alpn_protocols(["h2", "http/1.1"])
    if minimum is not None:
        context.minimum_version = minimum
    if maximum is not None:
        context.maximum_version = maximum
    if cipher:
        context.set_ciphers(f"{cipher}:@SECLEVEL=0")
    else:
        try:
            context.set_ciphers("ALL:@SECLEVEL=0")
        except ssl.SSLError:
            pass
    raw = None
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
        raw.settimeout(timeout)
        wrapped = context.wrap_socket(raw, server_hostname=server_hostname or host)
        return wrapped, raw
    except Exception:
        if raw is not None:
            raw.close()
        raise


def _basic_handshake(
    host: str,
    port: int,
    timeout: float,
    verify: bool,
    *,
    server_hostname: str | None = None,
) -> dict[str, Any]:
    sock = None
    try:
        sock, _ = _connect(host, port, timeout, verify=verify, server_hostname=server_hostname)
        cipher = sock.cipher()
        return {
            "ok": True,
            "certificate_der": sock.getpeercert(binary_form=True),
            "certificate_dict": sock.getpeercert(),
            "protocol": sock.version(),
            "cipher": cipher[0] if cipher else None,
            "cipher_bits": cipher[2] if cipher else None,
            "alpn": sock.selected_alpn_protocol(),
            "peer_address": sock.getpeername()[0],
        }
    except ssl.SSLCertVerificationError as exc:
        verify_code = getattr(exc, "verify_code", None)
        error_kind = "certificate_validity" if verify_code in {9, 10} else "certificate_verification"
        return {
            "ok": False,
            "error": f"{type(exc).__name__}: {exc}",
            "error_kind": error_kind,
            "verify_code": verify_code,
            "peer_address": host,
        }
    except ssl.SSLError as exc:
        return {
            "ok": False,
            "error": f"{type(exc).__name__}: {exc}",
            "error_kind": "tls_handshake",
            "ssl_reason": getattr(exc, "reason", None),
            "peer_address": host,
        }
    except (socket.timeout, TimeoutError, ConnectionError, OSError) as exc:
        return {
            "ok": False,
            "error": f"{type(exc).__name__}: {exc}",
            "error_kind": "transport",
            "peer_address": host,
        }
    except Exception as exc:
        return {
            "ok": False,
            "error": f"{type(exc).__name__}: {exc}",
            "error_kind": "unknown",
            "peer_address": host,
        }
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


def _x509_names(name: x509.Name) -> str:
    return ", ".join(f"{attribute.oid._name or attribute.oid.dotted_string}={attribute.value}" for attribute in name)


def _extension(cert: x509.Certificate, oid: x509.ObjectIdentifier):
    try:
        return cert.extensions.get_extension_for_oid(oid).value
    except x509.ExtensionNotFound:
        return None


def _certificate_details(der: bytes, trust_valid: bool | None, trust_error: str | None) -> tuple[dict[str, Any], x509.Certificate]:
    cert = x509.load_der_x509_certificate(der)
    now = datetime.now(timezone.utc)
    not_before = cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before.replace(tzinfo=timezone.utc)
    not_after = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after.replace(tzinfo=timezone.utc)
    days_remaining = int((not_after - now).total_seconds() // 86400)
    validity_status = "not_yet_valid" if now < not_before else "expired" if now > not_after else "valid"

    common_names = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    common_name = common_names[0].value if common_names else None
    san_extension = _extension(cert, ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    sans = san_extension.get_values_for_type(x509.DNSName) if san_extension else []
    ip_sans = [str(value) for value in san_extension.get_values_for_type(x509.IPAddress)] if san_extension else []

    public_key = cert.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        key_type, key_bits = "RSA", public_key.key_size
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        key_type, key_bits = "EC", public_key.key_size
    elif isinstance(public_key, dsa.DSAPublicKey):
        key_type, key_bits = "DSA", public_key.key_size
    elif isinstance(public_key, ed25519.Ed25519PublicKey):
        key_type, key_bits = "Ed25519", 256
    elif isinstance(public_key, ed448.Ed448PublicKey):
        key_type, key_bits = "Ed448", 448
    else:
        key_type, key_bits = type(public_key).__name__, getattr(public_key, "key_size", None)

    aia = _extension(cert, ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
    ocsp_uris: list[str] = []
    ca_issuers: list[str] = []
    if aia:
        for item in aia:
            if isinstance(item.access_location, x509.UniformResourceIdentifier):
                if item.access_method == AuthorityInformationAccessOID.OCSP:
                    ocsp_uris.append(item.access_location.value)
                elif item.access_method == AuthorityInformationAccessOID.CA_ISSUERS:
                    ca_issuers.append(item.access_location.value)

    crl_points = _extension(cert, ExtensionOID.CRL_DISTRIBUTION_POINTS)
    crl_uris: list[str] = []
    if crl_points:
        for point in crl_points:
            if point.full_name:
                crl_uris.extend(
                    name.value
                    for name in point.full_name
                    if isinstance(name, x509.UniformResourceIdentifier)
                )

    try:
        signature_algorithm = cert.signature_hash_algorithm.name
    except Exception:
        signature_algorithm = cert.signature_algorithm_oid._name or cert.signature_algorithm_oid.dotted_string

    sct = _extension(cert, ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS)
    details = {
        "common_name": common_name,
        "subject_alt_names": sans,
        "san_dns": sans,
        "ip_subject_alt_names": ip_sans,
        "subject": _x509_names(cert.subject),
        "issuer": _x509_names(cert.issuer),
        "serial_number": format(cert.serial_number, "X"),
        "sha1_fingerprint": cert.fingerprint(hashes.SHA1()).hex(":").upper(),
        "sha256_fingerprint": cert.fingerprint(hashes.SHA256()).hex(":").upper(),
        "fingerprint_sha1": cert.fingerprint(hashes.SHA1()).hex(":").upper(),
        "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(":").upper(),
        "signature_algorithm": signature_algorithm,
        "signature_oid": cert.signature_algorithm_oid.dotted_string,
        "public_key_type": key_type,
        "public_key_bits": key_bits,
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "days_remaining": days_remaining,
        "validity_status": validity_status,
        "trust_valid": trust_valid,
        "trust_error": trust_error,
        "ocsp_uri": ocsp_uris[0] if ocsp_uris else None,
        "ocsp_uris": ocsp_uris,
        "ca_issuer_uris": ca_issuers,
        "crl_uris": crl_uris,
        "certificate_transparency_scts": len(sct) if sct else 0,
        "ct_sct_count": len(sct) if sct else 0,
    }
    return details, cert


def _hostname_matches(host: str, cert: x509.Certificate) -> tuple[bool | None, str | None]:
    san_extension = _extension(cert, ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    sans = san_extension.get_values_for_type(x509.DNSName) if san_extension else []
    ip_sans = [str(value) for value in san_extension.get_values_for_type(x509.IPAddress)] if san_extension else []
    common_names = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)

    def dns_matches(pattern: str, requested: str) -> bool:
        pattern = pattern.rstrip(".").lower()
        requested = requested.rstrip(".").lower()
        if "*" not in pattern:
            return pattern == requested
        if not pattern.startswith("*.") or pattern.count("*") != 1:
            return False
        return requested.endswith(pattern[1:]) and requested.count(".") == pattern.count(".")

    try:
        ipaddress.ip_address(host)
        matched = host in ip_sans
        return matched, None if matched else f"IP address {host} is absent from certificate SANs"
    except ValueError:
        identities = sans if sans else [item.value for item in common_names]
        matched = any(dns_matches(identity, host) for identity in identities)
        return matched, None if matched else f"Hostname {host} does not match: {', '.join(identities) or 'no DNS identity'}"
    except Exception as exc:
        return None, str(exc)


def _openssl_endpoint(host: str, port: int) -> str:
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def _run_openssl_s_client(
    host: str,
    port: int,
    timeout: float,
    *,
    server_hostname: str | None = None,
) -> dict[str, Any]:
    binary = locate_openssl()
    if not binary:
        return {"available": False, "error": "OpenSSL executable not found"}
    command = [
        binary,
        "s_client",
        "-connect",
        _openssl_endpoint(host, port),
        "-servername",
        server_hostname or host,
        "-alpn",
        "h2,http/1.1",
        "-status",
        "-showcerts",
        "-prexit",
    ]
    try:
        process = subprocess.run(
            command,
            input="",
            capture_output=True,
            text=True,
            timeout=max(0.05, timeout),
            check=False,
            errors="replace",
        )
    except subprocess.TimeoutExpired:
        return {"available": True, "error": "OpenSSL handshake timed out", "raw": ""}
    except Exception as exc:
        return {"available": True, "error": f"{type(exc).__name__}: {exc}", "raw": ""}

    raw = (process.stdout or "") + "\n" + (process.stderr or "")
    pem_blocks = re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", raw, re.S)
    temp_key = re.search(r"(?:Server|Peer) Temp Key:\s*([^,\r\n]+)(?:,\s*(\d+) bits)?", raw, re.I)
    cipher = re.search(r"(?:Cipher is|Cipher\s*:)\s*([^\s\r\n]+)", raw)
    protocol = re.search(r"Protocol\s*:\s*([^\r\n]+)", raw)
    ocsp_status = None
    if re.search(r"Cert Status:\s*good", raw, re.I):
        ocsp_status = "good"
    elif re.search(r"Cert Status:\s*revoked", raw, re.I):
        ocsp_status = "revoked"
    elif re.search(r"Cert Status:\s*unknown", raw, re.I):
        ocsp_status = "unknown"
    elif "OCSP response: no response sent" in raw:
        ocsp_status = "not_stapled"

    return {
        "available": True,
        "return_code": process.returncode,
        "raw": raw[-30000:],
        "pem_chain": pem_blocks,
        "protocol": protocol.group(1).strip() if protocol else None,
        "cipher": cipher.group(1).strip() if cipher else None,
        "temp_key_method": temp_key.group(1).strip() if temp_key else None,
        "temp_key_bits": int(temp_key.group(2)) if temp_key and temp_key.group(2) else None,
        "secure_renegotiation": True if "Secure Renegotiation IS supported" in raw else False if "Secure Renegotiation IS NOT supported" in raw else None,
        "compression": False if re.search(r"Compression:\s*NONE", raw, re.I) else True if re.search(r"Compression:\s*(?!NONE)\S+", raw, re.I) else None,
        "alpn": (re.search(r"ALPN protocol:\s*([^\r\n]+)", raw) or [None, None])[1],
        "ocsp_stapling": ocsp_status in {"good", "revoked", "unknown"},
        "ocsp_status": ocsp_status,
        "peer_address": host,
        "error": None if pem_blocks else "No certificate chain found in OpenSSL output",
    }


def _probe_openssl_protocol(
    host: str,
    port: int,
    timeout: float,
    flag: str,
    *,
    server_hostname: str | None = None,
) -> str:
    binary = locate_openssl()
    if not binary:
        return "not_tested"
    command = [
        binary,
        "s_client",
        "-connect",
        _openssl_endpoint(host, port),
        "-servername",
        server_hostname or host,
        flag,
        "-brief",
    ]
    try:
        process = subprocess.run(
            command,
            input="",
            capture_output=True,
            text=True,
            timeout=max(0.05, timeout),
            check=False,
            errors="replace",
        )
    except subprocess.TimeoutExpired:
        return "error"
    except Exception:
        return "error"
    output = (process.stdout or "") + "\n" + (process.stderr or "")
    if process.returncode == 0 and re.search(r"Protocol version:\s*TLSv1(?:\.0|\.1)?\b", output):
        return "supported"
    transport_markers = (
        "connection refused",
        "connect:errno",
        "timed out",
        "no route to host",
        "network is unreachable",
    )
    if any(marker in output.lower() for marker in transport_markers):
        return "error"
    # Only an alert attributable to the peer proves target-side rejection.
    # OpenSSL's bare "unsupported protocol" and "no protocols available"
    # messages can be emitted locally before any ClientHello is sent.
    peer_version_alerts = (
        "alert protocol version",
        "ssl alert number 70",
    )
    if any(marker in output.lower() for marker in peer_version_alerts):
        return "unsupported"
    return "error"


def _verify_chain_ignoring_time(
    host: str,
    port: int,
    timeout: float,
    *,
    server_hostname: str | None = None,
    deadline: float | None = None,
    cancel: CancelCallback | None = None,
) -> tuple[bool | None, str]:
    """Re-run public-chain validation while ignoring only certificate dates.

    Hostname identity remains a separate local X.509 comparison.  ``None``
    means the local provider or transport did not produce a trustworthy chain
    verdict; callers must not turn that into either trusted or untrusted.
    """
    if cancel is not None and cancel():
        return None, "Chain validation without time checks was cancelled"
    if deadline is not None and time.monotonic() >= deadline:
        return None, "Chain validation without time checks missed the deadline"
    binary = locate_openssl()
    if not binary:
        return None, "OpenSSL executable not found"
    operation_timeout = timeout
    if deadline is not None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None, "Chain validation without time checks missed the deadline"
        operation_timeout = min(timeout, remaining)
    command = [
        binary,
        "s_client",
        "-connect",
        _openssl_endpoint(host, port),
        "-servername",
        server_hostname or host,
        "-verify_return_error",
        "-no_check_time",
        "-brief",
    ]
    try:
        process = subprocess.run(
            command,
            input="",
            capture_output=True,
            text=True,
            timeout=operation_timeout,
            check=False,
            errors="replace",
        )
    except subprocess.TimeoutExpired:
        return None, "OpenSSL chain validation without time checks timed out"
    except Exception as exc:
        return None, f"OpenSSL chain validation without time checks failed locally: {type(exc).__name__}: {exc}"
    output = ((process.stdout or "") + "\n" + (process.stderr or "")).strip()
    excerpt = output[-2000:]
    if process.returncode == 0 and re.search(
        r"(?:Verification:\s*OK|Verify return code:\s*0\s*\(ok\))",
        output,
        re.I,
    ):
        return True, excerpt or "Verification: OK"
    local_markers = (
        "unknown option",
        "unrecognized option",
        "unsupported protocol",
        "no protocols available",
        "connection refused",
        "connect:errno",
        "timed out",
        "no route to host",
        "network is unreachable",
    )
    if any(marker in output.lower() for marker in local_markers):
        return None, excerpt or "OpenSSL did not produce a chain verdict"
    # -no_check_time should suppress date failures.  If one remains, the local
    # provider did not perform the requested controlled validation.
    if re.search(r"certificate (?:has expired|is not yet valid)|error (?:9|10) at", output, re.I):
        return None, excerpt or "Certificate-date checking was not disabled"
    if re.search(r"(?:Verification error:|verify error:num=|certificate verify error)", output, re.I):
        return False, excerpt or "Certificate chain verification failed"
    return None, excerpt or f"OpenSSL exited with code {process.returncode} without a chain verdict"


def _probe_protocol(
    host: str,
    port: int,
    timeout: float,
    attribute: str,
    *,
    server_hostname: str | None = None,
) -> str:
    legacy_flag = {"TLSv1_1": "-tls1_1", "TLSv1": "-tls1"}.get(attribute)
    if legacy_flag:
        return _probe_openssl_protocol(
            host,
            port,
            timeout,
            legacy_flag,
            server_hostname=server_hostname,
        )
    if not hasattr(ssl.TLSVersion, attribute):
        return "not_tested"
    version = getattr(ssl.TLSVersion, attribute)
    sock = None
    try:
        sock, _ = _connect(
            host,
            port,
            timeout,
            verify=False,
            minimum=version,
            maximum=version,
            server_hostname=server_hostname,
        )
        return "supported"
    except ssl.SSLError as exc:
        reason = str(getattr(exc, "reason", "") or "").upper()
        message = str(exc).upper()
        # A protocol-version alert is peer evidence.  UNSUPPORTED_PROTOCOL and
        # NO_PROTOCOLS_AVAILABLE can originate in the local provider before a
        # ClientHello and therefore remain measurement errors.
        definitive = "TLSV1_ALERT_PROTOCOL_VERSION"
        return "unsupported" if definitive in reason or definitive in message else "error"
    except (socket.timeout, TimeoutError, ConnectionError, OSError):
        return "error"
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


def _ssl3_client_hello(host: str) -> bytes:
    cipher_ids = (
        0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x0008,
        0x0009, 0x000A, 0x000B, 0x000C, 0x000D, 0x000E, 0x000F, 0x0010,
        0x0011, 0x0012, 0x0013, 0x0014, 0x0015, 0x0016, 0x0017, 0x0018,
        0x0019, 0x001A, 0x001B,
    )
    ciphers = b"".join(item.to_bytes(2, "big") for item in cipher_ids)
    extensions = b""
    try:
        ipaddress.ip_address(host)
    except ValueError:
        encoded = host.encode("idna")
        server_name = b"\x00" + len(encoded).to_bytes(2, "big") + encoded
        server_name_list = len(server_name).to_bytes(2, "big") + server_name
        extensions = b"\x00\x00" + len(server_name_list).to_bytes(2, "big") + server_name_list
    body = (
        b"\x03\x00"
        + os.urandom(32)
        + b"\x00"
        + len(ciphers).to_bytes(2, "big")
        + ciphers
        + b"\x01\x00"
        + len(extensions).to_bytes(2, "big")
        + extensions
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x00" + len(handshake).to_bytes(2, "big") + handshake


def _ssl2_client_hello() -> bytes:
    cipher_specs = (
        b"\x01\x00\x80", b"\x02\x00\x80", b"\x03\x00\x80", b"\x04\x00\x80",
        b"\x05\x00\x80", b"\x06\x00\x40", b"\x07\x00\xC0",
    )
    ciphers = b"".join(cipher_specs)
    challenge = os.urandom(16)
    body = (
        b"\x01"
        + b"\x00\x02"
        + len(ciphers).to_bytes(2, "big")
        + b"\x00\x00"
        + len(challenge).to_bytes(2, "big")
        + ciphers
        + challenge
    )
    return (0x8000 | len(body)).to_bytes(2, "big") + body


def _raw_legacy_probe(
    host: str,
    port: int,
    timeout: float,
    payload: bytes,
    probe_name: str,
    classify: Callable[[bytes, dict[str, Any]], tuple[str, dict[str, Any]] | None],
    *,
    server_hostname: str | None = None,
) -> tuple[str, dict[str, Any]]:
    observations: list[str] = []
    per_attempt_timeout = max(0.001, timeout / 2)
    for attempt in range(1, 3):
        sent = False
        try:
            with socket.create_connection((host, port), timeout=per_attempt_timeout) as raw:
                raw.settimeout(per_attempt_timeout)
                raw.sendall(payload)
                sent = True
                response = raw.recv(4096)
        except (socket.timeout, ConnectionResetError, BrokenPipeError) as exc:
            if sent:
                observations.append(f"{type(exc).__name__} after ClientHello")
                continue
            return "error", {"probe": probe_name, "evidence_class": "transport_or_local_error", "error": str(exc)}
        except OSError as exc:
            return "error", {"probe": probe_name, "evidence_class": "transport_or_local_error", "error": f"{type(exc).__name__}: {exc}"}
        detail = {
            "probe": probe_name,
            "peer_address": host,
            "server_hostname": server_hostname or host,
            "response_prefix_hex": response[:24].hex(),
            "attempt": attempt,
        }
        result = classify(response, detail)
        if result is not None:
            result[1]["evidence_class"] = "definitive_protocol_response"
            return result
        observations.append("closed after ClientHello" if not response else "unrecognized response")
    return "inferred_unsupported", {
        "probe": probe_name,
        "peer_address": host,
        "server_hostname": server_hostname or host,
        "evidence_class": "repeated_post_client_hello_rejection",
        "confidence": "inferred_not_definitive",
        "attempts": 2,
        "observations": observations,
    }


def _probe_ssl3(
    host: str,
    port: int,
    timeout: float,
    *,
    server_hostname: str | None = None,
) -> tuple[str, dict[str, Any]]:
    def classify(response: bytes, detail: dict[str, Any]):
        if len(response) >= 11 and response[0] == 0x16 and response[5] == 0x02:
            negotiated = response[9:11]
            detail["server_version_hex"] = negotiated.hex()
            return ("supported" if negotiated == b"\x03\x00" else "unsupported"), detail
        if len(response) >= 7 and response[0] == 0x15:
            detail["alert_description"] = response[6]
            return ("unsupported" if response[6] == 70 else "error"), detail
        return None
    return _raw_legacy_probe(host, port, timeout, _ssl3_client_hello(server_hostname or host), "raw SSL 3.0 ClientHello", classify, server_hostname=server_hostname)


def _probe_ssl2(
    host: str,
    port: int,
    timeout: float,
    *,
    server_hostname: str | None = None,
) -> tuple[str, dict[str, Any]]:
    def classify(response: bytes, detail: dict[str, Any]):
        if len(response) >= 7 and response[0] & 0x80 and response[2] == 0x04:
            detail["server_version_hex"] = response[5:7].hex()
            return ("supported" if response[5:7] == b"\x00\x02" else "unsupported"), detail
        if len(response) >= 7 and response[0] == 0x15:
            detail["alert_description"] = response[6]
            return ("unsupported" if response[6] == 70 else "error"), detail
        return None
    return _raw_legacy_probe(host, port, timeout, _ssl2_client_hello(), "native SSL 2.0 ClientHello", classify, server_hostname=server_hostname)


def _cipher_metadata(item: dict[str, Any]) -> dict[str, Any]:
    key_exchange = str(item.get("kea") or "").removeprefix("kx-").upper()
    key_exchange = {
        "ECDHE": "ECDHE",
        "DHE": "DHE",
        "RSA": "RSA",
        "ANY": "TLS 1.3",
    }.get(key_exchange, key_exchange or "unknown")
    authentication = str(item.get("auth") or "").removeprefix("auth-").upper()
    authentication = "None" if authentication in {"NULL", "NONE"} else authentication or "unknown"
    return {
        "name": item.get("name"),
        "protocol": item.get("protocol"),
        "bits": item.get("strength_bits"),
        "algorithm_bits": item.get("alg_bits"),
        "aead": item.get("aead"),
        "symmetric": item.get("symmetric"),
        "digest": item.get("digest"),
        "key_exchange": key_exchange,
        "authentication": authentication,
        "description": item.get("description"),
    }


def _enumerate_tls12_ciphers(
    host: str,
    port: int,
    timeout: float,
    *,
    server_hostname: str | None = None,
    deadline: float | None = None,
    cancel: CancelCallback | None = None,
) -> tuple[list[str], list[dict[str, Any]], dict[str, Any]]:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.set_ciphers("ALL:eNULL:@SECLEVEL=0")
    candidate_details: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in context.get_ciphers():
        name = str(item.get("name") or "")
        if not name or item.get("protocol") == "TLSv1.3" or name in seen:
            continue
        seen.add(name)
        candidate_details.append(_cipher_metadata(item))
    accepted: list[str] = []
    accepted_details: list[dict[str, Any]] = []
    attempted = 0
    indeterminate = 0
    handshake_count = 0
    inferred_unsupported_count = 0
    eof_rejection_attempts = 0
    inference: dict[str, Any] | None = None
    remaining = list(candidate_details)
    stopped_early = False
    # Iterative elimination is complete but normally much cheaper than one
    # connection per candidate: offer every remaining suite, record the one the
    # server selects, remove it, and repeat until the peer definitively rejects
    # the remaining set.  This needs accepted_count + 1 handshakes in the usual
    # case while still discovering the weakest accepted suite.
    while remaining:
        if (cancel is not None and cancel()) or (deadline is not None and time.monotonic() >= deadline):
            stopped_early = True
            break
        offered_names = [str(candidate["name"]) for candidate in remaining]
        cipher_spec = ":".join(offered_names)
        sock = None
        try:
            operation_timeout = timeout
            if deadline is not None:
                remaining_time = deadline - time.monotonic()
                if remaining_time <= 0:
                    stopped_early = True
                    break
                operation_timeout = min(timeout, remaining_time)
            handshake_count += 1
            handshake_started = time.monotonic()
            sock, _ = _connect(
                host,
                port,
                operation_timeout,
                verify=False,
                minimum=ssl.TLSVersion.TLSv1_2,
                maximum=ssl.TLSVersion.TLSv1_2,
                cipher=cipher_spec,
                server_hostname=server_hostname,
            )
            negotiated = sock.cipher()
            selected_name = negotiated[0] if negotiated else None
            selected = next(
                (candidate for candidate in remaining if candidate.get("name") == selected_name),
                None,
            )
            if selected is None:
                attempted += len(remaining)
                indeterminate += len(remaining)
                remaining.clear()
                continue
            eof_rejection_attempts = 0
            attempted += 1
            if selected_name not in accepted:
                accepted.append(selected_name)
                detail = dict(selected)
                detail.update(
                    {
                        "name": selected_name,
                        "negotiated_protocol": negotiated[1],
                        "bits": negotiated[2],
                        "peer_address": host,
                    }
                )
                accepted_details.append(detail)
            remaining.remove(selected)
        except ssl.SSLZeroReturnError:
            elapsed = time.monotonic() - handshake_started
            if accepted and elapsed <= 1.0:
                eof_rejection_attempts += 1
                if eof_rejection_attempts < 2:
                    continue
                inferred_unsupported_count = len(remaining)
                attempted += inferred_unsupported_count
                inference = {
                    "evidence_class": "repeated_post_client_hello_eof",
                    "confidence": "inferred_not_definitive",
                    "attempts": eof_rejection_attempts,
                    "observation": "The peer closed two forced-TLS-1.2 handshakes without an alert after previously negotiating an offered suite.",
                }
                remaining.clear()
            else:
                attempted += len(remaining)
                indeterminate += len(remaining)
                remaining.clear()
        except ssl.SSLError as exc:
            reason = str(getattr(exc, "reason", "") or "").upper()
            message = str(exc).upper()
            definitive_rejections = (
                "ALERT_HANDSHAKE_FAILURE",
                "ALERT_INSUFFICIENT_SECURITY",
                "NO_SHARED_CIPHER",
            )
            attempted += len(remaining)
            if not any(marker in reason or marker in message for marker in definitive_rejections):
                indeterminate += len(remaining)
            remaining.clear()
        except (socket.timeout, TimeoutError, ConnectionError, OSError):
            attempted += len(remaining)
            indeterminate += len(remaining)
            remaining.clear()
        except Exception:
            attempted += len(remaining)
            indeterminate += len(remaining)
            remaining.clear()
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass
    coverage = {
        "method": "All TLS <=1.2 ciphers configurable by the local Python ssl provider via ALL:eNULL:@SECLEVEL=0; iterative forced-TLS-1.2 elimination until the peer rejects the remaining set",
        "candidate_provider": ssl.OPENSSL_VERSION,
        "probe_provider": ssl.OPENSSL_VERSION,
        "candidate_count": len(candidate_details),
        "attempted_count": attempted,
        "definitive_count": attempted - indeterminate,
        "indeterminate_count": indeterminate,
        "inferred_unsupported_count": inferred_unsupported_count,
        "handshake_count": handshake_count,
        "complete": not remaining and attempted == len(candidate_details) and indeterminate == 0,
        "stopped_early": stopped_early,
        "inference": inference,
        "candidates": candidate_details,
        "peer_address": host,
        "server_hostname": server_hostname or host,
    }
    return accepted, accepted_details, coverage


def _probe_key_exchange_cipher(
    host: str,
    port: int,
    timeout: float,
    cipher: str,
    *,
    server_hostname: str | None = None,
) -> dict[str, Any] | None:
    binary = locate_openssl()
    if not binary:
        return None
    command = [
        binary,
        "s_client",
        "-connect",
        _openssl_endpoint(host, port),
        "-servername",
        server_hostname or host,
        "-tls1_2",
        "-cipher",
        f"{cipher}:@SECLEVEL=0",
        "-brief",
    ]
    try:
        process = subprocess.run(
            command,
            input="",
            capture_output=True,
            text=True,
            timeout=max(0.05, timeout),
            check=False,
            errors="replace",
        )
    except Exception:
        return None
    raw = (process.stdout or "") + "\n" + (process.stderr or "")
    temp_key = re.search(r"(?:Server|Peer) Temp Key:\s*([^,\r\n]+)(?:,\s*(\d+) bits)?", raw, re.I)
    negotiated = re.search(r"(?:Ciphersuite|Cipher is|Cipher\s*:)\s*([^\s\r\n]+)", raw, re.I)
    if not temp_key or not negotiated:
        return None
    return {
        "cipher": negotiated.group(1).strip(),
        "method": temp_key.group(1).strip(),
        "bits": int(temp_key.group(2)) if temp_key.group(2) else None,
        "peer_address": host,
    }


def _direct_ocsp(
    openssl: str,
    leaf_pem: str,
    issuer_pem: str,
    url: str,
    timeout: float,
    *,
    deadline: float | None = None,
    cancel: CancelCallback | None = None,
) -> tuple[str, str]:
    if (cancel is not None and cancel()) or (deadline is not None and time.monotonic() >= deadline):
        return "unknown", "OCSP validation was not run because the assessment stopped"
    operation_deadline = time.monotonic() + max(0.001, timeout)
    if deadline is not None:
        operation_deadline = min(operation_deadline, deadline)
    with tempfile.TemporaryDirectory(prefix="tlsgrader-ocsp-") as directory:
        leaf_path = Path(directory) / "leaf.pem"
        issuer_path = Path(directory) / "issuer.pem"
        request_path = Path(directory) / "request.der"
        response_path = Path(directory) / "response.der"
        leaf_path.write_text(leaf_pem, encoding="ascii")
        issuer_path.write_text(issuer_pem, encoding="ascii")
        request_command = [
            openssl,
            "ocsp",
            "-issuer",
            str(issuer_path),
            "-cert",
            str(leaf_path),
            "-no_nonce",
            "-reqout",
            str(request_path),
        ]
        try:
            request_process = subprocess.run(
                request_command,
                capture_output=True,
                text=True,
                timeout=_remaining(operation_deadline, timeout),
                check=False,
                errors="replace",
            )
        except Exception as exc:
            return "check_failed", f"OCSP request generation failed: {exc}"
        if request_process.returncode != 0 or not request_path.is_file():
            detail = ((request_process.stdout or "") + "\n" + (request_process.stderr or "")).strip()
            return "check_failed", detail[-1200:] or "OpenSSL did not generate an OCSP request"
        try:
            response_der, final_url = _safe_http_fetch(
                url,
                timeout=_remaining(operation_deadline, timeout),
                deadline=operation_deadline,
                cancel=cancel,
                method="POST",
                body=request_path.read_bytes(),
                headers={
                    "Content-Type": "application/ocsp-request",
                    "Accept": "application/ocsp-response",
                },
                max_bytes=2_000_000,
            )
        except (ValueError, TimeoutError, InterruptedError, OSError) as exc:
            return "check_failed", f"OCSP response fetch blocked or failed: {exc}"
        response_path.write_bytes(response_der)
        verify_command = [
            openssl,
            "ocsp",
            "-respin",
            str(response_path),
            "-issuer",
            str(issuer_path),
            "-cert",
            str(leaf_path),
            "-CAfile",
            str(issuer_path),
            "-no_nonce",
            "-status_age",
            "86400",
            "-resp_text",
        ]
        try:
            process = subprocess.run(
                verify_command,
                capture_output=True,
                text=True,
                timeout=_remaining(operation_deadline, timeout),
                check=False,
                errors="replace",
            )
        except Exception as exc:
            return "check_failed", f"Offline OCSP verification failed: {exc}"
        output = (process.stdout or "") + "\n" + (process.stderr or "")
        if process.returncode != 0 or re.search(r"Response Verify Failure|certificate verify error", output, re.I):
            return "check_failed", output.strip()[-1200:] or f"OpenSSL OCSP exited with code {process.returncode}"
        if not re.search(r"Response verify OK", output, re.I):
            return "check_failed", output.strip()[-1200:] or "OCSP response signature/chain was not verified"
        try:
            parsed_response = ocsp.load_der_ocsp_response(response_der)
        except (ValueError, TypeError):
            parsed_response = None

        if parsed_response is not None:
            if parsed_response.response_status is not ocsp.OCSPResponseStatus.SUCCESSFUL:
                return "check_failed", f"OCSP responder returned {parsed_response.response_status.name.lower()}"
            try:
                leaf_cert = x509.load_pem_x509_certificate(leaf_pem.encode("ascii"))
                issuer_cert = x509.load_pem_x509_certificate(issuer_pem.encode("ascii"))
                matches = []
                for single in parsed_response.responses:
                    if single.serial_number != leaf_cert.serial_number:
                        continue
                    expected = (
                        ocsp.OCSPRequestBuilder()
                        .add_certificate(leaf_cert, issuer_cert, single.hash_algorithm)
                        .build()
                    )
                    if (
                        single.issuer_name_hash == expected.issuer_name_hash
                        and single.issuer_key_hash == expected.issuer_key_hash
                    ):
                        matches.append(single)
            except Exception as exc:
                return "check_failed", f"OCSP leaf identity could not be verified: {type(exc).__name__}: {exc}"
            if len(matches) != 1:
                return "check_failed", f"OCSP response contained {len(matches)} matching status records for the requested leaf"
            matched = matches[0]
            this_time = matched.this_update_utc
            next_time = matched.next_update_utc
            if this_time is None or next_time is None:
                return "check_failed", "OCSP response freshness could not be verified because thisUpdate or nextUpdate is missing"
            now = datetime.now(timezone.utc)
            if this_time > now:
                return "check_failed", "OCSP response thisUpdate is in the future"
            if next_time < now:
                return "check_failed", "OCSP response nextUpdate has expired"
            state = {
                ocsp.OCSPCertStatus.GOOD: "good",
                ocsp.OCSPCertStatus.REVOKED: "revoked",
                ocsp.OCSPCertStatus.UNKNOWN: "unknown",
            }.get(matched.certificate_status)
            if state is None:
                return "check_failed", "OCSP response contained an unrecognised certificate status"
            detail = f"Fetched safely from {final_url}; leaf-bound DER status: {state}; " + output.strip()[-1000:]
            return state, detail

        # Compatibility path for verified OpenSSL providers whose response DER
        # is not understood by the pinned cryptography version.  Bind the text
        # status and timestamps to OpenSSL's exact requested-certificate line;
        # never accept an unrelated ``Cert Status`` block.
        leaf_labels = (str(leaf_path), leaf_path.name)
        status_match = None
        for label in leaf_labels:
            status_match = re.search(
                rf"^{re.escape(label)}:\s*(good|revoked|unknown)\b(?P<tail>.*?)(?=^\S[^\r\n]*:\s*(?:good|revoked|unknown)\b|\Z)",
                output,
                re.I | re.M | re.S,
            )
            if status_match:
                break
        if not status_match:
            return "check_failed", "No status explicitly bound to the requested leaf certificate"
        tail = status_match.group("tail")
        this_update = re.search(r"This Update:\s*([^\r\n]+)", tail, re.I)
        next_update = re.search(r"Next Update:\s*([^\r\n]+)", tail, re.I)
        if not this_update or not next_update:
            return "check_failed", "OCSP response freshness could not be verified because thisUpdate or nextUpdate is missing"
        try:
            now = datetime.now(timezone.utc)
            this_time = parsedate_to_datetime(this_update.group(1).strip())
            if this_time.tzinfo is None:
                this_time = this_time.replace(tzinfo=timezone.utc)
            if this_time > now:
                return "check_failed", "OCSP response thisUpdate is in the future"
            next_time = parsedate_to_datetime(next_update.group(1).strip())
            if next_time.tzinfo is None:
                next_time = next_time.replace(tzinfo=timezone.utc)
            if next_time < now:
                return "check_failed", "OCSP response nextUpdate has expired"
        except (TypeError, ValueError, OverflowError) as exc:
            return "check_failed", f"OCSP response freshness timestamps could not be parsed: {exc}"
        state = status_match.group(1).lower()
        return state, f"Fetched safely from {final_url}; leaf-bound OpenSSL status: {state}; " + output.strip()[-1000:]


def _check_crl(
    cert: x509.Certificate,
    urls: list[str],
    timeout: float,
    *,
    issuer_cert: x509.Certificate | None = None,
    deadline: float | None = None,
    cancel: CancelCallback | None = None,
) -> tuple[str, str]:
    operation_deadline = time.monotonic() + max(0.001, timeout)
    if deadline is not None:
        operation_deadline = min(operation_deadline, deadline)
    for url in urls[:2]:
        if (cancel is not None and cancel()) or time.monotonic() >= operation_deadline:
            return "unknown", "CRL validation stopped before all candidate URLs were checked"
        if not url.lower().startswith(("http://", "https://")):
            continue
        try:
            data, final_url = _safe_http_fetch(
                url,
                timeout=_remaining(operation_deadline, timeout),
                deadline=operation_deadline,
                cancel=cancel,
                method="GET",
                headers={"Accept": "application/pkix-crl, application/x-pkcs7-crl, */*"},
                max_bytes=2_000_000,
            )
            try:
                crl = x509.load_der_x509_crl(data)
            except ValueError:
                crl = x509.load_pem_x509_crl(data)
            if issuer_cert is None:
                return "unknown", "CRL was downloaded but no issuer certificate was available for signature validation"
            try:
                if cert.issuer != issuer_cert.subject or crl.issuer != issuer_cert.subject:
                    return "unknown", "CRL issuer does not match the validated leaf issuer"
                if not crl.is_signature_valid(issuer_cert.public_key()):
                    return "unknown", "CRL signature validation failed"
                now = datetime.now(timezone.utc)
                last_update = crl.last_update_utc
                next_update = crl.next_update_utc
                if last_update is None or last_update > now:
                    return "unknown", "CRL thisUpdate is missing or in the future"
                if next_update is None or next_update < now:
                    return "unknown", "CRL nextUpdate is missing or expired"
            except Exception as exc:
                return "unknown", f"CRL authenticity or validity could not be verified: {type(exc).__name__}: {exc}"
            revoked = crl.get_revoked_certificate_by_serial_number(cert.serial_number)
            return ("revoked", f"Serial found in CRL from {final_url}") if revoked else ("good", f"Serial absent from CRL at {final_url}")
        except Exception as exc:
            last_error = f"CRL query failed for {url}: {exc}"
    return "check_failed", locals().get("last_error", "No supported CRL URL")


def _not_scored_scan(
    *,
    host: str,
    port: int,
    country: str,
    sector: str,
    source: str,
    status: str,
    started: float,
    addresses: list[str],
    peer_address: str | None,
    errors: list[str],
    certificate: dict[str, Any] | None = None,
    protocols: dict[str, str] | None = None,
    ciphers: dict[str, Any] | None = None,
    key_exchange: dict[str, Any] | None = None,
    probe_peers: dict[str, str] | None = None,
    attempted_peers: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return score_scan(
        {
            "assessment_version": ASSESSMENT_VERSION,
            "evidence_schema_version": EVIDENCE_SCHEMA_VERSION,
            "hostname": host,
            "port": port,
            "country": country,
            "sector": sector,
            "source": source,
            "mode": "full",
            "scan_time": utc_now_iso(),
            "duration_seconds": round(time.monotonic() - started, 3),
            "status": status,
            "addresses": addresses,
            "peer_address": peer_address,
            "probe_peers": probe_peers or {},
            "attempted_peers": attempted_peers or [],
            "certificate": certificate or {"trust_valid": None, "trust_state": "unknown", "revocation_status": "unknown"},
            "protocols": protocols or {},
            "key_exchange": key_exchange or {},
            "ciphers": ciphers or {"enumeration_complete": False},
            "compression": "not_tested",
            "secure_renegotiation": "not_tested",
            "errors": errors,
            "capabilities": scanner_capabilities(),
        }
    )


def scan_target(
    hostname: str,
    port: int = 443,
    *,
    mode: str = "full",
    timeout: float = 4.0,
    country: str = "",
    sector: str = "",
    source: str = "manual",
    progress: ProgressCallback | None = None,
    deadline: float | None = None,
    cancel: CancelCallback | None = None,
) -> dict[str, Any]:
    """Collect one internally consistent TLS observation against one fixed peer IP.

    ``deadline`` is an absolute ``time.monotonic()`` value. ``cancel`` is checked
    between bounded network operations. Cancelled and inconclusive observations
    retain evidence but never receive a numeric grade.
    """
    host = normalize_host(hostname)
    port = safe_port(port)
    mode = "full"
    started = time.monotonic()
    errors: list[str] = []
    addresses: list[str] = []
    peer_address: str | None = None
    probe_peers: dict[str, str] = {}
    attempted_peers: list[dict[str, Any]] = []

    def stop_state() -> str | None:
        if cancel is not None and cancel():
            return "cancelled"
        if deadline is not None and time.monotonic() >= deadline:
            return "inconclusive"
        return None

    def bounded_timeout() -> float:
        if deadline is None:
            return timeout
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Per-target assessment deadline expired")
        return max(0.05, min(timeout, remaining))

    stopped = stop_state()
    if stopped:
        return _not_scored_scan(
            host=host, port=port, country=country, sector=sector, source=source,
            status=stopped, started=started, addresses=[], peer_address=None,
            errors=["Assessment cancelled before collection" if stopped == "cancelled" else "Per-target assessment deadline expired"],
        )

    _notify(progress, "Resolving hostname", 5)
    resolution_status: str | None = None
    try:
        resolver_deadline = time.monotonic() + max(0.001, timeout)
        if deadline is not None:
            resolver_deadline = min(resolver_deadline, deadline)
        addresses = sorted(
            {
                item[4][0]
                for item in _getaddrinfo_with_budget(
                    host,
                    port,
                    deadline=resolver_deadline,
                    cancel=cancel,
                )
            },
            key=lambda value: (ipaddress.ip_address(value).version, int(ipaddress.ip_address(value))),
        )
    except InterruptedError as exc:
        resolution_status = "cancelled"
        errors.append(f"DNS resolution cancelled: {exc}")
    except TimeoutError as exc:
        resolution_status = "inconclusive"
        errors.append(f"DNS resolution timed out: {exc}")
    except Exception as exc:
        errors.append(f"DNS resolution failed: {type(exc).__name__}: {exc}")
    if not addresses:
        return _not_scored_scan(
            host=host, port=port, country=country, sector=sector, source=source,
            status=resolution_status or "failed", started=started, addresses=addresses, peer_address=None,
            errors=errors or ["DNS resolution returned no addresses"],
        )
    _notify(progress, "Validating certificate chain", 15)
    handshake: dict[str, Any] = {"ok": False, "error": "No peer produced TLS evidence"}
    trust_valid: bool | None = None
    trust_state = "unknown"
    trust_error: str | None = None
    for candidate_address in addresses:
        if stop_state() is not None:
            break
        verified = _basic_handshake(
            candidate_address, port, bounded_timeout(), True, server_hostname=host
        )
        probe_peers[f"peer_attempt:{len(attempted_peers) + 1}:verified"] = candidate_address
        attempt = {
            "peer_address": candidate_address,
            "verified_ok": bool(verified.get("ok")),
            "verified_error_kind": verified.get("error_kind"),
            "verified_error": verified.get("error"),
        }
        if verified.get("ok"):
            peer_address = candidate_address
            trust_valid = True
            trust_state = "trusted"
            trust_error = None
            handshake = verified
            attempt["selected"] = True
            attempted_peers.append(attempt)
            break
        verification_error = verified.get("error")
        evidence_handshake = _basic_handshake(
            candidate_address, port, bounded_timeout(), False, server_hostname=host
        )
        probe_peers[f"peer_attempt:{len(attempted_peers) + 1}:evidence"] = candidate_address
        attempt["evidence_ok"] = bool(evidence_handshake.get("ok"))
        attempt["evidence_error"] = evidence_handshake.get("error")
        if evidence_handshake.get("ok"):
            peer_address = candidate_address
            if verified.get("error_kind") == "certificate_verification":
                trust_valid = False
                trust_state = "untrusted"
            elif verified.get("error_kind") == "certificate_validity":
                trust_valid, no_time_detail = _verify_chain_ignoring_time(
                    candidate_address,
                    port,
                    bounded_timeout(),
                    server_hostname=host,
                    deadline=deadline,
                    cancel=cancel,
                )
                probe_peers[f"peer_attempt:{len(attempted_peers) + 1}:chain_without_time"] = candidate_address
                if trust_valid is True:
                    trust_state = "trusted_ignoring_time"
                elif trust_valid is False:
                    trust_state = "untrusted"
                else:
                    trust_state = "validity_failed_unresolved"
                trust_error = f"{verification_error}; chain-without-time: {no_time_detail}"
            else:
                trust_valid = None
                trust_state = "unknown"
            if verified.get("error_kind") != "certificate_validity":
                trust_error = verification_error
            handshake = evidence_handshake
            attempt["selected"] = True
            attempted_peers.append(attempt)
            break
        attempt["selected"] = False
        attempted_peers.append(attempt)
    if not handshake.get("ok"):
        errors.append(handshake.get("error", "TLS handshake failed"))
        return _not_scored_scan(
            host=host, port=port, country=country, sector=sector, source=source,
            status="failed", started=started, addresses=addresses, peer_address=peer_address,
            errors=errors,
            certificate={
                "trust_valid": trust_valid,
                "trust_state": trust_state,
                "trust_error": trust_error,
                "hostname_valid": None,
                "validity_status": "unknown",
                "revocation_status": "unknown",
            },
            probe_peers=probe_peers,
            attempted_peers=attempted_peers,
        )

    # The absolute target deadline protects DNS and initial reachability only.
    # Once the endpoint has produced TLS evidence, continue the full assessment
    # with the existing per-operation timeouts and cooperative cancellation.
    deadline = None

    _notify(progress, "Parsing X.509 certificate", 28)
    certificate, cert_object = _certificate_details(handshake["certificate_der"], trust_valid, trust_error)
    certificate["trust_valid"] = trust_valid
    certificate["trust_state"] = trust_state
    certificate["trust_error"] = trust_error
    hostname_valid, hostname_error = _hostname_matches(host, cert_object)
    certificate["hostname_valid"] = hostname_valid
    certificate["hostname_error"] = hostname_error

    _notify(progress, "Inspecting OpenSSL handshake evidence", 38)
    if stop_state() is None:
        openssl_result = _run_openssl_s_client(
            peer_address, port, bounded_timeout(), server_hostname=host
        )
        probe_peers["openssl_handshake"] = peer_address
    else:
        openssl_result = {
            "available": bool(locate_openssl()),
            "error": "OpenSSL evidence not collected before assessment stopped",
            "raw": "",
        }
    chain = openssl_result.get("pem_chain", [])
    certificate["chain_length"] = len(chain) or 1
    certificate["chain_complete"] = trust_valid is True
    certificate["observed_chain_length"] = len(chain) or 1
    certificate["observed_ocsp_stapling"] = bool(openssl_result.get("ocsp_stapling"))
    certificate["ocsp_stapling_verified"] = False
    certificate["ocsp_stapling"] = False
    stapled = openssl_result.get("ocsp_status")
    certificate["observed_stapled_ocsp_status"] = stapled
    certificate["revocation_status"] = "unknown"
    certificate["revocation_source"] = None
    certificate["revocation_detail"] = (
        f"A stapled OCSP response reported {stapled}, but this collection path did not verify its signature/chain"
        if stapled in {"good", "revoked", "unknown"}
        else "No verified stapled OCSP response was observed"
    )

    issuer_cert: x509.Certificate | None = None
    if len(chain) >= 2:
        try:
            issuer_cert = x509.load_pem_x509_certificate(chain[1].encode("ascii"))
        except (ValueError, UnicodeError):
            issuer_cert = None

    if certificate["revocation_status"] not in {"good", "revoked"} and stop_state() is None and trust_valid is True:
        binary = locate_openssl()
        if binary and len(chain) >= 2 and certificate.get("ocsp_uri"):
            _notify(progress, "Querying direct OCSP responder", 46)
            state, detail = _direct_ocsp(
                binary,
                chain[0],
                chain[1],
                certificate["ocsp_uri"],
                bounded_timeout(),
                deadline=deadline,
                cancel=cancel,
            )
            certificate["revocation_status"] = state
            certificate["revocation_source"] = "direct OCSP"
            certificate["revocation_detail"] = detail
        if (
            certificate["revocation_status"] not in {"good", "revoked"}
            and certificate.get("crl_uris")
            and stop_state() is None
        ):
            _notify(progress, "Checking certificate revocation list", 52)
            state, detail = _check_crl(
                cert_object,
                certificate["crl_uris"],
                bounded_timeout(),
                issuer_cert=issuer_cert,
                deadline=deadline,
                cancel=cancel,
            )
            certificate["revocation_status"] = state
            certificate["revocation_source"] = "CRL"
            certificate["revocation_detail"] = detail

    protocols: dict[str, str] = {}
    protocol_probe_details: dict[str, Any] = {}
    _notify(progress, "Testing protocol versions", 58)
    for name, attribute in PROTOCOL_VERSIONS:
        if stop_state() is not None:
            protocols[name] = "not_tested"
            continue
        protocols[name] = _probe_protocol(
            peer_address,
            port,
            bounded_timeout(),
            attribute,
            server_hostname=host,
        )
        probe_peers[f"protocol:{name}"] = peer_address
    if stop_state() is None:
        ssl3_state, ssl3_detail = _probe_ssl3(
            peer_address, port, bounded_timeout(), server_hostname=host
        )
        probe_peers["protocol:SSL 3.0"] = peer_address
    else:
        ssl3_state, ssl3_detail = "not_tested", {"reason": "assessment stopped"}
    if stop_state() is None:
        ssl2_state, ssl2_detail = _probe_ssl2(
            peer_address, port, bounded_timeout(), server_hostname=host
        )
        probe_peers["protocol:SSL 2.0"] = peer_address
    else:
        ssl2_state, ssl2_detail = "not_tested", {"reason": "assessment stopped"}
    protocols["SSL 3.0"] = ssl3_state
    protocols["SSL 2.0"] = ssl2_state
    protocol_probe_details.update({"SSL 3.0": ssl3_detail, "SSL 2.0": ssl2_detail})

    negotiated_cipher = openssl_result.get("cipher") or handshake.get("cipher")
    accepted: list[str] = [negotiated_cipher] if negotiated_cipher else []
    accepted_details: list[dict[str, Any]] = []
    if negotiated_cipher:
        accepted_details.append(
            {
                "name": negotiated_cipher,
                "protocol": handshake.get("protocol") or openssl_result.get("protocol"),
                "bits": handshake.get("cipher_bits"),
                "key_exchange": "TLS 1.3" if handshake.get("protocol") == "TLSv1.3" else "unknown",
                "authentication": "unknown",
                "peer_address": peer_address,
            }
        )
    cipher_coverage: dict[str, Any] = {
        "method": "not_applicable_without_TLS_1_2",
        "candidate_count": 0,
        "attempted_count": 0,
        "definitive_count": 0,
        "indeterminate_count": 0,
        "complete": protocols.get("TLS 1.2") == "unsupported",
        "candidates": [],
        "peer_address": peer_address,
        "server_hostname": host,
    }
    if protocols.get("TLS 1.2") == "supported" and stop_state() is None:
        _notify(progress, "Enumerating TLS 1.2 cipher suites", 68)
        enumerated, enumerated_details, cipher_coverage = _enumerate_tls12_ciphers(
            peer_address,
            port,
            bounded_timeout(),
            server_hostname=host,
            deadline=deadline,
            cancel=cancel,
        )
        probe_peers["tls12_cipher_enumeration"] = peer_address
        accepted = list(dict.fromkeys(accepted + enumerated))
        known_details = {item.get("name"): item for item in accepted_details}
        for item in enumerated_details:
            known_details[item.get("name")] = item
        accepted_details = list(known_details.values())

    method = openssl_result.get("temp_key_method")
    if not method and negotiated_cipher:
        upper = negotiated_cipher.upper()
        method = (
            "ECDHE" if "ECDHE" in upper else
            "DHE" if "DHE" in upper else
            "TLS 1.3 integrated key exchange" if handshake.get("protocol") == "TLSv1.3" else
            "unknown"
        )
    method_upper = (method or "").upper()
    forward_secrecy = (
        True if any(marker in method_upper for marker in ("ECDHE", "DHE", "X25519", "X448", "TLS 1.3"))
        else False if method and "RSA" in method_upper
        else None
    )
    key_observations: list[dict[str, Any]] = []
    if method:
        key_observations.append(
            {
                "cipher": negotiated_cipher,
                "method": method,
                "bits": openssl_result.get("temp_key_bits"),
                "peer_address": peer_address,
            }
        )
    _notify(progress, "Measuring accepted Diffie-Hellman keys", 84)
    detail_by_name = {str(item.get("name")): item for item in accepted_details}
    dhe_candidates = [
        name for name in accepted
        if str(detail_by_name.get(name, {}).get("key_exchange", "")).upper() in {"DHE", "DH"}
        and not str(name).upper().startswith("ECDHE-")
    ]
    dhe_attempted = 0
    dhe_definitive = 0
    for cipher_name in accepted:
        if stop_state() is not None:
            break
        detail = detail_by_name.get(cipher_name, {})
        if cipher_name not in dhe_candidates:
            continue
        dhe_attempted += 1
        observation = _probe_key_exchange_cipher(
            peer_address,
            port,
            bounded_timeout(),
            cipher_name,
            server_hostname=host,
        )
        probe_peers[f"key_exchange:{cipher_name}"] = peer_address
        if observation and observation not in key_observations:
            key_observations.append(observation)
        if observation and isinstance(observation.get("bits"), int):
            dhe_definitive += 1
    finite_field_dh_bits = sorted(
        {
            int(item["bits"])
            for item in key_observations
            if isinstance(item.get("bits"), int)
            and (
                ("DHE" in str(item.get("cipher", "")).upper() and "ECDHE" not in str(item.get("cipher", "")).upper())
                or str(item.get("method", "")).upper() in {"DH", "DHE"}
            )
        }
    )
    cipher_bits = [
        int(item["bits"]) for item in accepted_details
        if isinstance(item.get("bits"), int)
    ]

    stopped = stop_state()
    status = stopped or "completed"
    if trust_valid is None:
        errors.append("Certificate-chain trust was not definitively measured: " + str(trust_error or "unknown verification error"))
    if stopped == "cancelled":
        errors.append("Assessment cancelled before all evidence was collected")
    elif stopped == "inconclusive":
        errors.append("Per-target assessment deadline expired before all evidence was collected")
    if openssl_result.get("error"):
        errors.append(openssl_result["error"])

    _notify(progress, "Calculating explainable score", 92)
    scan = {
        "assessment_version": ASSESSMENT_VERSION,
        "evidence_schema_version": EVIDENCE_SCHEMA_VERSION,
        "hostname": host,
        "port": port,
        "country": country,
        "sector": sector,
        "source": source,
        "mode": mode,
        "scan_time": utc_now_iso(),
        "duration_seconds": round(time.monotonic() - started, 3),
        "status": status,
        "addresses": addresses,
        "peer_address": peer_address,
        "probe_peers": probe_peers,
        "attempted_peers": attempted_peers,
        "certificate": certificate,
        "protocols": protocols,
        "key_exchange": {
            "method": method,
            "bits": openssl_result.get("temp_key_bits"),
            "forward_secrecy": forward_secrecy,
            "observed": key_observations,
            "finite_field_dh_bits": finite_field_dh_bits,
            "minimum_dhe_bits": min(finite_field_dh_bits) if finite_field_dh_bits else None,
            "maximum_dhe_bits": max(finite_field_dh_bits) if finite_field_dh_bits else None,
            "dhe_coverage": {
                "candidate_count": len(dhe_candidates),
                "attempted_count": dhe_attempted,
                "definitive_count": dhe_definitive,
                "indeterminate_count": dhe_attempted - dhe_definitive,
                "complete": dhe_attempted == len(dhe_candidates) and dhe_definitive == len(dhe_candidates),
                "peer_address": peer_address,
                "server_hostname": host,
            },
        },
        "ciphers": {
            "negotiated": negotiated_cipher,
            "negotiated_bits": handshake.get("cipher_bits"),
            "accepted": accepted,
            "accepted_details": accepted_details,
            "weakest_bits": min(cipher_bits) if cipher_bits else handshake.get("cipher_bits"),
            "strongest_bits": max(cipher_bits) if cipher_bits else handshake.get("cipher_bits"),
            "attempted": cipher_coverage["attempted_count"],
            "enumeration_complete": bool(cipher_coverage["complete"]),
            "coverage": cipher_coverage,
        },
        "secure_renegotiation": "not_tested",
        "compression": "not_tested",
        "observed_secure_renegotiation": openssl_result.get("secure_renegotiation"),
        "observed_compression": openssl_result.get("compression"),
        "alpn": openssl_result.get("alpn") or handshake.get("alpn"),
        "alpn_offered": ["h2", "http/1.1"],
        "errors": errors,
        "capabilities": scanner_capabilities(),
        "raw_evidence": {
            "openssl_excerpt": openssl_result.get("raw", "")[-8000:],
            "legacy_protocol_probes": protocol_probe_details,
        },
    }
    result = score_scan(scan)
    _notify(progress, "Scan complete", 100)
    return result
