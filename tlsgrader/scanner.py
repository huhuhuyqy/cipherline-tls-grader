from __future__ import annotations

import os
import ipaddress
import re
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa
from cryptography.x509 import AuthorityInformationAccessOID, ExtensionOID

from .scoring import score_scan
from .utils import normalize_host, safe_port, utc_now_iso


ProgressCallback = Callable[[str, int], None]

PROTOCOL_VERSIONS: list[tuple[str, str]] = [
    ("TLS 1.3", "TLSv1_3"),
    ("TLS 1.2", "TLSv1_2"),
    ("TLS 1.1", "TLSv1_1"),
    ("TLS 1.0", "TLSv1"),
]


def _notify(callback: ProgressCallback | None, message: str, percent: int) -> None:
    if callback:
        callback(message, percent)


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
        "protocol_probe": [name for name, attr in PROTOCOL_VERSIONS if hasattr(ssl.TLSVersion, attr)] + ["SSL 3.0", "SSL 2.0"],
        "ssl2_ssl3": "raw_client_hello_probe",
        "full_cipher_enumeration_limit": None,
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
) -> tuple[ssl.SSLSocket, socket.socket]:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = verify
    context.verify_mode = ssl.CERT_REQUIRED if verify else ssl.CERT_NONE
    if verify:
        context.load_default_certs()
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
    raw = socket.create_connection((host, port), timeout=timeout)
    raw.settimeout(timeout)
    wrapped = context.wrap_socket(raw, server_hostname=host)
    return wrapped, raw


def _basic_handshake(host: str, port: int, timeout: float, verify: bool) -> dict[str, Any]:
    sock = None
    try:
        sock, _ = _connect(host, port, timeout, verify=verify)
        cipher = sock.cipher()
        return {
            "ok": True,
            "certificate_der": sock.getpeercert(binary_form=True),
            "certificate_dict": sock.getpeercert(),
            "protocol": sock.version(),
            "cipher": cipher[0] if cipher else None,
            "cipher_bits": cipher[2] if cipher else None,
            "alpn": sock.selected_alpn_protocol(),
        }
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
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


def _run_openssl_s_client(host: str, port: int, timeout: float) -> dict[str, Any]:
    binary = locate_openssl()
    if not binary:
        return {"available": False, "error": "OpenSSL executable not found"}
    command = [
        binary,
        "s_client",
        "-connect",
        f"{host}:{port}",
        "-servername",
        host,
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
            timeout=max(4, timeout * 2),
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
        "error": None if pem_blocks else "No certificate chain found in OpenSSL output",
    }


def _probe_protocol(host: str, port: int, timeout: float, attribute: str) -> str:
    if not hasattr(ssl.TLSVersion, attribute):
        return "not_tested"
    version = getattr(ssl.TLSVersion, attribute)
    sock = None
    try:
        sock, _ = _connect(host, port, timeout, verify=False, minimum=version, maximum=version)
        return "supported"
    except ssl.SSLError:
        return "unsupported"
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


def _probe_ssl3(host: str, port: int, timeout: float) -> tuple[str, dict[str, Any]]:
    response = b""
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            raw.settimeout(timeout)
            raw.sendall(_ssl3_client_hello(host))
            response = raw.recv(4096)
    except socket.timeout:
        return "error", {"probe": "raw SSL 3.0 ClientHello", "error": "response timeout"}
    except (ConnectionResetError, BrokenPipeError):
        return "unsupported", {"probe": "raw SSL 3.0 ClientHello", "result": "connection rejected"}
    except OSError as exc:
        return "error", {"probe": "raw SSL 3.0 ClientHello", "error": f"{type(exc).__name__}: {exc}"}

    detail = {"probe": "raw SSL 3.0 ClientHello", "response_prefix_hex": response[:24].hex()}
    if len(response) >= 11 and response[0] == 0x16 and response[5] == 0x02:
        negotiated = response[9:11]
        detail["server_version_hex"] = negotiated.hex()
        return ("supported" if negotiated == b"\x03\x00" else "unsupported"), detail
    if len(response) >= 2 and response[0] == 0x15:
        detail["result"] = "TLS alert"
        return "unsupported", detail
    if not response:
        detail["result"] = "connection closed without ServerHello"
        return "unsupported", detail
    detail["result"] = "non-SSL3 response"
    return "unsupported", detail


def _probe_ssl2(host: str, port: int, timeout: float) -> tuple[str, dict[str, Any]]:
    response = b""
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            raw.settimeout(timeout)
            raw.sendall(_ssl2_client_hello())
            response = raw.recv(4096)
    except socket.timeout:
        return "error", {"probe": "native SSL 2.0 ClientHello", "error": "response timeout"}
    except (ConnectionResetError, BrokenPipeError):
        return "unsupported", {"probe": "native SSL 2.0 ClientHello", "result": "connection rejected"}
    except OSError as exc:
        return "error", {"probe": "native SSL 2.0 ClientHello", "error": f"{type(exc).__name__}: {exc}"}

    detail = {"probe": "native SSL 2.0 ClientHello", "response_prefix_hex": response[:24].hex()}
    if len(response) >= 7 and response[0] & 0x80 and response[2] == 0x04:
        detail["server_version_hex"] = response[5:7].hex()
        return ("supported" if response[5:7] == b"\x00\x02" else "unsupported"), detail
    if len(response) >= 2 and response[0] == 0x15:
        detail["result"] = "TLS alert"
        return "unsupported", detail
    if not response:
        detail["result"] = "connection closed without ServerHello"
        return "unsupported", detail
    detail["result"] = "non-SSL2 response"
    return "unsupported", detail


def _enumerate_tls12_ciphers(host: str, port: int, timeout: float) -> tuple[list[str], list[dict[str, Any]], int]:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    candidates: list[str] = []
    for item in context.get_ciphers():
        name = item.get("name")
        protocol = item.get("protocol", "")
        if name and protocol != "TLSv1.3" and name not in candidates:
            candidates.append(name)
    accepted: list[str] = []
    accepted_details: list[dict[str, Any]] = []
    attempted = 0
    for name in candidates:
        attempted += 1
        sock = None
        try:
            sock, _ = _connect(
                host,
                port,
                timeout,
                verify=False,
                minimum=ssl.TLSVersion.TLSv1_2,
                maximum=ssl.TLSVersion.TLSv1_2,
                cipher=name,
            )
            negotiated = sock.cipher()
            if negotiated and negotiated[0] not in accepted:
                accepted.append(negotiated[0])
                accepted_details.append(
                    {
                        "name": negotiated[0],
                        "protocol": negotiated[1],
                        "bits": negotiated[2],
                    }
                )
        except Exception:
            pass
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass
    return accepted, accepted_details, attempted


def _probe_key_exchange_cipher(host: str, port: int, timeout: float, cipher: str) -> dict[str, Any] | None:
    binary = locate_openssl()
    if not binary:
        return None
    command = [
        binary,
        "s_client",
        "-connect",
        f"{host}:{port}",
        "-servername",
        host,
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
            timeout=max(4, timeout * 2),
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
    }


def _direct_ocsp(openssl: str, leaf_pem: str, issuer_pem: str, url: str, timeout: float) -> tuple[str, str]:
    if not url.lower().startswith(("http://", "https://")):
        return "unknown", "Unsupported OCSP URL scheme"
    with tempfile.TemporaryDirectory(prefix="tlsgrader-ocsp-") as directory:
        leaf_path = Path(directory) / "leaf.pem"
        issuer_path = Path(directory) / "issuer.pem"
        leaf_path.write_text(leaf_pem, encoding="ascii")
        issuer_path.write_text(issuer_pem, encoding="ascii")
        command = [openssl, "ocsp", "-issuer", str(issuer_path), "-cert", str(leaf_path), "-url", url, "-no_nonce", "-timeout", str(max(2, int(timeout)))]
        try:
            process = subprocess.run(command, capture_output=True, text=True, timeout=max(5, timeout * 2), check=False, errors="replace")
        except Exception as exc:
            return "check_failed", f"OCSP query failed: {exc}"
        output = (process.stdout or "") + "\n" + (process.stderr or "")
        if re.search(r":\s*good\b", output, re.I):
            return "good", output.strip()[-1200:]
        if re.search(r":\s*revoked\b", output, re.I):
            return "revoked", output.strip()[-1200:]
        if re.search(r":\s*unknown\b", output, re.I):
            return "unknown", output.strip()[-1200:]
        return "check_failed", output.strip()[-1200:] or "No OCSP response"


def _check_crl(cert: x509.Certificate, urls: list[str], timeout: float) -> tuple[str, str]:
    for url in urls[:2]:
        if not url.lower().startswith(("http://", "https://")):
            continue
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "TLSGraderLocal/1.0"})
            with urllib.request.urlopen(request, timeout=timeout) as response:
                data = response.read(2_000_001)
            if len(data) > 2_000_000:
                return "check_failed", "CRL exceeded the 2 MB safety limit"
            try:
                crl = x509.load_der_x509_crl(data)
            except ValueError:
                crl = x509.load_pem_x509_crl(data)
            revoked = crl.get_revoked_certificate_by_serial_number(cert.serial_number)
            return ("revoked", f"Serial found in CRL from {url}") if revoked else ("good", f"Serial absent from CRL at {url}")
        except Exception as exc:
            last_error = f"CRL query failed for {url}: {exc}"
    return "check_failed", locals().get("last_error", "No supported CRL URL")


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
) -> dict[str, Any]:
    host = normalize_host(hostname)
    port = safe_port(port)
    mode = "full"
    started = time.monotonic()
    errors: list[str] = []
    _notify(progress, "Resolving hostname", 5)
    try:
        addresses = sorted({item[4][0] for item in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)})
    except Exception as exc:
        addresses = []
        errors.append(f"DNS resolution failed: {exc}")

    _notify(progress, "Validating certificate chain", 15)
    verified = _basic_handshake(host, port, timeout, True)
    trust_valid = True if verified.get("ok") else False
    trust_error = verified.get("error") if not verified.get("ok") else None
    handshake = verified
    if not verified.get("ok"):
        handshake = _basic_handshake(host, port, timeout, False)
    if not handshake.get("ok"):
        errors.append(handshake.get("error", "TLS handshake failed"))
        base = {
            "hostname": host,
            "port": port,
            "country": country,
            "sector": sector,
            "source": source,
            "mode": mode,
            "scan_time": utc_now_iso(),
            "duration_seconds": round(time.monotonic() - started, 3),
            "status": "failed",
            "addresses": addresses,
            "certificate": {"trust_valid": trust_valid, "trust_error": trust_error, "revocation_status": "unknown"},
            "protocols": {},
            "key_exchange": {},
            "ciphers": {},
            "errors": errors,
            "capabilities": scanner_capabilities(),
        }
        return score_scan(base)

    _notify(progress, "Parsing X.509 certificate", 28)
    certificate, cert_object = _certificate_details(handshake["certificate_der"], trust_valid, trust_error)
    hostname_valid, hostname_error = _hostname_matches(host, cert_object)
    certificate["hostname_valid"] = hostname_valid
    certificate["hostname_error"] = hostname_error

    _notify(progress, "Inspecting OpenSSL handshake evidence", 38)
    openssl_result = _run_openssl_s_client(host, port, timeout)
    chain = openssl_result.get("pem_chain", [])
    certificate["chain_length"] = len(chain) or 1
    certificate["chain_complete"] = trust_valid or len(chain) > 1
    certificate["ocsp_stapling"] = openssl_result.get("ocsp_stapling")
    stapled = openssl_result.get("ocsp_status")
    if stapled in {"good", "revoked", "unknown"}:
        certificate["revocation_status"] = stapled
        certificate["revocation_source"] = "stapled OCSP"
        certificate["revocation_detail"] = f"Stapled OCSP status: {stapled}"
    else:
        certificate["revocation_status"] = "unknown"
        certificate["revocation_source"] = None
        certificate["revocation_detail"] = "No definitive stapled OCSP response was observed"

    if certificate["revocation_status"] not in {"good", "revoked"}:
        binary = locate_openssl()
        if binary and len(chain) >= 2 and certificate.get("ocsp_uri"):
            _notify(progress, "Querying direct OCSP responder", 46)
            state, detail = _direct_ocsp(binary, chain[0], chain[1], certificate["ocsp_uri"], timeout)
            certificate["revocation_status"] = state
            certificate["revocation_source"] = "direct OCSP"
            certificate["revocation_detail"] = detail
        if certificate["revocation_status"] not in {"good", "revoked"} and certificate.get("crl_uris"):
            _notify(progress, "Checking certificate revocation list", 52)
            state, detail = _check_crl(cert_object, certificate["crl_uris"], timeout)
            certificate["revocation_status"] = state
            certificate["revocation_source"] = "CRL"
            certificate["revocation_detail"] = detail

    _notify(progress, "Testing protocol versions", 58)
    protocols = {name: _probe_protocol(host, port, timeout, attribute) for name, attribute in PROTOCOL_VERSIONS}
    ssl3_state, ssl3_detail = _probe_ssl3(host, port, timeout)
    ssl2_state, ssl2_detail = _probe_ssl2(host, port, timeout)
    protocols["SSL 3.0"] = ssl3_state
    protocols["SSL 2.0"] = ssl2_state
    protocol_probe_details = {
        "SSL 3.0": ssl3_detail,
        "SSL 2.0": ssl2_detail,
    }

    negotiated_cipher = openssl_result.get("cipher") or handshake.get("cipher")
    accepted = [negotiated_cipher] if negotiated_cipher else []
    accepted_details = (
        [{
            "name": negotiated_cipher,
            "protocol": handshake.get("protocol") or openssl_result.get("protocol"),
            "bits": handshake.get("cipher_bits"),
        }]
        if negotiated_cipher
        else []
    )
    attempted = 1 if negotiated_cipher else 0
    if protocols.get("TLS 1.2") == "supported":
        _notify(progress, "Enumerating TLS 1.2 cipher suites", 68)
        enumerated, enumerated_details, attempted_count = _enumerate_tls12_ciphers(host, port, timeout)
        accepted = list(dict.fromkeys(accepted + enumerated))
        known_details = {item.get("name"): item for item in accepted_details}
        for item in enumerated_details:
            known_details[item.get("name")] = item
        accepted_details = list(known_details.values())
        attempted += attempted_count

    method = openssl_result.get("temp_key_method")
    if not method and negotiated_cipher:
        upper = negotiated_cipher.upper()
        method = "ECDHE" if "ECDHE" in upper else "DHE" if "DHE" in upper else "RSA" if "RSA" in upper else "TLS 1.3 integrated key exchange" if handshake.get("protocol") == "TLSv1.3" else "unknown"
    method_upper = (method or "").upper()
    forward_secrecy = True if any(marker in method_upper for marker in ("ECDHE", "DHE", "X25519", "X448", "TLS 1.3")) else False if method and "RSA" in method_upper else None
    key_observations: list[dict[str, Any]] = []
    if method:
        key_observations.append(
            {
                "cipher": negotiated_cipher,
                "method": method,
                "bits": openssl_result.get("temp_key_bits"),
            }
        )
    _notify(progress, "Measuring accepted Diffie-Hellman keys", 84)
    for cipher_name in accepted:
        upper = cipher_name.upper()
        if "DHE" not in upper or "ECDHE" in upper:
            continue
        observation = _probe_key_exchange_cipher(host, port, timeout, cipher_name)
        if observation and observation not in key_observations:
            key_observations.append(observation)
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
    cipher_bits = [int(item["bits"]) for item in accepted_details if isinstance(item.get("bits"), int)]

    _notify(progress, "Calculating explainable score", 92)
    scan = {
        "hostname": host,
        "port": port,
        "country": country,
        "sector": sector,
        "source": source,
        "mode": mode,
        "scan_time": utc_now_iso(),
        "duration_seconds": round(time.monotonic() - started, 3),
        "status": "completed",
        "addresses": addresses,
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
        },
        "ciphers": {
            "negotiated": negotiated_cipher,
            "negotiated_bits": handshake.get("cipher_bits"),
            "accepted": accepted,
            "accepted_details": accepted_details,
            "weakest_bits": min(cipher_bits) if cipher_bits else handshake.get("cipher_bits"),
            "strongest_bits": max(cipher_bits) if cipher_bits else handshake.get("cipher_bits"),
            "attempted": attempted,
            "enumeration_complete": attempted > 1,
        },
        "secure_renegotiation": openssl_result.get("secure_renegotiation"),
        "compression": openssl_result.get("compression"),
        "alpn": openssl_result.get("alpn") or handshake.get("alpn"),
        "errors": errors + ([openssl_result["error"]] if openssl_result.get("error") else []),
        "capabilities": scanner_capabilities(),
        "raw_evidence": {
            "openssl_excerpt": openssl_result.get("raw", "")[-8000:],
            "legacy_protocol_probes": protocol_probe_details,
        },
    }
    result = score_scan(scan)
    _notify(progress, "Scan complete", 100)
    return result
