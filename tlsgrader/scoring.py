from __future__ import annotations

from copy import deepcopy
from typing import Any

from .utils import clamp


DEFAULT_WEIGHTS = {
    "certificate": 0.40,
    "configuration": 0.60,
    "protocol": 0.35,
    "key_exchange": 0.35,
    "cipher": 0.30,
}


WEAK_CIPHER_MARKERS = (
    "NULL",
    "EXPORT",
    "RC4",
    "RC2",
    "DES-CBC",
    "3DES",
    "IDEA",
    "MD5",
    "ANON",
)


def finding(severity: str, code: str, title: str, detail: str, remediation: str = "") -> dict[str, str]:
    return {
        "severity": severity,
        "code": code,
        "title": title,
        "detail": detail,
        "remediation": remediation,
    }


def _certificate_score(scan: dict[str, Any], findings: list[dict[str, str]]) -> float:
    cert = scan.get("certificate", {})
    score = 100.0

    if cert.get("trust_valid") is False:
        score -= 30
        findings.append(finding("critical", "CERT_UNTRUSTED", "Certificate chain is not trusted", cert.get("trust_error", "Trust validation failed"), "Install a complete chain issued by a trusted public CA."))
    elif cert.get("trust_valid") is True:
        findings.append(finding("pass", "CERT_TRUSTED", "Certificate chain is trusted", "The chain validated against the recorded local trust store."))
    else:
        score -= 8
        findings.append(finding("warning", "CERT_TRUST_UNKNOWN", "Certificate trust could not be confirmed", "The trust check did not produce a definitive result."))

    if cert.get("hostname_valid") is False:
        score -= 20
        findings.append(finding("critical", "HOSTNAME_MISMATCH", "Certificate does not match the hostname", "The requested hostname is absent from the certificate identity fields.", "Issue a certificate whose SAN contains this hostname."))
    elif cert.get("hostname_valid") is True:
        findings.append(finding("pass", "HOSTNAME_VALID", "Certificate hostname is valid", "The hostname matches a certificate SAN or CN."))

    status = cert.get("validity_status")
    if status == "expired":
        score -= 15
        findings.append(finding("critical", "CERT_EXPIRED", "Certificate has expired", f"Expired {abs(cert.get('days_remaining', 0))} day(s) ago.", "Renew and deploy the certificate immediately."))
    elif status == "not_yet_valid":
        score -= 15
        findings.append(finding("critical", "CERT_NOT_YET_VALID", "Certificate is not yet valid", "The certificate validity period has not started."))
    elif status == "valid":
        days = cert.get("days_remaining")
        if isinstance(days, int) and days < 30:
            score -= 4
            findings.append(finding("warning", "CERT_EXPIRING", "Certificate expires soon", f"Only {days} day(s) remain.", "Renew the certificate before expiry."))
        else:
            findings.append(finding("pass", "CERT_DATE_VALID", "Certificate dates are valid", f"{days} day(s) remain." if days is not None else "The validity window contains the scan time."))

    revocation = cert.get("revocation_status", "unknown")
    if revocation == "revoked":
        score -= 15
        findings.append(finding("critical", "CERT_REVOKED", "Certificate is revoked", "OCSP or CRL evidence reports the leaf certificate as revoked.", "Replace the certificate immediately and investigate the revocation reason."))
    elif revocation == "good":
        findings.append(finding("pass", "REVOCATION_GOOD", "Certificate revocation status is good", cert.get("revocation_source", "OCSP/CRL")))
    elif revocation == "check_failed":
        score -= 5
        findings.append(finding("warning", "REVOCATION_FAILED", "Revocation check failed", cert.get("revocation_detail", "The responder or CRL could not be queried."), "Check OCSP/CRL availability and retry."))
    else:
        score -= 3
        findings.append(finding("info", "REVOCATION_UNKNOWN", "Revocation status is unknown", cert.get("revocation_detail", "No definitive OCSP or CRL evidence was available.")))

    signature = (cert.get("signature_algorithm") or "").lower()
    if "md5" in signature:
        score -= 10
        findings.append(finding("critical", "SIG_MD5", "Certificate uses an MD5 signature", signature, "Replace it with a SHA-256-or-stronger signed certificate."))
    elif "sha1" in signature or "sha-1" in signature:
        score -= 8
        findings.append(finding("critical", "SIG_SHA1", "Certificate uses a SHA-1 signature", signature, "Replace it with a SHA-256-or-stronger signed certificate."))
    elif signature:
        findings.append(finding("pass", "SIG_MODERN", "Certificate signature is modern", signature))

    key_type = cert.get("public_key_type", "unknown")
    key_size = cert.get("public_key_bits")
    if key_type == "RSA" and isinstance(key_size, int) and key_size < 2048:
        score -= 10
        findings.append(finding("critical", "RSA_TOO_SMALL", "RSA key is too short", f"RSA {key_size} bits", "Use an RSA key of at least 2048 bits or a suitable EC key."))
    elif key_type == "EC" and isinstance(key_size, int) and key_size < 224:
        score -= 10
        findings.append(finding("critical", "EC_TOO_SMALL", "EC key is too weak", f"EC {key_size} bits"))
    elif key_size:
        findings.append(finding("pass", "KEY_SIZE_OK", "Certificate public key strength is acceptable", f"{key_type} {key_size} bits"))

    if cert.get("chain_complete") is False:
        score -= 5
        findings.append(finding("warning", "CHAIN_INCOMPLETE", "Certificate chain may be incomplete", "Only the leaf certificate was observed or verification reported a missing issuer.", "Serve the required intermediate certificates."))
    if cert.get("ocsp_stapling") is True:
        findings.append(finding("pass", "OCSP_STAPLED", "OCSP stapling is enabled", "The server supplied a stapled certificate-status response."))
    elif cert.get("ocsp_uri"):
        findings.append(finding("info", "OCSP_NOT_STAPLED", "OCSP stapling was not observed", "The certificate publishes an OCSP responder but no stapled response was detected."))

    return clamp(score)


def _protocol_score(scan: dict[str, Any], findings: list[dict[str, str]]) -> float:
    protocols = scan.get("protocols", {})
    score = 100.0
    supported = {name for name, state in protocols.items() if state == "supported"}
    expected = {"TLS 1.3", "TLS 1.2", "TLS 1.1", "TLS 1.0", "SSL 3.0", "SSL 2.0"}
    incomplete = sorted(name for name in expected if protocols.get(name) in {None, "not_tested", "error"})

    if "TLS 1.3" not in supported:
        score -= 10
        findings.append(finding("warning", "NO_TLS13", "TLS 1.3 was not detected", "TLS 1.3 should be preferred when operationally possible.", "Enable TLS 1.3 while retaining secure TLS 1.2 compatibility if required."))
    else:
        findings.append(finding("pass", "TLS13", "TLS 1.3 is supported", "The newest tested TLS version negotiated successfully."))
    if "TLS 1.2" not in supported:
        score -= 35
        findings.append(finding("critical", "NO_TLS12", "TLS 1.2 was not detected", "The service lacks the broadly required modern compatibility baseline."))
    for version, deduction in (("TLS 1.1", 25), ("TLS 1.0", 30), ("SSL 3.0", 45), ("SSL 2.0", 60)):
        if version in supported:
            score -= deduction
            findings.append(finding("critical" if version.startswith("SSL") else "warning", "LEGACY_" + version.replace(" ", "").replace(".", ""), f"Obsolete protocol enabled: {version}", "Legacy protocols expose clients to known weaknesses and downgrade risk.", f"Disable {version}."))
    if supported and supported.issubset({"TLS 1.2", "TLS 1.3"}) and not incomplete:
        findings.append(finding("pass", "PROTOCOL_MODERN", "Only modern tested TLS versions are enabled", ", ".join(sorted(supported))))
    elif incomplete:
        findings.append(
            finding(
                "info",
                "PROTOCOL_COVERAGE_INCOMPLETE",
                "Protocol coverage is incomplete",
                "No definitive result for: " + ", ".join(incomplete),
                "Retry from a stable network before using this result for formal comparison.",
            )
        )
    if not supported:
        score = 0
        findings.append(finding("critical", "NO_PROTOCOL", "No tested TLS protocol negotiated", "The endpoint was unreachable or incompatible with the probe."))
    return clamp(score)


def _key_exchange_score(scan: dict[str, Any], findings: list[dict[str, str]]) -> float:
    key = scan.get("key_exchange", {})
    score = 100.0
    method = (key.get("method") or "unknown").upper()
    bits = key.get("bits")
    fs = key.get("forward_secrecy")

    if fs is True:
        findings.append(finding("pass", "FORWARD_SECRECY", "Forward secrecy is supported", method))
    elif fs is False:
        score -= 35
        findings.append(finding("warning", "NO_FORWARD_SECRECY", "Forward secrecy was not detected", method, "Prefer ECDHE or sufficiently strong ephemeral DHE key exchange."))
    else:
        score -= 8
        findings.append(finding("info", "KEY_EXCHANGE_UNKNOWN", "Key-exchange details are incomplete", "The negotiated handshake did not expose a parseable temporary key."))

    minimum_dhe_bits = key.get("minimum_dhe_bits")
    maximum_dhe_bits = key.get("maximum_dhe_bits")
    assessed_dhe_bits = minimum_dhe_bits if isinstance(minimum_dhe_bits, int) else bits if "DHE" in method and "ECDHE" not in method and isinstance(bits, int) else None
    if isinstance(assessed_dhe_bits, int):
        if assessed_dhe_bits < 1024:
            score -= 55
            findings.append(finding("critical", "DHE_CRITICAL", "Finite-field DH key is critically weak", f"Minimum accepted DHE strength: {assessed_dhe_bits} bits", "Use at least 2048-bit DHE or a recommended ECDHE group."))
        elif assessed_dhe_bits < 2048:
            score -= 30
            findings.append(finding("warning", "DHE_WEAK", "Finite-field DH key is below 2048 bits", f"Minimum accepted DHE strength: {assessed_dhe_bits} bits"))
        elif assessed_dhe_bits >= 4096:
            findings.append(finding("pass", "DHE_4096", "Finite-field DH key is very strong", f"Minimum accepted DHE strength: {assessed_dhe_bits} bits"))
        else:
            findings.append(finding("pass", "DHE_ACCEPTABLE", "Finite-field DH key meets the baseline", f"Minimum {assessed_dhe_bits} bits; maximum {maximum_dhe_bits or assessed_dhe_bits} bits"))
    if method in {"RSA", "STATIC RSA"}:
        score -= 25
        findings.append(finding("warning", "STATIC_RSA", "Static RSA key exchange detected", "Static RSA does not provide forward secrecy."))
    return clamp(score)


def _cipher_score(scan: dict[str, Any], findings: list[dict[str, str]]) -> float:
    cipher_data = scan.get("ciphers", {})
    accepted = list(dict.fromkeys(cipher_data.get("accepted", []) + ([cipher_data.get("negotiated")] if cipher_data.get("negotiated") else [])))
    score = 100.0
    weak = [name for name in accepted if any(marker in name.upper() for marker in WEAK_CIPHER_MARKERS)]
    cbc = [name for name in accepted if "CBC" in name.upper()]
    details = cipher_data.get("accepted_details", [])
    strengths = [int(item["bits"]) for item in details if isinstance(item, dict) and isinstance(item.get("bits"), int)]
    if not strengths and isinstance(cipher_data.get("negotiated_bits"), int):
        strengths = [int(cipher_data["negotiated_bits"])]
    below_128 = [item for item in details if isinstance(item, dict) and isinstance(item.get("bits"), int) and item["bits"] < 128]
    if weak:
        score -= min(70, 20 + 10 * len(weak))
        findings.append(finding("critical", "WEAK_CIPHERS", "Weak cipher suites were accepted", ", ".join(weak[:12]), "Disable NULL, export, RC4, DES/3DES, MD5, and anonymous suites."))
    if cbc:
        score -= min(20, 3 * len(cbc))
        findings.append(finding("warning", "CBC_CIPHERS", "CBC cipher suites were accepted", ", ".join(cbc[:12]), "Prefer AEAD suites such as AES-GCM or ChaCha20-Poly1305."))
    if below_128:
        score -= min(55, 25 + 5 * len(below_128))
        findings.append(
            finding(
                "critical",
                "CIPHER_BELOW_128",
                "Cipher strength below 128 bits was accepted",
                ", ".join(f"{item.get('name')} ({item.get('bits')} bits)" for item in below_128[:12]),
                "Disable every cipher with effective strength below 128 bits.",
            )
        )
    if strengths and min(strengths) >= 256:
        findings.append(finding("pass", "CIPHER_256_PLUS", "All measured ciphers provide at least 256-bit strength", f"Measured range: {min(strengths)}-{max(strengths)} bits"))
    elif strengths and min(strengths) >= 128:
        findings.append(finding("pass", "CIPHER_128_BASELINE", "All measured ciphers meet the 128-bit baseline", f"Measured range: {min(strengths)}-{max(strengths)} bits"))
    if accepted and not weak and not cbc and not below_128:
        findings.append(finding("pass", "CIPHERS_MODERN", "Observed cipher suites are modern", ", ".join(accepted[:8])))
    if not accepted:
        score -= 20
        findings.append(finding("info", "CIPHER_UNKNOWN", "Cipher evidence is incomplete", "No accepted or negotiated cipher was recorded."))
    if scan.get("compression") is True:
        score -= 15
        findings.append(finding("warning", "TLS_COMPRESSION", "TLS compression is enabled", "TLS-level compression can enable information leakage attacks.", "Disable TLS compression."))
    elif scan.get("compression") is False:
        findings.append(finding("pass", "NO_COMPRESSION", "TLS compression is disabled", "Compression: NONE"))
    return clamp(score)


def grade_for(score: float, cap: str | None = None) -> str:
    grade = "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70 else "D" if score >= 60 else "F"
    if cap and "ABCDF".index(grade) < "ABCDF".index(cap):
        return cap
    return grade


def score_scan(scan: dict[str, Any], weights: dict[str, float] | None = None) -> dict[str, Any]:
    weights = {**DEFAULT_WEIGHTS, **(weights or {})}
    if scan.get("status") == "failed":
        result = deepcopy(scan)
        detail = "; ".join(str(item) for item in scan.get("errors", []) if item) or "The TLS assessment did not complete."
        result["scores"] = {
            "certificate": None,
            "protocol": None,
            "key_exchange": None,
            "cipher": None,
            "configuration": None,
            "overall": None,
            "grade": "N/A",
            "grade_cap": None,
            "weights": weights,
            "not_scored": True,
        }
        result["findings"] = [
            finding(
                "info",
                "SCAN_NOT_COMPLETED",
                "Target was not scored",
                detail,
                "Confirm the hostname, DNS resolution, network reachability, and HTTPS availability, then retry.",
            )
        ]
        result["recommendation"] = "Retry the target after resolving the collection error; no security grade was assigned."
        return result
    findings: list[dict[str, str]] = []
    certificate = _certificate_score(scan, findings)
    protocol = _protocol_score(scan, findings)
    key_exchange = _key_exchange_score(scan, findings)
    cipher = _cipher_score(scan, findings)
    configuration = protocol * weights["protocol"] + key_exchange * weights["key_exchange"] + cipher * weights["cipher"]
    overall = certificate * weights["certificate"] + configuration * weights["configuration"]

    cert = scan.get("certificate", {})
    cap = None
    if cert.get("trust_valid") is False or cert.get("hostname_valid") is False or cert.get("validity_status") in {"expired", "not_yet_valid"} or cert.get("revocation_status") == "revoked":
        overall = min(overall, 59)
        cap = "F"
    supported = {name for name, state in scan.get("protocols", {}).items() if state == "supported"}
    if supported.intersection({"SSL 2.0", "SSL 3.0"}):
        overall = min(overall, 69)
        cap = cap or "D"

    severity_order = {"critical": 0, "warning": 1, "info": 2, "pass": 3}
    findings.sort(key=lambda item: (severity_order.get(item["severity"], 9), item["code"]))
    result = deepcopy(scan)
    result["scores"] = {
        "certificate": round(certificate, 1),
        "protocol": round(protocol, 1),
        "key_exchange": round(key_exchange, 1),
        "cipher": round(cipher, 1),
        "configuration": round(configuration, 1),
        "overall": round(clamp(overall), 1),
        "grade": grade_for(overall, cap),
        "grade_cap": cap,
        "weights": weights,
    }
    result["findings"] = findings
    result["recommendation"] = (
        "Do not trust this configuration until critical findings are corrected."
        if any(item["severity"] == "critical" for item in findings)
        else "Usable with improvements recommended."
        if any(item["severity"] == "warning" for item in findings)
        else "Strong modern TLS configuration based on the completed checks."
    )
    return result
