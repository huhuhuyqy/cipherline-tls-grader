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
    "ADH",
    "AECDH",
)

PROTOCOL_RULES = (
    ("TLS 1.3", 10.0, "modern"),
    ("TLS 1.2", 35.0, "modern"),
    ("TLS 1.1", 25.0, "legacy"),
    ("TLS 1.0", 30.0, "legacy"),
    ("SSL 3.0", 45.0, "legacy"),
    ("SSL 2.0", 60.0, "legacy"),
)
EXPECTED_PROTOCOLS = tuple(item[0] for item in PROTOCOL_RULES)
NOT_SCORED_STATUSES = {"failed", "partial", "inconclusive", "cancelled"}


def finding(severity: str, code: str, title: str, detail: str, remediation: str = "") -> dict[str, str]:
    return {
        "severity": severity,
        "code": code,
        "title": title,
        "detail": detail,
        "remediation": remediation,
    }


def _incomplete_coverage_penalty(coverage: Any, maximum: float) -> tuple[float, int, int]:
    if not isinstance(coverage, dict) or coverage.get("complete") is True:
        return 0.0, 0, 0
    candidates = max(0, int(coverage.get("candidate_count") or 0))
    definitive = max(0, min(candidates, int(coverage.get("definitive_count") or 0)))
    ratio = definitive / candidates if candidates else 0.0
    return maximum * (1.0 - ratio), definitive, candidates


def _certificate_score(scan: dict[str, Any], findings: list[dict[str, str]]) -> float:
    cert = scan.get("certificate", {})
    score = 100.0

    if cert.get("trust_valid") is False:
        score -= 30
        findings.append(finding("critical", "CERT_UNTRUSTED", "Certificate chain is not trusted", cert.get("trust_error", "Trust validation failed"), "Install a complete chain issued by a trusted public CA."))
    elif cert.get("trust_valid") is True:
        findings.append(finding("pass", "CERT_TRUSTED", "Certificate chain is trusted", "The chain validated against the recorded local trust store."))
    elif cert.get("trust_state") == "validity_failed":
        findings.append(
            finding(
                "info",
                "CERT_VALIDITY_VERIFY_FAILURE",
                "Certificate validation stopped at the validity check",
                "The verifier reported an expired or not-yet-valid certificate; this is scored by the separate validity finding and is not labelled as an untrusted chain.",
            )
        )
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
    if cert.get("ocsp_stapling_verified") is True:
        findings.append(finding("pass", "OCSP_STAPLED", "OCSP stapling is enabled", "The server supplied a stapled certificate-status response."))
    elif cert.get("ocsp_uri"):
        findings.append(finding("info", "OCSP_NOT_STAPLED", "OCSP stapling was not observed", "The certificate publishes an OCSP responder but no stapled response was detected."))

    return clamp(score)


def _protocol_score(
    scan: dict[str, Any], findings: list[dict[str, str]]
) -> tuple[float | None, dict[str, Any]]:
    protocols = scan.get("protocols", {})
    supported = {name for name, state in protocols.items() if state == "supported"}
    inferred_unsupported = sorted(name for name, state in protocols.items() if state == "inferred_unsupported")
    calculated = [
        name for name, _penalty, _kind in PROTOCOL_RULES
        if protocols.get(name) in {"supported", "unsupported", "not_supported", "inferred_unsupported"}
    ]
    not_calculated = [name for name in EXPECTED_PROTOCOLS if name not in calculated]
    total_weight = sum(penalty for _name, penalty, _kind in PROTOCOL_RULES)
    calculated_weight = sum(
        penalty for name, penalty, _kind in PROTOCOL_RULES if name in calculated
    )
    observed_deduction = 0.0

    if "TLS 1.3" in calculated and "TLS 1.3" not in supported:
        observed_deduction += 10
        findings.append(finding("warning", "NO_TLS13", "TLS 1.3 was not detected", "TLS 1.3 should be preferred when operationally possible.", "Enable TLS 1.3 while retaining secure TLS 1.2 compatibility if required."))
    elif "TLS 1.3" in supported:
        findings.append(finding("pass", "TLS13", "TLS 1.3 is supported", "The newest tested TLS version negotiated successfully."))
    if "TLS 1.2" in calculated and "TLS 1.2" not in supported:
        observed_deduction += 35
        findings.append(finding("critical", "NO_TLS12", "TLS 1.2 was not detected", "The service lacks the broadly required modern compatibility baseline."))
    for version, deduction in (("TLS 1.1", 25), ("TLS 1.0", 30), ("SSL 3.0", 45), ("SSL 2.0", 60)):
        if version in supported:
            observed_deduction += deduction
            findings.append(finding("critical" if version.startswith("SSL") else "warning", "LEGACY_" + version.replace(" ", "").replace(".", ""), f"Obsolete protocol enabled: {version}", "Legacy protocols expose clients to known weaknesses and downgrade risk.", f"Disable {version}."))
    if supported and supported.issubset({"TLS 1.2", "TLS 1.3"}) and not not_calculated and not inferred_unsupported:
        findings.append(finding("pass", "PROTOCOL_MODERN", "Only modern tested TLS versions are enabled", ", ".join(sorted(supported))))
    elif not_calculated:
        findings.append(
            finding(
                "info",
                "PROTOCOL_CHECKS_NOT_CALCULATED",
                "Some protocol checks were not calculated",
                "No definitive result; excluded from the protocol score: " + ", ".join(not_calculated),
                "Retry from a stable network to increase protocol-score coverage.",
            )
        )
    if inferred_unsupported:
        findings.append(
            finding(
                "info",
                "PROTOCOL_REJECTION_INFERRED",
                "Legacy protocol rejection was inferred",
                "Repeated post-ClientHello rejection, without a definitive protocol alert, for: " + ", ".join(inferred_unsupported),
            )
        )
    no_protocol = not supported and bool(calculated) and not not_calculated
    if no_protocol:
        findings.append(finding("critical", "NO_PROTOCOL", "No tested TLS protocol negotiated", "The endpoint was unreachable or incompatible with the probe."))
    score = (
        clamp(100.0 - observed_deduction * total_weight / calculated_weight)
        if calculated_weight > 0
        else None
    )
    if no_protocol:
        score = 0.0
    coverage = {
        "calculated": calculated,
        "not_calculated": not_calculated,
        "calculated_count": len(calculated),
        "total_count": len(EXPECTED_PROTOCOLS),
        "calculated_weight": round(calculated_weight, 1),
        "total_weight": round(total_weight, 1),
        "percent": round(calculated_weight / total_weight * 100, 1) if total_weight else 0.0,
        "partial": bool(not_calculated),
    }
    return score, coverage


def _key_exchange_score(scan: dict[str, Any], findings: list[dict[str, str]]) -> float:
    key = scan.get("key_exchange", {})
    score = 100.0
    method = (key.get("method") or "unknown").upper()
    bits = key.get("bits")
    fs = key.get("forward_secrecy")
    suite_details = [
        item for item in scan.get("ciphers", {}).get("accepted_details", [])
        if isinstance(item, dict)
    ]
    static_rsa = [
        item.get("name", "unknown") for item in suite_details
        if str(item.get("key_exchange", "")).upper() in {"RSA", "STATIC RSA"}
    ]
    anonymous = [
        item.get("name", "unknown") for item in suite_details
        if str(item.get("authentication", "")).upper() in {"NONE", "ANONYMOUS", "NULL"}
        or str(item.get("name", "")).upper().startswith(("ADH-", "AECDH-"))
    ]

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
    if anonymous:
        score -= 60
        findings.append(
            finding(
                "critical",
                "ANONYMOUS_CIPHER",
                "Anonymous TLS authentication was accepted",
                ", ".join(anonymous[:12]),
                "Disable anonymous DH/ECDH cipher suites.",
            )
        )
    if static_rsa or method in {"RSA", "STATIC RSA"}:
        score -= 25
        findings.append(
            finding(
                "warning",
                "STATIC_RSA",
                "Static RSA key exchange was accepted",
                ", ".join(static_rsa[:12]) if static_rsa else "The negotiated suite uses static RSA.",
                "Disable static RSA suites and retain ephemeral ECDHE/DHE suites.",
            )
        )
    coverage_penalty, definitive, candidates = _incomplete_coverage_penalty(
        key.get("dhe_coverage"), 25.0
    )
    if coverage_penalty:
        score -= coverage_penalty
        findings.append(
            finding(
                "warning",
                "DHE_COVERAGE_PARTIAL",
                "DHE parameter coverage is incomplete",
                f"{definitive}/{candidates} accepted-DHE candidates produced definitive parameter evidence; {coverage_penalty:.1f} points deducted from the key-exchange component.",
                "Retry the assessment from a stable network to improve DHE coverage.",
            )
        )
    return clamp(score)


def _cipher_score(scan: dict[str, Any], findings: list[dict[str, str]]) -> float:
    cipher_data = scan.get("ciphers", {})
    accepted = list(dict.fromkeys(cipher_data.get("accepted", []) + ([cipher_data.get("negotiated")] if cipher_data.get("negotiated") else [])))
    score = 100.0
    details = cipher_data.get("accepted_details", [])
    metadata = {
        str(item.get("name")): item
        for item in details
        if isinstance(item, dict) and item.get("name")
    }

    def is_cbc(name: str) -> bool:
        item = metadata.get(name, {})
        symmetric = str(item.get("symmetric", "")).lower()
        if symmetric.endswith("-cbc") or "cbc" in symmetric or "CBC" in name.upper():
            return True
        upper = name.upper()
        return (
            any(prefix in upper for prefix in ("AES", "CAMELLIA", "ARIA", "SEED"))
            and "-SHA" in upper
            and not any(mode in upper for mode in ("GCM", "CCM", "CHACHA20"))
        )

    def is_weak(name: str) -> bool:
        item = metadata.get(name, {})
        authentication = str(item.get("authentication", "")).upper()
        return (
            any(marker in name.upper() for marker in WEAK_CIPHER_MARKERS)
            or authentication in {"NONE", "ANONYMOUS", "NULL"}
        )

    weak = [name for name in accepted if is_weak(name)]
    cbc = [name for name in accepted if is_cbc(name)]
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
    if accepted and not weak and not cbc and not below_128 and cipher_data.get("enumeration_complete") is not False:
        findings.append(finding("pass", "CIPHERS_MODERN", "Observed cipher suites are modern", ", ".join(accepted[:8])))
    if not accepted:
        score -= 20
        findings.append(finding("info", "CIPHER_UNKNOWN", "Cipher evidence is incomplete", "No accepted or negotiated cipher was recorded."))
    if scan.get("compression") is True:
        score -= 15
        findings.append(finding("warning", "TLS_COMPRESSION", "TLS compression is enabled", "TLS-level compression can enable information leakage attacks.", "Disable TLS compression."))
    elif scan.get("compression") is False:
        findings.append(finding("pass", "NO_COMPRESSION", "TLS compression is disabled", "Compression: NONE"))
    coverage_penalty, definitive, candidates = _incomplete_coverage_penalty(
        cipher_data.get("coverage"), 30.0
    )
    if cipher_data.get("enumeration_complete") is not True and not isinstance(cipher_data.get("coverage"), dict):
        coverage_penalty, definitive, candidates = 30.0, 0, 0
    if coverage_penalty:
        score -= coverage_penalty
        findings.append(
            finding(
                "warning",
                "CIPHER_COVERAGE_PARTIAL",
                "TLS 1.2 cipher coverage is incomplete",
                f"{definitive}/{candidates} candidates received a definitive classification; {coverage_penalty:.1f} points deducted from the cipher component.",
                "Retry the assessment from a stable network to improve cipher coverage.",
            )
        )
    return clamp(score)


def grade_for(score: float, cap: str | None = None) -> str:
    grade = "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70 else "D" if score >= 60 else "F"
    if cap and "ABCDF".index(grade) < "ABCDF".index(cap):
        return cap
    return grade


def score_scan(scan: dict[str, Any], weights: dict[str, float] | None = None) -> dict[str, Any]:
    weights = {**DEFAULT_WEIGHTS, **(weights or {})}
    status = scan.get("status")
    if status in NOT_SCORED_STATUSES:
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
        result["recommendation"] = "Retry the target after resolving the collection or coverage error; no security grade was assigned."
        return result
    findings: list[dict[str, str]] = []
    certificate = _certificate_score(scan, findings)
    protocol, protocol_coverage = _protocol_score(scan, findings)
    key_exchange = _key_exchange_score(scan, findings)
    cipher = _cipher_score(scan, findings)
    cipher_coverage_penalty, _cipher_definitive, _cipher_candidates = _incomplete_coverage_penalty(
        scan.get("ciphers", {}).get("coverage"), 30.0
    )
    if scan.get("ciphers", {}).get("enumeration_complete") is not True and not isinstance(
        scan.get("ciphers", {}).get("coverage"), dict
    ):
        cipher_coverage_penalty = 30.0
    dhe_coverage_penalty, _dhe_definitive, _dhe_candidates = _incomplete_coverage_penalty(
        scan.get("key_exchange", {}).get("dhe_coverage"), 25.0
    )
    configuration_components = [
        (protocol, weights["protocol"]),
        (key_exchange, weights["key_exchange"]),
        (cipher, weights["cipher"]),
    ]
    available_configuration_weight = sum(
        weight for value, weight in configuration_components if value is not None
    )
    configuration = sum(
        value * weight for value, weight in configuration_components if value is not None
    ) / available_configuration_weight
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
        "protocol": round(protocol, 1) if protocol is not None else None,
        "key_exchange": round(key_exchange, 1),
        "cipher": round(cipher, 1),
        "configuration": round(configuration, 1),
        "overall": round(clamp(overall), 1),
        "grade": grade_for(overall, cap),
        "grade_cap": cap,
        "weights": weights,
        "coverage": {"protocol": protocol_coverage},
        "coverage_penalties": {
            "certificate_trust_unknown": 8.0 if scan.get("certificate", {}).get("trust_valid") is None else 0.0,
            "cipher": round(cipher_coverage_penalty, 1),
            "dhe": round(dhe_coverage_penalty, 1),
        },
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
