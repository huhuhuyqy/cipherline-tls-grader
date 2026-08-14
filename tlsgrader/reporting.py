from __future__ import annotations

import csv
import html
import io
from typing import Any

from .analysis import deduplicate_newest
from .utils import is_current_methodology, json_dumps, utc_now_iso


def _spreadsheet_safe(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    stripped = value.lstrip()
    return "'" + value if stripped.startswith(("=", "+", "-", "@")) else value


def _methodology_status(scan: dict[str, Any]) -> str:
    return "current" if is_current_methodology(scan) else "legacy_methodology"


def _legacy_state(protocols: dict[str, Any]) -> str:
    states = [protocols.get(item) for item in ("TLS 1.0", "TLS 1.1", "SSL 3.0", "SSL 2.0")]
    if any(state == "supported" for state in states):
        return "supported"
    if states and all(state in {"unsupported", "not_supported"} for state in states):
        return "not_supported"
    return "unknown"


def scans_csv(scans: list[dict[str, Any]]) -> str:
    output = io.StringIO(newline="")
    fields = [
        "hostname", "port", "country", "sector", "source", "scan_time", "status",
        "assessment_version", "evidence_schema_version", "methodology_status", "error_code",
        "errors_json", "diagnostic", "overall", "grade", "certificate", "protocol",
        "key_exchange", "cipher", "score_weights_json", "certificate_trust", "hostname_valid",
        "revocation_status", "tls13", "tls12", "tls11", "tls10", "ssl3", "ssl2",
        "legacy_tls", "protocol_coverage_percent", "protocol_calculated_json",
        "protocol_not_calculated_json", "cipher_inferred_unsupported_count",
        "cipher_inference_json", "minimum_dhe_bits", "minimum_cipher_bits", "accepted_ciphers_json",
        "accepted_cipher_details_json", "findings_json", "scanner_environment_json",
    ]
    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()
    for scan in scans:
        scores = scan.get("scores", {})
        protocols = scan.get("protocols", {})
        certificate = scan.get("certificate", {})
        ciphers = scan.get("ciphers", {})
        protocol_coverage = scores.get("coverage", {}).get("protocol", {})
        cipher_coverage = ciphers.get("coverage", {})
        scored = scan.get("status") == "completed" and isinstance(scores.get("overall"), (int, float))
        writer.writerow(
            {
                "hostname": _spreadsheet_safe(scan.get("hostname")),
                "port": scan.get("port"),
                "country": _spreadsheet_safe(scan.get("country")),
                "sector": _spreadsheet_safe(scan.get("sector")),
                "source": _spreadsheet_safe(scan.get("source")),
                "scan_time": scan.get("scan_time"),
                "status": scan.get("status"),
                "assessment_version": scan.get("assessment_version"),
                "evidence_schema_version": scan.get("evidence_schema_version"),
                "methodology_status": _methodology_status(scan),
                "error_code": scan.get("error_code"),
                "errors_json": json_dumps(scan.get("errors", [])),
                "diagnostic": _spreadsheet_safe(scan.get("diagnostic", "")),
                "overall": scores.get("overall") if scored else None,
                "grade": scores.get("grade") if scored else "N/A",
                "certificate": scores.get("certificate") if scored else None,
                "protocol": scores.get("protocol") if scored else None,
                "key_exchange": scores.get("key_exchange") if scored else None,
                "cipher": scores.get("cipher") if scored else None,
                "score_weights_json": json_dumps(scores.get("weights", {})),
                "certificate_trust": certificate.get("trust_valid"),
                "hostname_valid": certificate.get("hostname_valid"),
                "revocation_status": certificate.get("revocation_status"),
                "tls13": protocols.get("TLS 1.3"),
                "tls12": protocols.get("TLS 1.2"),
                "tls11": protocols.get("TLS 1.1"),
                "tls10": protocols.get("TLS 1.0"),
                "ssl3": protocols.get("SSL 3.0"),
                "ssl2": protocols.get("SSL 2.0"),
                "legacy_tls": _legacy_state(protocols),
                "protocol_coverage_percent": protocol_coverage.get("percent"),
                "protocol_calculated_json": json_dumps(protocol_coverage.get("calculated", [])),
                "protocol_not_calculated_json": json_dumps(protocol_coverage.get("not_calculated", [])),
                "cipher_inferred_unsupported_count": cipher_coverage.get("inferred_unsupported_count", 0),
                "cipher_inference_json": json_dumps(cipher_coverage.get("inference")),
                "minimum_dhe_bits": scan.get("key_exchange", {}).get("minimum_dhe_bits"),
                "minimum_cipher_bits": ciphers.get("weakest_bits"),
                "accepted_ciphers_json": json_dumps(ciphers.get("accepted", [])),
                "accepted_cipher_details_json": json_dumps(ciphers.get("accepted_details", [])),
                "findings_json": json_dumps(scan.get("findings", [])),
                "scanner_environment_json": json_dumps(scan.get("capabilities", {})),
            }
        )
    return output.getvalue()


def report_html(scans: list[dict[str, Any]], analysis: dict[str, Any]) -> str:
    def esc(value: Any) -> str:
        return html.escape(str(value if value is not None else "--"))

    def bars(values: dict[str, dict[str, Any]]) -> str:
        return "".join(
            f"<div class='bar-row'><b>{esc(name)}</b><div class='track'><i style='width:{max(0, min(100, float(data.get('mean') or 0)))}%'></i></div><strong>{esc(data.get('mean'))}</strong></div>"
            for name, data in values.items()
        )

    analysis_eligible = [
        scan
        for scan in scans
        if scan.get("status") == "completed"
        and is_current_methodology(scan)
        and isinstance(scan.get("scores", {}).get("overall"), (int, float))
    ]
    included, _ = deduplicate_newest(analysis_eligible)
    included_objects = {id(scan) for scan in included}

    def inclusion(scan: dict[str, Any]) -> str:
        status = scan.get("status")
        if status == "failed":
            return "Excluded: collection failed"
        if status in {"cancelled", "inconclusive"}:
            return f"Excluded: {status} assessment"
        if _methodology_status(scan) != "current":
            return "Excluded: legacy methodology"
        if status != "completed" or not isinstance(scan.get("scores", {}).get("overall"), (int, float)):
            return "Excluded: not scored"
        if id(scan) not in included_objects:
            return "Excluded: older duplicate"
        return "Included"

    def report_score(scan: dict[str, Any], field: str, fallback: str = "--") -> Any:
        scores = scan.get("scores", {})
        if scan.get("status") != "completed" or not isinstance(scores.get("overall"), (int, float)):
            return fallback
        return scores.get(field)

    def protocol_coverage_text(scan: dict[str, Any]) -> str:
        coverage = scan.get("scores", {}).get("coverage", {}).get("protocol", {})
        omitted = coverage.get("not_calculated", [])
        if omitted:
            return "Not calculated: " + ", ".join(str(item) for item in omitted)
        if coverage.get("total_count"):
            return f"Calculated: {coverage.get('calculated_count')}/{coverage.get('total_count')}"
        return "Not recorded"

    def cipher_coverage_text(scan: dict[str, Any]) -> str:
        coverage = scan.get("ciphers", {}).get("coverage", {})
        inferred = int(coverage.get("inferred_unsupported_count") or 0)
        inference = coverage.get("inference") or {}
        if inferred:
            confidence = str(inference.get("confidence") or "inferred").replace("_", " ")
            return f"{inferred} inferred unsupported ({confidence})"
        if coverage.get("candidate_count") is not None:
            return f"{coverage.get('definitive_count', 0)}/{coverage.get('candidate_count', 0)} classified"
        return "Not recorded"

    rows = "".join(
        f"<tr><td>{esc(scan.get('hostname'))}</td><td>{esc(scan.get('country'))}</td><td>{esc(scan.get('sector'))}</td>"
        f"<td>{esc(report_score(scan, 'overall', 'Not scored'))}</td><td><b>{esc(report_score(scan, 'grade', 'N/A'))}</b></td>"
        f"<td>{esc(scan.get('protocols', {}).get('TLS 1.3'))}</td><td>{esc(scan.get('protocols', {}).get('SSL 3.0'))}</td>"
        f"<td>{esc(scan.get('protocols', {}).get('SSL 2.0'))}</td><td>{esc(scan.get('key_exchange', {}).get('minimum_dhe_bits'))}</td>"
        f"<td>{esc(scan.get('ciphers', {}).get('weakest_bits'))}</td><td>{esc(scan.get('scan_time'))}</td>"
        f"<td>{esc(protocol_coverage_text(scan))}</td><td>{esc(cipher_coverage_text(scan))}</td>"
        f"<td>{esc(_methodology_status(scan).replace('_', ' '))}</td><td>{esc(inclusion(scan))}</td></tr>"
        for scan in scans
    ) or "<tr><td colspan='15'>No scan results available.</td></tr>"

    selection = analysis.get("selection", {})
    comparison = analysis.get("comparison", {})
    summaries = analysis.get("selected_summaries", {})
    ready = bool(analysis.get("comparison_ready"))
    title = f"{esc(selection.get('group_a'))} vs {esc(selection.get('group_b'))}" if ready else "No comparison selected"
    stats = ""
    if ready:
        interval = comparison.get("bootstrap_ci_95") or ["--", "--"]
        stats = (
            f"<dl><dt>Observed difference</dt><dd>{esc(comparison.get('observed_difference'))}</dd>"
            f"<dt>Two-sided p-value</dt><dd>{esc(comparison.get('p_value'))}</dd>"
            f"<dt>Cliff's delta</dt><dd>{esc(comparison.get('cliffs_delta'))}</dd>"
            f"<dt>Bootstrap 95% CI</dt><dd>{esc(interval)}</dd>"
            f"<dt>Control field</dt><dd>{esc(selection.get('stratum_field'))}</dd>"
            f"<dt>Selected strata</dt><dd>{esc(', '.join(selection.get('strata') or []))}</dd></dl>"
        )
    cards = "".join(
        f"<div class='card'><small>{esc(card.get('group'))} / {esc(card.get('stratum'))}</small>"
        f"<strong>{esc(card.get('summary', {}).get('mean'))}</strong>"
        f"<span>mean score / n={esc(card.get('summary', {}).get('n'))}</span></div>"
        for card in analysis.get("group_cards", [])
    )
    methodology = analysis.get("methodology", {})
    overall = analysis.get("overall_summary", {})
    overall_card = (
        f"<div class='card'><small>All current-method completed sites</small><strong>{esc(overall.get('mean'))}</strong>"
        f"<span>mean score / n={esc(overall.get('n'))} / TLS 1.3={esc(overall.get('tls13_rate'))}%</span></div>"
    )
    limitations = "".join(f"<li>{esc(item)}</li>" for item in methodology.get("limitations", []))
    conclusion = comparison.get("conclusion") or "Choose a comparison dimension and two labels in Analysis before exporting to include an inferential comparison."
    return f"""<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width'>
<title>TLS Grader Research Report</title><style>
body{{font:15px/1.55 system-ui;margin:0;background:#fff;color:#171a20}}main{{max-width:1120px;margin:auto;padding:44px 24px}}
h1{{font-size:34px;margin:0}}h2{{margin-top:38px}}.muted,small{{color:#5c5e62}}.notice{{background:#f4f4f4;border-left:4px solid #3e6ae1;padding:16px;margin:16px 0}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px;margin:22px 0}}.card{{background:#f4f4f4;padding:18px}}
.card strong{{display:block;font-size:28px;color:#3e6ae1}}.comparison{{background:#f4f4f4;padding:22px}}
.bar-row{{display:grid;grid-template-columns:140px 1fr 45px;gap:12px;align-items:center;margin:14px 0}}.track{{height:18px;background:#d0d1d2}}.track i{{display:block;height:100%;background:#3e6ae1}}
dl{{display:grid;grid-template-columns:1fr auto}}dt,dd{{padding:8px 0;border-bottom:1px solid #d0d1d2}}dd{{margin:0;font-weight:600}}table{{width:100%;border-collapse:collapse}}th,td{{padding:10px;border-bottom:1px solid #d0d1d2;text-align:left}}th{{color:#5c5e62}}
@media(max-width:760px){{.grid{{grid-template-columns:1fr 1fr}}}}@media print{{main{{padding:0}}}}
</style></head><body><main><p class='muted'>P3 / Local TLS Security Grader</p><h1>Research evidence report</h1>
<p>Generated {esc(utc_now_iso())}. {esc(analysis.get('total_collected'))} current-method unique completed observations; {esc(analysis.get('duplicate_observations_excluded'))} older duplicates and {esc(analysis.get('legacy_methodology_excluded'))} legacy-method records excluded from analysis.</p>
<div class='notice'><b>{title}</b><br>{esc(conclusion)}</div>
<section class='comparison'><h2>User-selected comparison</h2>{bars(summaries)}{stats}</section>
<h2>Descriptive and selected groups</h2><div class='grid'>{overall_card}{cards}</div>
<h2>Evidence audit trail</h2><table><thead><tr><th>Host</th><th>Country</th><th>Sector</th><th>Score</th><th>Grade</th><th>TLS 1.3</th><th>SSL 3.0</th><th>SSL 2.0</th><th>Min DHE</th><th>Min cipher</th><th>Scanned</th><th>Protocol coverage</th><th>Cipher coverage</th><th>Method</th><th>Analysis use</th></tr></thead><tbody>{rows}</tbody></table>
<h2>Method</h2><p>{esc(methodology.get('test'))}. {esc(methodology.get('effect_size'))}. {esc(methodology.get('uncertainty'))}. {esc(methodology.get('sample_rule'))}.</p>
<h2>Limitations</h2><ul>{limitations}</ul>
<p class='muted'>This standalone report contains no external scripts, fonts, or cloud resources.</p></main></body></html>"""
