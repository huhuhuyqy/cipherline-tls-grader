from __future__ import annotations

import csv
import html
import io
from typing import Any

from .utils import utc_now_iso


def scans_csv(scans: list[dict[str, Any]]) -> str:
    output = io.StringIO(newline="")
    fields = [
        "hostname", "port", "country", "sector", "scan_time", "status", "overall", "grade",
        "certificate", "protocol", "key_exchange", "cipher", "tls13", "tls12", "tls11", "tls10",
        "ssl3", "ssl2", "legacy_tls", "minimum_dhe_bits", "minimum_cipher_bits",
    ]
    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()
    for scan in scans:
        scores = scan.get("scores", {})
        protocols = scan.get("protocols", {})
        scored = scan.get("status") == "completed" and isinstance(scores.get("overall"), (int, float))
        writer.writerow(
            {
                "hostname": scan.get("hostname"),
                "port": scan.get("port"),
                "country": scan.get("country"),
                "sector": scan.get("sector"),
                "scan_time": scan.get("scan_time"),
                "status": scan.get("status"),
                "overall": scores.get("overall") if scored else None,
                "grade": scores.get("grade") if scored else "N/A",
                "certificate": scores.get("certificate") if scored else None,
                "protocol": scores.get("protocol") if scored else None,
                "key_exchange": scores.get("key_exchange") if scored else None,
                "cipher": scores.get("cipher") if scored else None,
                "tls13": protocols.get("TLS 1.3"),
                "tls12": protocols.get("TLS 1.2"),
                "tls11": protocols.get("TLS 1.1"),
                "tls10": protocols.get("TLS 1.0"),
                "ssl3": protocols.get("SSL 3.0"),
                "ssl2": protocols.get("SSL 2.0"),
                "legacy_tls": any(
                    protocols.get(version) == "supported"
                    for version in ("TLS 1.0", "TLS 1.1", "SSL 3.0", "SSL 2.0")
                ),
                "minimum_dhe_bits": scan.get("key_exchange", {}).get("minimum_dhe_bits"),
                "minimum_cipher_bits": scan.get("ciphers", {}).get("weakest_bits"),
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

    def report_score(scan: dict[str, Any], field: str, fallback: str = "--") -> Any:
        scores = scan.get("scores", {})
        if scan.get("status") != "completed" or not isinstance(scores.get("overall"), (int, float)):
            return fallback
        return scores.get(field)

    rows = "".join(
        f"<tr><td>{esc(scan.get('hostname'))}</td><td>{esc(scan.get('country'))}</td><td>{esc(scan.get('sector'))}</td>"
        f"<td>{esc(report_score(scan, 'overall', 'Not scored'))}</td><td><b>{esc(report_score(scan, 'grade', 'N/A'))}</b></td>"
        f"<td>{esc(scan.get('protocols', {}).get('TLS 1.3'))}</td><td>{esc(scan.get('protocols', {}).get('SSL 3.0'))}</td>"
        f"<td>{esc(scan.get('protocols', {}).get('SSL 2.0'))}</td><td>{esc(scan.get('key_exchange', {}).get('minimum_dhe_bits'))}</td>"
        f"<td>{esc(scan.get('ciphers', {}).get('weakest_bits'))}</td><td>{esc(scan.get('scan_time'))}</td></tr>"
        for scan in scans
    ) or "<tr><td colspan='11'>No scan results available.</td></tr>"

    selection = analysis.get("selection", {})
    comparison = analysis.get("comparison", {})
    summaries = analysis.get("selected_summaries", {})
    ready = bool(analysis.get("comparison_ready"))
    title = (
        f"{esc(selection.get('group_a'))} vs {esc(selection.get('group_b'))}"
        if ready else "No comparison selected"
    )
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
        f"<div class='card'><small>All completed sites</small>"
        f"<strong>{esc(overall.get('mean'))}</strong>"
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
<p>Generated {esc(utc_now_iso())}. {esc(analysis.get('total_collected'))} unique completed observations; {esc(analysis.get('duplicate_observations_excluded'))} older duplicates excluded.</p>
<div class='notice'><b>{title}</b><br>{esc(conclusion)}</div>
<section class='comparison'><h2>User-selected comparison</h2>{bars(summaries)}{stats}</section>
<h2>Descriptive and selected groups</h2><div class='grid'>{overall_card}{cards}</div>
<h2>Scored websites</h2><table><thead><tr><th>Host</th><th>Country</th><th>Sector</th><th>Score</th><th>Grade</th><th>TLS 1.3</th><th>SSL 3.0</th><th>SSL 2.0</th><th>Min DHE</th><th>Min cipher</th><th>Scanned</th></tr></thead><tbody>{rows}</tbody></table>
<h2>Method</h2><p>{esc(methodology.get('test'))}. {esc(methodology.get('effect_size'))}. {esc(methodology.get('uncertainty'))}. {esc(methodology.get('sample_rule'))}.</p>
<h2>Limitations</h2><ul>{limitations}</ul>
<p class='muted'>This standalone report contains no external scripts, fonts, or cloud resources.</p></main></body></html>"""
