# CIPHERLINE v2.3.0

Local TLS security grading and research tool for SUTD Tools Lab 1 Project P3.

## Start

Use CPython 3.11 through 3.13. The submitted environment was verified with
CPython 3.11.15 and the dependency version pinned in `requirements.txt`.

The easiest option is to double-click `run_local.bat`, wait for
`http://127.0.0.1:8843` to open, and press `Ctrl+C` in the service window when
finished. In VS Code, open this folder and run the supplied task from
`Terminal -> Run Task`.

Do not open `web/index.html` directly. Scanning, SQLite storage, task progress,
analysis, and exports require the local Python service.

## Workflow

1. Upload a CSV in Scan lab, or enter one site manually.
2. Run the full TLS assessment.
3. Monitor Collection progress.
   A running collection can be cancelled; a cancelled or restart-interrupted
   collection can resume from its stored target checkpoint. One collection job
   is active at a time; within that job, two targets are assessed concurrently
   by default and results are checkpointed in original CSV order.
4. Open Evidence and click any result row for full details.
5. In Analysis, choose Country or Sector, choose Group A and Group B, then choose
   the control strata.
6. Export CSV evidence or the current user-selected HTML analysis report.

Analysis never chooses a comparison automatically. Country and sector values are
read from completed scan records, so arbitrary CSV labels are accepted.

## CSV format

A CSV may be a headerless, one-column hostname list:

```csv
google.com
gtld-servers.net
cloudflare.com
```

This format receives full scanning and descriptive analysis. For grouped
country/sector comparisons, use the labelled format:

```csv
hostname,country,sector,source
www.gov.sg,Singapore,Government,official-directory
www.nus.edu.sg,Singapore,University,official-directory
www.healthhub.sg,Singapore,Healthcare,official-directory
```

In a labelled file, `hostname` is required. The aliases `host`, `domain`,
`website`, and `url` are also accepted. `country`, `sector`, and `source` are
optional study metadata. There is no label allowlist or fixed batch row limit.

## Collection coverage

- Certificate trust, identity, validity, signature, and key strength.
- Observed OCSP stapling plus cryptographically verified direct OCSP and CRL
  evidence. Certificate-controlled revocation URLs are fetched with public-IP
  pinning, redirect revalidation, response-size limits, and the target deadline.
- TLS 1.3, 1.2, 1.1, 1.0, SSL 3.0, and SSL 2.0.
- Local TLS 1.2 cipher candidate enumeration and effective strength.
- Key exchange, forward secrecy, DHE strength, compression, ALPN, secure
  renegotiation, and raw OpenSSL evidence.

An `unsupported` SSL 2.0/3.0 result is a successful and secure test outcome.

After at least one TLS 1.2 suite has negotiated, two consecutive fast EOF
closures for the unchanged remaining suite set are recorded as lower-confidence
`inferred_unsupported`. A single EOF, timeout, reset, or EOF before any successful
suite remains indeterminate and prevents scoring. Evidence and exports disclose
the inference count, class, confidence, and attempts.

If an individual protocol probe returns `error` or `not_tested`, that check is
shown as `Not calculated`, excluded from the protocol-score denominator, and the
remaining definitive protocol checks are re-normalised. The Evidence view and
exports disclose the calculated checks, omitted checks, and weighted coverage.
Once an endpoint produces initial TLS evidence, incomplete certificate trust,
TLS 1.2 cipher coverage, and accepted-DHE parameter coverage no longer suppress
the whole score. Unknown trust deducts 8 certificate points. Missing cipher and
DHE classifications deduct proportionally to the unclassified candidate ratio,
up to 30 cipher points and 25 key-exchange points. Findings and exports disclose
the formula inputs and deduction.

A target that cannot produce any initial TLS evidence because of DNS,
connectivity, timeout, or handshake failure is retained as audit evidence but
receives `Not scored / N/A`. A manually cancelled assessment is also N/A.
It is not treated as a 59-point website and is excluded from analysis. A
completed assessment with a critical certificate problem may legitimately score
59 or lower because 59 is the F-grade ceiling, not a default failure score.

## Analysis method

The selected comparison is a two-sided stratified permutation test:

- comparing country labels controls for the selected sector labels;
- comparing sector labels controls for the selected country labels;
- at least 2 observations are required in each selected group-stratum cell;
- at least 10 observations per cell marks the result stable;
- Cliff's delta and a stratified bootstrap 95% interval are reported.

Repeated identical analysis requests are cached until scan data changes. Full
network scans remain intentionally exhaustive and may take substantial time. A
target has a 90-second reachability budget by default. After the first successful
TLS handshake, the absolute deadline is released so the full assessment can
finish; every individual network operation remains bounded by its own timeout and
manual cancellation remains cooperative.

## Data and tests

- SQLite: `data/tls_grader.db`
- CSV and standalone HTML: Evidence page
- Reset: `Reset project`

Only evidence with assessment methodology 2.3 and evidence schema 2 is current.
Older or mismatched evidence is visibly marked `legacy methodology`; it remains in
the audit trail but must not be silently mixed with current-method results. Existing
targets must be rescanned after upgrading to v2.3.0 before they can be included in
current analysis. CSV exports include source, stable error code,
diagnostic evidence, certificate state, accepted ciphers, findings, weights, and
scanner environment so results can be independently audited. `legacy_tls` is
three-state (`supported`, `not_supported`, or `unknown`).

The service binds to `127.0.0.1` by default. Mutating API calls require the
session CSRF token returned by `/api/health`, same-origin Host/Origin validation,
and `application/json`. Non-loopback binding is always rejected because this is a
local-only research console. The paginated lightweight scan endpoint is
`/api/scans?summary=1&limit=100&offset=0`; full evidence remains at
`/api/scans/{id}`, and the original GET list remains available for compatibility.

The browser has no Node.js runtime dependency. See `SPEC.md` for implemented
behaviour and `CODE_MANUAL.md` for code-level details.

## Repository and public-release hygiene

The repository intentionally contains only reproducible source material:

- Python and browser source code and local launch configuration;
- the product specification and code manual;
- a CSV template and a four-site pilot list.

Runtime databases, scan evidence, exports, logs, virtual environments, caches,
temporary files, environment files, private keys, and certificate bundles are
ignored. The complete regression suite, final 524-site study dataset, and final
technical report are maintained locally and intentionally excluded. Before making
a fork public, choose an explicit software licence and confirm that the course
permits publication. The restricted course handouts are not part of this repository.

Use the scanner only on public endpoints and within applicable authorisation,
acceptable-use, rate-limit, and legal boundaries. It performs read-only TLS
negotiation but can still create network traffic visible to remote operators.
