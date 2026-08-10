# CIPHERLINE v1.3.2

Local TLS security grading and research tool for SUTD Tools Lab 1 Project P3.

## Start

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
- OCSP stapling, direct OCSP, and CRL evidence.
- TLS 1.3, 1.2, 1.1, 1.0, SSL 3.0, and SSL 2.0.
- Local TLS 1.2 cipher candidate enumeration and effective strength.
- Key exchange, forward secrecy, DHE strength, compression, ALPN, secure
  renegotiation, and raw OpenSSL evidence.

An `unsupported` SSL 2.0/3.0 result is a successful and secure test outcome.

A target whose assessment fails because of DNS, connectivity, timeout, or
handshake errors is retained as audit evidence but receives `Not scored / N/A`.
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
network scans remain intentionally exhaustive and may take substantial time.

## Data and tests

- SQLite: `data/tls_grader.db`
- CSV and standalone HTML: Evidence page
- Reset: `Reset project`

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

See `HANDOFF.md` for project status and `CODE_MANUAL.md` for code-level details.
