# Sampling data

`candidates_template.csv` documents the supported labelled import format.
Replace its examples with manually verified targets and retain the directory or
page used to identify each endpoint in the `source` column.

`tls_sites_pilot_4.csv` is a four-site smoke-test list for checking the complete
batch workflow before a long collection.

The CSV is an input list, not scan evidence and not a claim that every endpoint
is reachable. Eligibility was determined before observing TLS grades. Preserve
unreachable results instead of replacing them after seeing the outcome.

The final study dataset is maintained locally and intentionally excluded from
the repository.

The repository does not publish `tls_grader.db`, exported evidence, raw OpenSSL
output, or logs. Those files may contain timestamps, resolved peer addresses,
certificate details, and operational diagnostics and remain local by default.
