# Sampling data

Use `candidates_template.csv` as the import format. Replace every placeholder with a manually verified target and retain the directory or page used to identify it in `source`.

`tls_sites_200_balanced.csv` is the prepared research candidate list. It contains 50 rows in each of the four strata and can be imported directly in **Scan lab → Batch collection**. Re-check eligibility and accessibility before the final collection date; an unreachable candidate should be documented rather than silently replaced after seeing its score.

`tls_sites_400_balanced.csv` is the expanded candidate list. It preserves all 200 targets above and adds 50 new targets to every stratum, giving 100 rows per stratum and 400 unique hostnames in total. The added Singapore school rows come from the 2026 MOE dataset on data.gov.sg; government and Chinese university targets retain their official directory sources in the `source` column.

Use `tls_sites_pilot_4.csv` after a fresh restart to verify the complete batch path with one target from each stratum before submitting all 200 candidates.

The final study requires 50 valid observations in each stratum:

- China — Government
- China — Education
- Singapore — Government
- Singapore — Education

Eligibility must be determined before TLS scanning. Record redirects and unreachable hosts instead of silently substituting them.
