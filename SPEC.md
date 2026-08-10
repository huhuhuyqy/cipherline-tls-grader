# CIPHERLINE Product Specification

Status: implemented baseline, updated for the current local application.

Source requirements: `../Guidelines.pdf`, `../P3 - Tools Lab 1.pdf`, and the
approved proposal documents in the parent folder. Architecture and function-level
details are maintained in `CODE_MANUAL.md`.

## Problem Statement

People evaluating public HTTPS endpoints need a local, explainable way to determine
whether a website's certificate and TLS configuration are trustworthy without
depending on an opaque third-party grade. The course project additionally requires a
real research use case: collect a sufficiently large website dataset, compare chosen
groups, communicate uncertainty, and present the results clearly enough that every
score and conclusion can be defended.

The application must therefore join four concerns in one coherent workflow: complete
TLS evidence collection, transparent scoring, auditable local storage, and
user-selected statistical analysis. Collection failures must remain visible without
being mistaken for low security scores.

## Solution

CIPHERLINE is a local-only TLS research console. A user supplies one hostname, a
headerless hostname list, or a labelled CSV. The application performs the complete
assessment, stores evidence locally, assigns explainable component and overall scores
only to completed assessments, and exposes every finding and remediation in an audit
view. The user can then build a comparison from any country or sector labels present
in the completed dataset and export evidence or a standalone HTML report.

The interface presents the workflow as Overview, Scan Lab, Evidence, Analysis, and
Method. It uses calm, platform-familiar visual hierarchy and immediate feedback while
keeping research evidence, destructive actions, and unknown states unambiguous.

## User Stories

1. As a researcher, I want to scan one hostname, so that I can inspect an endpoint before preparing a batch.
2. As a researcher, I want to upload a labelled CSV, so that I can collect a reproducible study dataset.
3. As a researcher, I want to upload a headerless one-column hostname list, so that simple datasets work without manual reformatting.
4. As a researcher, I want hostname header aliases to be accepted, so that common CSV exports require less cleanup.
5. As a researcher, I want arbitrary country and sector labels, so that the tool is not restricted to a predefined study.
6. As a researcher, I want no artificial batch-size ceiling, so that the course sample can be collected in one workflow.
7. As a user, I want uploaded-file confirmation and target counts, so that I know exactly what will be scanned.
8. As a user, I want every batch target to receive the same full assessment, so that scores remain comparable.
9. As a user, I want live job progress and the current target, so that a long assessment never appears frozen.
10. As a user, I want one active collection job at a time, so that local resources and target websites are treated responsibly.
11. As a security analyst, I want certificate-chain trust checked, so that untrusted authentication cannot receive a passing grade.
12. As a security analyst, I want hostname identity checked against SAN/CN, so that certificate misbinding is detected.
13. As a security analyst, I want certificate dates checked, so that expired and not-yet-valid certificates are detected.
14. As a security analyst, I want revocation evidence separated into good, revoked, unknown, and failed checks, so that uncertainty is not reported as revocation.
15. As a security analyst, I want signature algorithms and public-key strength assessed, so that obsolete certificate cryptography is penalised.
16. As a security analyst, I want TLS 1.3 through SSL 2.0 tested explicitly, so that modern and obsolete protocol support are distinguishable.
17. As a security analyst, I want unsupported, not tested, and probe failed to remain separate states, so that capability gaps are visible.
18. As a security analyst, I want accepted cipher suites and effective bit strength recorded, so that weak symmetric encryption is penalised.
19. As a security analyst, I want key exchange, forward secrecy, and DHE strength recorded, so that 4096-bit DHE rates higher than 512-bit DHE.
20. As a security analyst, I want compression, ALPN, renegotiation, and raw evidence retained, so that advanced findings are reproducible.
21. As a user, I want certificate, protocol, key-exchange, cipher, configuration, and overall scores, so that the grade is explainable.
22. As a user, I want critical certificate failures to cap the grade, so that strong ciphers cannot hide failed authentication.
23. As a user, I want failed collections shown as Not scored/N/A, so that unreachable websites are not misrepresented as 59-point websites.
24. As a user, I want a completed but critically insecure endpoint to retain a 59-or-lower F grade, so that failure and insecurity remain distinct.
25. As a user, I want every finding to include severity, evidence, and remediation, so that the grade leads to action.
26. As a researcher, I want failed attempts retained in the audit trail, so that reachability bias and exclusions can be discussed.
27. As a researcher, I want failed attempts excluded from descriptive and inferential scores, so that missing evidence does not bias results.
28. As a researcher, I want repeated hostname/port observations deduplicated to the newest result, so that rescans do not inflate the sample.
29. As a researcher, I want overall descriptive metrics for an unlabelled hostname list, so that simple data remains useful.
30. As a researcher, I want Analysis to begin with no default comparison, so that the software never chooses my hypothesis.
31. As a researcher, I want to choose country or sector as the comparison dimension, so that the analysis fits my dataset.
32. As a researcher, I want Group A, Group B, and control strata populated from observed labels, so that new categories work automatically.
33. As a researcher, I want at least two observations per selected cell before calculation, so that empty or single-item comparisons are blocked.
34. As a researcher, I want results marked stable only at ten observations per selected cell, so that exploratory output is not overstated.
35. As a researcher, I want a two-sided stratified permutation test, so that group differences control for the opposite label dimension.
36. As a researcher, I want Cliff's delta and a stratified bootstrap interval, so that effect size and uncertainty accompany significance.
37. As a researcher, I want repeated identical analysis requests cached, so that exploring the interface remains responsive.
38. As a researcher, I want CSV evidence export, so that calculations can be independently checked.
39. As a researcher, I want a standalone HTML report using my current selection, so that the conclusion can be submitted or shared locally.
40. As a user, I want to open any Evidence row for full details, so that summary numbers never hide source evidence.
41. As a user, I want English-only runtime text and stable date formatting, so that the final demonstration is consistent.
42. As a privacy-conscious user, I want all project data stored locally, so that no scan evidence is uploaded to a cloud service.
43. As a user, I want an explicit project reset with confirmation, so that I can restart while avoiding accidental deletion.
44. As a keyboard or assistive-technology user, I want visible focus, clear labels, and predictable navigation, so that the complete workflow is accessible.
45. As a motion-sensitive user, I want reduced-motion and reduced-transparency alternatives, so that visual polish does not reduce usability.
46. As an assessor, I want a Method page mapping implementation to P3 requirements, so that coverage and scoring rationale are easy to verify.
47. As an assessor, I want errors, unknowns, limitations, and the Singapore vantage point documented, so that conclusions remain appropriately bounded.
48. As an assessor, I want concise graphs and statistics rather than unnecessary raw-data presentation, so that report quality follows the project guidelines.

## Implementation Decisions

- The product remains a local Python HTTP service with a dependency-light HTML,
  CSS, and JavaScript client. It is not converted to a hosted framework.
- The existing API, SQLite schema, scanner, scoring engine, analysis engine, and
  report contracts remain the system boundaries.
- The UI reads and writes only through the established local API; visual refinement
  must not introduce a second state model or duplicate business rules in the client.
- Every submitted target uses the full assessment. Quick or demo scan modes are not
  exposed.
- A failed collection is an audit record, not a scored security observation. Its
  component and overall scores are absent and its grade is N/A.
- A completed observation uses the published 40/21/21/18 effective weighting and
  critical grade caps documented in the Method view.
- Protocol support values preserve supported, unsupported, not tested, and error as
  separate evidence states.
- Statistical comparison is entirely user-selected. Comparing countries controls
  for selected sectors; comparing sectors controls for selected countries.
- The newest hostname/port observation is the only one used statistically. Older
  rows remain available as audit evidence.
- The visual system uses platform system typography, layered translucent navigation,
  restrained depth, large readable targets, immediate press feedback, and calm
  critically damped transitions.
- Motion is limited to wayfinding and feedback. It uses transform and opacity, never
  blocks input, and has reduced-motion, reduced-transparency, and increased-contrast
  fallbacks.
- Destructive reset remains visually separated and requires confirmation.
- The application remains English-only and local-only.

## Testing Decisions

- Tests assert external behaviour at the highest stable seams: local HTTP routes,
  stored scan round-trips, exported reports, and deterministic analysis results.
- Scoring tests cover secure configurations, critical certificate caps, legacy
  protocols, weak ciphers and DHE, and the distinction between failed/not-scored and
  completed/insecure targets.
- Scanner integration tests use controlled local TLS endpoints and raw legacy
  protocol responses rather than public websites.
- Analysis tests cover no default comparison, arbitrary labels, both comparison
  directions, sample thresholds, deduplication, and unlabelled descriptive analysis.
- Reporting tests verify that failed rows never regain a numeric score in CSV or HTML.
- Web validation checks JavaScript syntax, referenced element IDs, English-only copy,
  responsive CSS rules, visible focus treatment, and accessibility preference media
  queries.
- Existing tests are preferred over new internal seams; visual work must not require
  changes to core Python test fixtures.

## Out of Scope

- Authentication, login testing, exploitation, content crawling, HTTP application
  vulnerability scanning, denial-of-service testing, or authenticated endpoints.
- Cloud storage, telemetry, remote grading APIs, hosted deployment, or multi-user
  accounts.
- Automatic claims that one country or sector is universally more secure.
- Treating unreachable, blocked, or untested endpoints as zero-score or 59-score
  security results.
- Replacing the full scanner with a faster but incomplete probe.
- Automatic selection of a hypothesis, comparison groups, or control strata.
- A native mobile application or gesture-heavy interactions that do not serve the
  research workflow.

## Further Notes

- The P3 brief allocates 15 points to grader implementation, 10 to use cases, 10 to
  results/evaluation/discussion, and 9 to report quality/presentation.
- The general project guidelines require at least 40 hours, concise technical writing,
  major error sources, interpreted results, improvements, and referenced facts.
- The P3 brief suggests at least 100 websites per category for significance. The
  application does not fabricate statistical readiness; it reports current cell counts
  and explicitly marks small samples preliminary.
- See `README.md` for operation, `CODE_MANUAL.md` for implementation detail, and
  `HANDOFF.md` for the latest continuation state.
