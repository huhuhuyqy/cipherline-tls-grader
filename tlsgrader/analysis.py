from __future__ import annotations

import random
import statistics
from collections import Counter, defaultdict
from typing import Any, Iterable

from .utils import CURRENT_ASSESSMENT_VERSION, is_current_methodology


LABEL_FIELDS = ("country", "sector")


def _mean(values: list[float]) -> float | None:
    return statistics.fmean(values) if values else None


def _median(values: list[float]) -> float | None:
    return statistics.median(values) if values else None


def _round(value: float | None, digits: int = 2):
    return round(value, digits) if value is not None else None


def _score(scan: dict[str, Any]) -> float:
    return float(scan.get("scores", {}).get("overall", 0))


def _group_summary(scans: list[dict[str, Any]]) -> dict[str, Any]:
    values = [_score(scan) for scan in scans]
    grades = Counter(scan.get("scores", {}).get("grade", "F") for scan in scans)
    tls13 = sum(scan.get("protocols", {}).get("TLS 1.3") == "supported" for scan in scans)
    legacy = sum(
        any(
            scan.get("protocols", {}).get(version) == "supported"
            for version in ("TLS 1.1", "TLS 1.0", "SSL 3.0", "SSL 2.0")
        )
        for scan in scans
    )
    critical_cert = sum(
        any(
            finding.get("code")
            in {"CERT_UNTRUSTED", "HOSTNAME_MISMATCH", "CERT_EXPIRED", "CERT_REVOKED"}
            for finding in scan.get("findings", [])
        )
        for scan in scans
    )
    return {
        "n": len(scans),
        "mean": _round(_mean(values)),
        "median": _round(_median(values)),
        "minimum": _round(min(values) if values else None),
        "maximum": _round(max(values) if values else None),
        "standard_deviation": _round(statistics.stdev(values) if len(values) > 1 else None),
        "grades": {grade: grades.get(grade, 0) for grade in "ABCDF"},
        "tls13_rate": _round(tls13 / len(scans) * 100 if scans else None, 1),
        "legacy_rate": _round(legacy / len(scans) * 100 if scans else None, 1),
        "critical_certificate_rate": _round(critical_cert / len(scans) * 100 if scans else None, 1),
    }


def cliffs_delta(group_a: list[float], group_b: list[float]) -> float | None:
    if not group_a or not group_b:
        return None
    greater = sum(a > b for a in group_a for b in group_b)
    lower = sum(a < b for a in group_a for b in group_b)
    return (greater - lower) / (len(group_a) * len(group_b))


def _stratified_values(
    scans: list[dict[str, Any]],
    *,
    compare_field: str,
    group_a: str,
    group_b: str,
    stratum_field: str,
    strata: tuple[str, ...],
) -> list[tuple[list[float], list[float]]]:
    grouped = []
    for stratum in strata:
        values_a = [
            _score(scan)
            for scan in scans
            if scan.get(stratum_field) == stratum and scan.get(compare_field) == group_a
        ]
        values_b = [
            _score(scan)
            for scan in scans
            if scan.get(stratum_field) == stratum and scan.get(compare_field) == group_b
        ]
        grouped.append((values_a, values_b))
    return grouped


def _stratified_difference(grouped: list[tuple[list[float], list[float]]]) -> float | None:
    differences = [
        statistics.fmean(values_a) - statistics.fmean(values_b)
        for values_a, values_b in grouped
        if values_a and values_b
    ]
    return statistics.fmean(differences) if differences else None


def _stratified_permutation_test(
    grouped: list[tuple[list[float], list[float]]],
    *,
    iterations: int = 4000,
    seed: int = 20260731,
) -> dict[str, Any]:
    observed = _stratified_difference(grouped)
    if observed is None:
        return {"observed_difference": None, "p_value": None, "iterations": 0}
    rng = random.Random(seed)
    extreme = 0
    for _ in range(iterations):
        differences = []
        for values_a, values_b in grouped:
            combined = values_a + values_b
            shuffled = rng.sample(combined, len(combined))
            permuted_a = shuffled[: len(values_a)]
            permuted_b = shuffled[len(values_a) :]
            differences.append(statistics.fmean(permuted_a) - statistics.fmean(permuted_b))
        permuted = statistics.fmean(differences)
        if abs(permuted) >= abs(observed):
            extreme += 1
    return {
        "observed_difference": _round(observed),
        "p_value": _round((extreme + 1) / (iterations + 1), 4),
        "iterations": iterations,
        "alternative": "two-sided",
    }


def _bootstrap_stratified_difference(
    grouped: list[tuple[list[float], list[float]]],
    *,
    iterations: int = 2000,
    seed: int = 20260731,
) -> tuple[float | None, float | None]:
    if not grouped or any(len(values_a) < 2 or len(values_b) < 2 for values_a, values_b in grouped):
        return None, None
    rng = random.Random(seed)
    differences = []
    for _ in range(iterations):
        stratum_differences = []
        for values_a, values_b in grouped:
            sample_a = [rng.choice(values_a) for _ in values_a]
            sample_b = [rng.choice(values_b) for _ in values_b]
            stratum_differences.append(statistics.fmean(sample_a) - statistics.fmean(sample_b))
        differences.append(statistics.fmean(stratum_differences))
    differences.sort()
    return (
        differences[int(0.025 * iterations)],
        differences[min(iterations - 1, int(0.975 * iterations))],
    )


def deduplicate_newest(scans: Iterable[dict[str, Any]]) -> tuple[list[dict[str, Any]], int]:
    """Keep one target observation using timestamp then stable scan ID as recency."""
    ordered = sorted(
        scans,
        key=lambda scan: (str(scan.get("scan_time", "")), str(scan.get("id", ""))),
        reverse=True,
    )
    usable = []
    seen_targets: set[tuple[str, int]] = set()
    for scan in ordered:
        target_key = (
            str(scan.get("hostname", "")).lower().rstrip("."),
            int(scan.get("port", 443)),
        )
        if target_key in seen_targets:
            continue
        seen_targets.add(target_key)
        usable.append(scan)
    return usable, len(ordered) - len(usable)


def _labels(scans: list[dict[str, Any]], field: str) -> list[str]:
    return sorted(
        {str(scan.get(field, "")).strip() for scan in scans if str(scan.get(field, "")).strip()},
        key=str.casefold,
    )


def analyse(
    scans: Iterable[dict[str, Any]],
    *,
    compare_field: str = "",
    group_a: str = "",
    group_b: str = "",
    strata: Iterable[str] | None = None,
) -> dict[str, Any]:
    all_scans = list(scans)
    legacy_methodology_count = sum(
        not is_current_methodology(scan)
        for scan in all_scans
    )
    completed = [
        scan
        for scan in all_scans
        if scan.get("status") == "completed"
        and is_current_methodology(scan)
        and isinstance(scan.get("scores", {}).get("overall"), (int, float))
    ]
    usable, duplicates_excluded = deduplicate_newest(completed)
    available_labels = {field: _labels(usable, field) for field in LABEL_FIELDS}
    label_counts = {
        field: dict(
            Counter(
                value
                for scan in usable
                if (value := str(scan.get(field, "")).strip())
            )
        )
        for field in LABEL_FIELDS
    }
    combination_counts = Counter(
        (str(scan.get("country", "")).strip(), str(scan.get("sector", "")).strip())
        for scan in usable
        if str(scan.get("country", "")).strip() and str(scan.get("sector", "")).strip()
    )
    combinations = [
        {"country": country, "sector": sector, "n": count}
        for (country, sector), count in sorted(
            combination_counts.items(),
            key=lambda item: (item[0][0].casefold(), item[0][1].casefold()),
        )
    ]

    selection_valid = (
        compare_field in LABEL_FIELDS
        and group_a in available_labels.get(compare_field, [])
        and group_b in available_labels.get(compare_field, [])
        and group_a != group_b
    )
    stratum_field = "sector" if compare_field == "country" else "country" if compare_field == "sector" else ""
    available_strata = available_labels.get(stratum_field, [])
    requested_strata = list(strata) if strata is not None else available_strata
    selected_strata = tuple(value for value in available_strata if value in requested_strata)

    comparison = {
        "status": "awaiting_selection",
        "conclusion": "Choose a label field, Group A, and Group B to calculate a comparison.",
        "observed_difference": None,
        "p_value": None,
        "iterations": 0,
        "cliffs_delta": None,
        "bootstrap_ci_95": [None, None],
        "alpha": 0.05,
    }
    if all(len(available_labels[field]) < 2 for field in LABEL_FIELDS):
        comparison["conclusion"] = (
            "Descriptive analysis is available for all completed sites. Add at least two "
            "country or sector labels to enable a grouped comparison."
        )
    selected_summaries: dict[str, dict[str, Any]] = {}
    group_cards: list[dict[str, Any]] = []
    cell_counts: list[dict[str, Any]] = []
    stable = False

    if selection_valid and not selected_strata:
        comparison["status"] = "awaiting_strata"
        comparison["conclusion"] = "Select at least one control stratum to calculate the comparison."
    elif selection_valid:
        comparison_scans = [
            scan
            for scan in usable
            if scan.get(compare_field) in {group_a, group_b}
            and scan.get(stratum_field) in selected_strata
        ]
        grouped = _stratified_values(
            comparison_scans,
            compare_field=compare_field,
            group_a=group_a,
            group_b=group_b,
            stratum_field=stratum_field,
            strata=selected_strata,
        )
        for stratum, (values_a, values_b) in zip(selected_strata, grouped):
            cell_counts.append(
                {
                    "stratum": stratum,
                    "group_a_n": len(values_a),
                    "group_b_n": len(values_b),
                }
            )
            for group_name in (group_a, group_b):
                cell_scans = [
                    scan
                    for scan in comparison_scans
                    if scan.get(compare_field) == group_name and scan.get(stratum_field) == stratum
                ]
                group_cards.append(
                    {
                        "group": group_name,
                        "stratum": stratum,
                        "summary": _group_summary(cell_scans),
                    }
                )

        minimum_ready = all(len(values_a) >= 2 and len(values_b) >= 2 for values_a, values_b in grouped)
        stable = all(len(values_a) >= 10 and len(values_b) >= 10 for values_a, values_b in grouped)
        selected_summaries = {
            group_name: _group_summary(
                [scan for scan in comparison_scans if scan.get(compare_field) == group_name]
            )
            for group_name in (group_a, group_b)
        }
        if not minimum_ready:
            comparison["status"] = "insufficient_data"
            comparison["conclusion"] = (
                "At least two valid websites are required for both selected groups in every "
                "selected control stratum."
            )
        else:
            test = _stratified_permutation_test(grouped)
            ci_low, ci_high = _bootstrap_stratified_difference(grouped)
            pooled_a = [
                _score(scan) for scan in comparison_scans if scan.get(compare_field) == group_a
            ]
            pooled_b = [
                _score(scan) for scan in comparison_scans if scan.get(compare_field) == group_b
            ]
            difference = test["observed_difference"]
            p_value = test["p_value"]
            comparison.update(
                {
                    **test,
                    "difference_definition": (
                        f"{group_a} - {group_b}, equally averaged across selected "
                        f"{stratum_field} strata"
                    ),
                    "cliffs_delta": _round(cliffs_delta(pooled_a, pooled_b), 3),
                    "bootstrap_ci_95": [_round(ci_low), _round(ci_high)],
                }
            )
            if not stable:
                comparison["status"] = "preliminary"
                comparison["conclusion"] = (
                    f"Exploratory result: {group_a} - {group_b} = {difference:.2f} points "
                    f"(two-sided p={p_value:.4f}). Collect at least 10 websites for both "
                    "groups in every selected stratum before treating the result as stable."
                )
            elif p_value is not None and p_value < 0.05:
                stronger = group_a if difference > 0 else group_b
                comparison["status"] = "significant"
                comparison["conclusion"] = (
                    f"{stronger} scored significantly higher after controlling for "
                    f"{stratum_field} ({group_a} - {group_b} = {difference:.2f} points; "
                    f"two-sided p={p_value:.4f})."
                )
            else:
                comparison["status"] = "not_significant"
                comparison["conclusion"] = (
                    f"No statistically significant difference was detected after controlling "
                    f"for {stratum_field} ({group_a} - {group_b} = {difference:.2f} points; "
                    f"two-sided p={p_value:.4f})."
                )

    severity_counts = Counter(
        finding.get("severity", "info")
        for scan in usable
        for finding in scan.get("findings", [])
    )
    return {
        "generated_from": "real",
        "total_collected": len(usable),
        "total_records": len(all_scans),
        "legacy_methodology_excluded": legacy_methodology_count,
        "assessment_version": CURRENT_ASSESSMENT_VERSION,
        "unlabelled_observations": sum(
            not str(scan.get("country", "")).strip()
            or not str(scan.get("sector", "")).strip()
            for scan in usable
        ),
        "duplicate_observations_excluded": duplicates_excluded,
        "overall_summary": _group_summary(usable),
        "available_labels": available_labels,
        "label_counts": label_counts,
        "combinations": combinations,
        "selection": {
            "compare_field": compare_field if compare_field in LABEL_FIELDS else "",
            "group_a": group_a if selection_valid else "",
            "group_b": group_b if selection_valid else "",
            "stratum_field": stratum_field,
            "strata": list(selected_strata),
        },
        "comparison_ready": selection_valid and bool(selected_strata),
        "comparison_stable": stable,
        "selected_summaries": selected_summaries,
        "group_cards": group_cards,
        "cell_counts": cell_counts,
        "comparison": comparison,
        "finding_counts": dict(severity_counts),
        "methodology": {
            "test": (
                "Two-sided stratified permutation test; selected comparison labels are "
                "permuted only within selected control strata"
            ),
            "effect_size": "Cliff's delta (Group A relative to Group B)",
            "uncertainty": "Stratified bootstrap 95% confidence interval",
            "sample_rule": (
                "Minimum 2 observations per group-stratum cell to calculate; "
                "minimum 10 per cell for a stable comparison"
            ),
            "limitations": [
                "One network vantage point in Singapore",
                "TLS configuration is time-dependent and CDN-dependent",
                "Unreachable sites can create selection bias",
                "Scores depend on a published but partly judgment-based weighting model",
            ],
        },
    }
