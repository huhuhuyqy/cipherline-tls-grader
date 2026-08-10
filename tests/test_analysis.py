import unittest

from tlsgrader.analysis import analyse


def make_scan(index, country, sector, score=80, scan_time=None):
    return {
        "id": f"{country}-{sector}-{index}",
        "hostname": f"{country}-{sector}-{index}.example.test".lower().replace(" ", "-"),
        "port": 443,
        "country": country,
        "sector": sector,
        "status": "completed",
        "scan_time": scan_time or f"2026-07-31T00:{index % 60:02d}:00+00:00",
        "scores": {"overall": score, "grade": "A"},
        "protocols": {"TLS 1.3": "supported"},
        "findings": [],
    }


def labelled_scans(per_cell, countries=("China", "Singapore"), sectors=("University", "Hospital")):
    return [
        make_scan(index, country, sector, 90 if country == "Singapore" else 70)
        for country in countries
        for sector in sectors
        for index in range(per_cell)
    ]


class AnalysisTests(unittest.TestCase):
    def test_unlabelled_hostname_list_receives_descriptive_analysis(self):
        scans = [make_scan(index, "", "", score=60 + index) for index in range(3)]
        result = analyse(scans)
        self.assertEqual(result["total_collected"], 3)
        self.assertEqual(result["unlabelled_observations"], 3)
        self.assertEqual(result["available_labels"], {"country": [], "sector": []})
        self.assertEqual(result["overall_summary"]["mean"], 61)
        self.assertEqual(result["comparison"]["status"], "awaiting_selection")
        self.assertIn("Descriptive analysis", result["comparison"]["conclusion"])

    def test_analysis_has_no_default_comparison(self):
        result = analyse(labelled_scans(2))
        self.assertEqual(result["comparison"]["status"], "awaiting_selection")
        self.assertEqual(result["selection"]["compare_field"], "")
        self.assertEqual(result["selected_summaries"], {})

    def test_labels_are_discovered_without_allowlist(self):
        scans = labelled_scans(2, countries=("Atlantis", "El Dorado"), sectors=("Space Agency", "Museum"))
        result = analyse(scans)
        self.assertEqual(result["available_labels"]["country"], ["Atlantis", "El Dorado"])
        self.assertEqual(result["available_labels"]["sector"], ["Museum", "Space Agency"])

    def test_user_selected_country_comparison(self):
        result = analyse(
            labelled_scans(10),
            compare_field="country",
            group_a="Singapore",
            group_b="China",
            strata=("University", "Hospital"),
        )
        self.assertTrue(result["comparison_ready"])
        self.assertTrue(result["comparison_stable"])
        self.assertEqual(result["selection"]["stratum_field"], "sector")
        self.assertEqual(result["comparison"]["status"], "significant")
        self.assertGreater(result["comparison"]["observed_difference"], 0)

    def test_user_selected_sector_comparison_controls_for_country(self):
        scans = [
            make_scan(index, country, sector, 85 if sector == "Research Lab" else 70)
            for country in ("Region A", "Region B")
            for sector in ("Research Lab", "Public Library")
            for index in range(10)
        ]
        result = analyse(
            scans,
            compare_field="sector",
            group_a="Research Lab",
            group_b="Public Library",
            strata=("Region A", "Region B"),
        )
        self.assertEqual(result["selection"]["stratum_field"], "country")
        self.assertEqual(result["comparison"]["status"], "significant")

    def test_comparison_is_preliminary_below_ten_per_cell(self):
        result = analyse(
            labelled_scans(3),
            compare_field="country",
            group_a="Singapore",
            group_b="China",
            strata=("University",),
        )
        self.assertEqual(result["comparison"]["status"], "preliminary")

    def test_latest_duplicate_hostname_is_counted_once(self):
        scans = labelled_scans(1)
        duplicate = {**scans[0], "id": "newer", "scan_time": "2099-01-01T00:00:00+00:00"}
        result = analyse(scans + [duplicate])
        self.assertEqual(result["total_collected"], 4)
        self.assertEqual(result["duplicate_observations_excluded"], 1)


if __name__ == "__main__":
    unittest.main()
