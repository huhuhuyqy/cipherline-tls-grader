import csv
import io
import unittest

from tlsgrader.analysis import analyse
from tlsgrader.reporting import report_html, scans_csv


def scan(hostname, country, sector, score):
    return {
        "hostname": hostname,
        "port": 443,
        "country": country,
        "sector": sector,
        "scan_time": "2026-07-31T00:00:00+00:00",
        "status": "completed",
        "scores": {
            "overall": score,
            "grade": "A",
            "certificate": 100,
            "protocol": 100,
            "key_exchange": 100,
            "cipher": 100,
        },
        "protocols": {
            "TLS 1.3": "supported",
            "TLS 1.2": "supported",
            "TLS 1.1": "unsupported",
            "TLS 1.0": "unsupported",
            "SSL 3.0": "unsupported",
            "SSL 2.0": "unsupported",
        },
        "key_exchange": {
            "finite_field_dh_bits": [4096],
            "minimum_dhe_bits": 4096,
            "maximum_dhe_bits": 4096,
        },
        "ciphers": {"weakest_bits": 128},
    }


class ReportingTests(unittest.TestCase):
    def setUp(self):
        self.scans = []
        for i in range(50):
            self.scans.extend(
                [
                    scan(f"cn-gov-{i}.test", "China", "Government", 70),
                    scan(f"cn-edu-{i}.test", "China", "Education", 65),
                    scan(f"sg-gov-{i}.test", "Singapore", "Government", 90),
                    scan(f"sg-edu-{i}.test", "Singapore", "Education", 85),
                ]
            )

    def test_csv_contains_all_protocol_and_strength_fields(self):
        rows = list(csv.DictReader(io.StringIO(scans_csv(self.scans[:1]))))
        self.assertEqual(rows[0]["ssl3"], "unsupported")
        self.assertEqual(rows[0]["ssl2"], "unsupported")
        self.assertEqual(rows[0]["minimum_dhe_bits"], "4096")
        self.assertEqual(rows[0]["minimum_cipher_bits"], "128")

    def test_html_contains_only_user_selected_inference(self):
        analysis = analyse(
            self.scans,
            compare_field="country",
            group_a="Singapore",
            group_b="China",
            strata=("Government", "Education"),
        )
        rendered = report_html(self.scans, analysis)
        self.assertIn("Singapore vs China", rendered)
        self.assertIn("User-selected comparison", rendered)
        self.assertIn("TLS 1.3", rendered)
        self.assertIn("SSL 2.0", rendered)

    def test_html_reports_unlabelled_hostname_list_descriptively(self):
        scans = [scan("one.test", "", "", 81), scan("two.test", "", "", 91)]
        rendered = report_html(scans, analyse(scans))
        self.assertIn("All completed sites", rendered)
        self.assertIn("mean score / n=2", rendered)
        self.assertIn("Descriptive analysis is available", rendered)

    def test_failed_scan_has_no_numeric_score_in_exports(self):
        failed = scan("offline.test", "", "", 59)
        failed["status"] = "failed"
        csv_row = list(csv.DictReader(io.StringIO(scans_csv([failed]))))[0]
        self.assertEqual(csv_row["overall"], "")
        self.assertEqual(csv_row["grade"], "N/A")
        rendered = report_html([failed], analyse([failed]))
        self.assertIn("Not scored", rendered)
        self.assertNotIn("<td>59</td>", rendered)


if __name__ == "__main__":
    unittest.main()
