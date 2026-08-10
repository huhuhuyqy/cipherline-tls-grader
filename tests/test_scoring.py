import unittest

from tlsgrader.scoring import score_scan


def modern_scan():
    return {
        "certificate": {
            "trust_valid": True, "hostname_valid": True, "validity_status": "valid",
            "days_remaining": 120, "revocation_status": "good", "signature_algorithm": "sha256WithRSAEncryption",
            "public_key_type": "RSA", "public_key_bits": 2048, "chain_complete": True, "ocsp_stapling": True,
        },
        "protocols": {"TLS 1.2": "supported", "TLS 1.3": "supported", "TLS 1.1": "unsupported", "TLS 1.0": "unsupported", "SSL 3.0": "unsupported", "SSL 2.0": "unsupported"},
        "key_exchange": {"method": "X25519", "bits": 253, "forward_secrecy": True},
        "ciphers": {
            "accepted": ["TLS_AES_256_GCM_SHA384"],
            "accepted_details": [{"name": "TLS_AES_256_GCM_SHA384", "protocol": "TLSv1.3", "bits": 256}],
            "negotiated": "TLS_AES_256_GCM_SHA384",
            "negotiated_bits": 256,
        },
        "compression": False,
    }


class ScoringTests(unittest.TestCase):
    def test_failed_scan_is_not_scored(self):
        result = score_scan(
            {
                "hostname": "unavailable.test",
                "status": "failed",
                "certificate": {"trust_valid": False},
                "protocols": {},
                "key_exchange": {},
                "ciphers": {},
                "errors": ["DNS resolution failed"],
            }
        )
        self.assertIsNone(result["scores"]["overall"])
        self.assertEqual(result["scores"]["grade"], "N/A")
        self.assertTrue(result["scores"]["not_scored"])
        self.assertEqual(result["findings"][0]["code"], "SCAN_NOT_COMPLETED")

    def test_modern_configuration_receives_a(self):
        result = score_scan(modern_scan())
        self.assertEqual(result["scores"]["overall"], 100)
        self.assertEqual(result["scores"]["grade"], "A")

    def test_untrusted_certificate_caps_grade_at_f(self):
        scan = modern_scan()
        scan["certificate"]["trust_valid"] = False
        scan["certificate"]["trust_error"] = "self signed"
        result = score_scan(scan)
        self.assertEqual(result["scores"]["grade"], "F")
        self.assertLessEqual(result["scores"]["overall"], 59)
        self.assertIn("CERT_UNTRUSTED", {item["code"] for item in result["findings"]})

    def test_sha1_fingerprint_does_not_trigger_signature_penalty(self):
        scan = modern_scan()
        scan["certificate"]["fingerprint_sha1"] = "AA:BB:CC"
        result = score_scan(scan)
        self.assertNotIn("SIG_SHA1", {item["code"] for item in result["findings"]})

    def test_ssl2_support_receives_the_lowest_protocol_penalty_and_grade_cap(self):
        scan = modern_scan()
        scan["protocols"]["SSL 2.0"] = "supported"
        result = score_scan(scan)
        self.assertLess(result["scores"]["protocol"], 50)
        self.assertEqual(result["scores"]["grade_cap"], "D")
        self.assertIn("LEGACY_SSL20", {item["code"] for item in result["findings"]})

    def test_4096_bit_dhe_scores_higher_than_512_bit_dhe(self):
        weak = modern_scan()
        weak["key_exchange"] = {
            "method": "DHE",
            "bits": 512,
            "forward_secrecy": True,
            "minimum_dhe_bits": 512,
            "maximum_dhe_bits": 512,
        }
        strong = modern_scan()
        strong["key_exchange"] = {
            "method": "DHE",
            "bits": 4096,
            "forward_secrecy": True,
            "minimum_dhe_bits": 4096,
            "maximum_dhe_bits": 4096,
        }
        self.assertGreater(score_scan(strong)["scores"]["key_exchange"], score_scan(weak)["scores"]["key_exchange"])

    def test_cipher_below_128_bits_is_penalised(self):
        scan = modern_scan()
        scan["ciphers"]["accepted"].append("DES-CBC3-SHA")
        scan["ciphers"]["accepted_details"].append({"name": "DES-CBC3-SHA", "protocol": "TLSv1.2", "bits": 112})
        result = score_scan(scan)
        self.assertLess(result["scores"]["cipher"], 60)
        self.assertIn("CIPHER_BELOW_128", {item["code"] for item in result["findings"]})


if __name__ == "__main__":
    unittest.main()
