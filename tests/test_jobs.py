import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from tlsgrader.jobs import JobManager
from tlsgrader.scoring import score_scan
from tlsgrader.storage import Storage
from tlsgrader.utils import utc_now_iso


def successful_scan(hostname, port=443, *, country="", sector="", source="manual", progress=None, **_):
    if progress:
        progress("Resolving hostname", 5)
        progress("Scan complete", 100)
    return score_scan(
        {
            "hostname": hostname, "port": port, "country": country, "sector": sector,
            "source": source, "status": "completed", "scan_time": utc_now_iso(),
            "certificate": {"trust_valid": True, "hostname_valid": True, "validity_status": "valid", "days_remaining": 90, "revocation_status": "good", "signature_algorithm": "sha256", "public_key_type": "RSA", "public_key_bits": 2048, "chain_complete": True},
            "protocols": {"TLS 1.2": "supported", "TLS 1.3": "supported"},
            "key_exchange": {"method": "X25519", "bits": 253, "forward_secrecy": True},
            "ciphers": {"accepted": ["TLS_AES_256_GCM_SHA384"], "negotiated": "TLS_AES_256_GCM_SHA384"},
            "compression": False, "errors": [],
        }
    )


class JobManagerTests(unittest.TestCase):
    def test_batch_can_exceed_previous_300_target_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            storage = Storage(Path(directory) / "jobs.db")
            manager = JobManager(storage, workers=1)
            try:
                targets = [{"hostname": f"site-{index}.example"} for index in range(301)]
                with patch.object(manager.executor, "submit") as submit:
                    job_id = manager.submit(targets)
                submit.assert_called_once()
                self.assertEqual(storage.get_job(job_id)["total"], 301)
                self.assertEqual(storage.get_job(job_id)["payload"]["mode"], "full")
            finally:
                manager.shutdown()

    def test_scanner_progress_callback_accepts_percent(self):
        with tempfile.TemporaryDirectory() as directory:
            storage = Storage(Path(directory) / "jobs.db")
            manager = JobManager(storage, workers=1)
            try:
                with patch("tlsgrader.jobs.scan_target", side_effect=successful_scan):
                    job_id = manager.submit([{"hostname": "example.com", "country": "Singapore", "sector": "Education"}])
                    for _ in range(100):
                        job = storage.get_job(job_id)
                        if job["status"] == "completed":
                            break
                        time.sleep(0.02)
                self.assertEqual(job["completed"], 1)
                self.assertEqual(job["failed"], 0)
                self.assertEqual(len(job["result_ids"]), 1)
                self.assertIn("1 completed", job["message"])
            finally:
                manager.shutdown()


if __name__ == "__main__":
    unittest.main()
