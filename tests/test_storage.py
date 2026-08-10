import tempfile
import unittest
from pathlib import Path

from tlsgrader.storage import Storage


def stored_scan():
    return {
        "id": "scan-1",
        "hostname": "example.com",
        "port": 443,
        "country": "Singapore",
        "sector": "Healthcare",
        "source": "test",
        "scan_time": "2026-07-31T00:00:00+00:00",
        "status": "completed",
        "scores": {"overall": 90, "grade": "A"},
    }


class StorageTests(unittest.TestCase):
    def test_not_scored_failure_round_trip(self):
        with tempfile.TemporaryDirectory() as directory:
            storage = Storage(Path(directory) / "test.db")
            failed = stored_scan()
            failed["id"] = "failed-1"
            failed["status"] = "failed"
            failed["scores"] = {"overall": None, "grade": "N/A", "not_scored": True}
            scan_id = storage.save_scan(failed)
            restored = storage.get_scan(scan_id)
            self.assertIsNone(restored["scores"]["overall"])
            self.assertEqual(restored["scores"]["grade"], "N/A")

    def test_analysis_revision_changes_after_scan_is_saved(self):
        with tempfile.TemporaryDirectory() as directory:
            storage = Storage(Path(directory) / "test.db")
            before = storage.analysis_revision()
            storage.save_scan(stored_scan())
            self.assertNotEqual(before, storage.analysis_revision())

    def test_scan_round_trip(self):
        with tempfile.TemporaryDirectory() as directory:
            storage = Storage(Path(directory) / "test.db")
            scan_id = storage.save_scan(stored_scan())
            self.assertEqual(storage.get_scan(scan_id)["hostname"], "example.com")
            self.assertEqual(len(storage.list_scans()), 1)
            self.assertTrue(storage.delete_scan(scan_id))

    def test_job_progress(self):
        with tempfile.TemporaryDirectory() as directory:
            storage = Storage(Path(directory) / "test.db")
            job_id = storage.create_job({"targets": [{"hostname": "localhost"}]}, 1)
            storage.update_job(job_id, status="completed", completed=1, result_ids_json=["abc"])
            job = storage.get_job(job_id)
            self.assertEqual(job["percent"], 100)
            self.assertEqual(job["result_ids"], ["abc"])

    def test_running_job_is_marked_interrupted_after_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            storage = Storage(Path(directory) / "test.db")
            job_id = storage.create_job({"targets": [{"hostname": "localhost"}]}, 1)
            storage.update_job(job_id, status="running", current_target="localhost")
            self.assertEqual(storage.recover_interrupted_jobs(), 1)
            job = storage.get_job(job_id)
            self.assertEqual(job["status"], "interrupted")
            self.assertIn("submit this batch again", job["message"])

    def test_reset_all_removes_scans_jobs_and_settings(self):
        with tempfile.TemporaryDirectory() as directory:
            storage = Storage(Path(directory) / "test.db")
            storage.save_scan(stored_scan())
            storage.create_job({"targets": [{"hostname": "localhost"}]}, 1)
            storage.set_setting("view", {"tab": "analysis"})
            counts = storage.reset_all()
            self.assertEqual(counts, {"scans": 1, "jobs": 1, "settings": 1})
            self.assertEqual(storage.list_scans(limit=0), [])
            self.assertEqual(storage.list_jobs(), [])
            self.assertIsNone(storage.get_setting("view"))


if __name__ == "__main__":
    unittest.main()
