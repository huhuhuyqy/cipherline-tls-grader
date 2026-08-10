import json
import tempfile
import threading
import unittest
import urllib.request
from pathlib import Path
from unittest.mock import patch

import server
from tlsgrader.jobs import JobManager
from tlsgrader.storage import Storage


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        server.APP.storage = Storage(Path(cls.temp.name) / "api.db")
        server.APP.jobs = JobManager(server.APP.storage, workers=1)
        server.APP._analysis_cache.clear()
        cls.httpd = server.ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.httpd.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.temp.cleanup()

    def get(self, path):
        with urllib.request.urlopen(self.base + path, timeout=5) as response:
            return response.status, response.headers, response.read()

    def test_dashboard_is_served_locally(self):
        status, headers, body = self.get("/")
        self.assertEqual(status, 200)
        self.assertIn(b"CIPHERLINE", body)
        self.assertIn("default-src 'self'", headers["Content-Security-Policy"])

    def test_health_and_dynamic_analysis_api(self):
        status, _, body = self.get("/api/health")
        self.assertEqual(status, 200)
        health = json.loads(body)
        self.assertTrue(health["local_only"])
        self.assertEqual(health["version"], "1.3.2")
        _, _, body = self.get("/api/analysis?compare_field=sector&group_a=Healthcare&group_b=Public+Service")
        analysis = json.loads(body)
        self.assertEqual(analysis["available_labels"], {"country": [], "sector": []})
        self.assertEqual(analysis["selection"]["compare_field"], "sector")
        self.assertEqual(analysis["generated_from"], "real")

    def test_identical_analysis_query_uses_cache(self):
        server.APP._analysis_cache.clear()
        with patch("server.analyse", wraps=server.analyse) as mocked:
            server.APP.get_analysis(compare_field="", strata=())
            server.APP.get_analysis(compare_field="", strata=())
        self.assertEqual(mocked.call_count, 1)

    def test_project_reset_clears_scans_and_job_history(self):
        payload = json.dumps({"confirm": "DELETE ALL"}).encode("utf-8")
        request = urllib.request.Request(
            self.base + "/api/data/clear",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            reset = json.loads(response.read())["reset"]
        self.assertGreaterEqual(reset["scans"], 0)
        self.assertGreaterEqual(reset["jobs"], 0)
        _, _, scans = self.get("/api/scans?limit=0")
        _, _, jobs = self.get("/api/jobs")
        self.assertEqual(json.loads(scans)["items"], [])
        self.assertEqual(json.loads(jobs)["items"], [])


if __name__ == "__main__":
    unittest.main()
