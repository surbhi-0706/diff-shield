
import sys
import unittest
from pathlib import Path

ENGINE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENGINE_ROOT))

from analyzers.detection_pipeline import run_detection


class TestDetectionPipeline(unittest.TestCase):

    def setUp(self):
        self.suspicious_diff = """\
diff --git a/example.py b/example.py
index 1234567..abcdef0 100644
--- a/example.py
+++ b/example.py
@@ -1,2 +1,2 @@
- database.execute("SELECT * FROM users WHERE name = ?", (query,))
+database.execute("SELECT * FROM users WHERE name = '" + query + "'")
"""

        self.unrelated_diff = """\
diff --git a/example.py b/example.py
index 1234567..abcdef0 100644
--- a/example.py
+++ b/example.py
@@ -1,2 +1,2 @@
-def get_user(query):
+def get_user(query, logger=None):
"""

    def test_detects_suspicious_change(self):
        result = run_detection(
            "demo-db-client",
            "pypi",
            self.suspicious_diff,
        )

        self.assertEqual(result.status, "SUSPICIOUS")
        self.assertEqual(result.assessed_advisories, 1)
        self.assertTrue(result.assessments[0].suspicious)

    def test_returns_no_match_for_unrelated_diff(self):
        result = run_detection(
            "demo-db-client",
            "pypi",
            self.unrelated_diff,
        )

        self.assertEqual(result.status, "NO_MATCH")
        self.assertEqual(result.assessed_advisories, 1)

    def test_reports_unknown_package_as_not_assessed(self):
        result = run_detection(
            "unknown-package",
            "pypi",
            self.suspicious_diff,
        )

        self.assertEqual(result.status, "NOT_ASSESSED")
        self.assertEqual(result.assessed_advisories, 0)
        self.assertEqual(result.assessments, [])

    def test_returns_structured_result(self):
        result = run_detection(
            "demo-db-client",
            "pypi",
            self.suspicious_diff,
        )

        data = result.to_dict()

        self.assertIn("package_name", data)
        self.assertIn("status", data)
        self.assertIn("assessments", data)
        self.assertIn("explanation", data)

    def test_rejects_empty_package_name(self):
        with self.assertRaises(ValueError):
            run_detection("", "pypi", self.suspicious_diff)


if __name__ == "__main__":
    unittest.main(verbosity=2)
