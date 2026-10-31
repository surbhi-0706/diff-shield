
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

        self.vulnerable_source = """
def get_user(query):
    return database.execute(
        "SELECT * FROM users WHERE name = '" + query + "'"
    )
"""

        self.patched_source = """
def get_user(query):
    return database.execute(
        "SELECT * FROM users WHERE name = ?",
        (query,)
    )
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
        self.assertIn("ast_analysis_performed", data)

    def test_rejects_empty_package_name(self):
        with self.assertRaises(ValueError):
            run_detection("", "pypi", self.suspicious_diff)

    def test_ast_detects_vulnerable_source(self):
        result = run_detection(
            "demo-db-client",
            "pypi",
            self.unrelated_diff,
            source_code=self.vulnerable_source,
            language="python",
        )

        self.assertEqual(result.status, "SUSPICIOUS")
        self.assertTrue(result.ast_analysis_performed)
        self.assertIn(
            "python_ast",
            result.assessments[0].detection_methods,
        )

    def test_ast_recognizes_patched_source(self):
        result = run_detection(
            "demo-db-client",
            "pypi",
            self.unrelated_diff,
            source_code=self.patched_source,
            language="python",
        )

        self.assertEqual(result.status, "NO_MATCH")
        self.assertTrue(result.ast_analysis_performed)
        self.assertNotIn(
            "python_ast",
            result.assessments[0].detection_methods,
        )

    def test_records_both_detection_methods(self):
        result = run_detection(
            "demo-db-client",
            "pypi",
            self.suspicious_diff,
            source_code=self.vulnerable_source,
            language="python",
        )

        methods = result.assessments[0].detection_methods

        self.assertIn("git_diff", methods)
        self.assertIn("python_ast", methods)

    def test_requires_language_when_source_is_provided(self):
        with self.assertRaises(ValueError):
            run_detection(
                "demo-db-client",
                "pypi",
                self.unrelated_diff,
                source_code=self.vulnerable_source,
            )

    def test_rejects_unsupported_ast_language(self):
        with self.assertRaises(ValueError):
            run_detection(
                "demo-db-client",
                "pypi",
                self.unrelated_diff,
                source_code="console.log('hello')",
                language="javascript",
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
