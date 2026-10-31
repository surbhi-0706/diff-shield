
import sys
import unittest
from pathlib import Path

ENGINE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENGINE_ROOT))

from analyzers.regression_detector import compare_code


class TestRegressionDetector(unittest.TestCase):

    def setUp(self):
        self.vulnerable_code = """
def get_user(query):
    return database.execute(
        "SELECT * FROM users WHERE name = '" + query + "'"
    )
"""

        self.patched_code = """
def get_user(query):
    return database.execute(
        "SELECT * FROM users WHERE name = ?",
        (query,)
    )
"""

    def test_detects_vulnerability_reintroduction(self):
        result = compare_code(
            self.vulnerable_code,
            self.patched_code,
            self.vulnerable_code
        )
        self.assertTrue(result.vulnerable_code_reintroduced)
        self.assertEqual(result.severity, "HIGH")
        self.assertGreater(result.confidence, 0)

    def test_accepts_unchanged_patched_code(self):
        result = compare_code(
            self.vulnerable_code,
            self.patched_code,
            self.patched_code
        )
        self.assertFalse(result.vulnerable_code_reintroduced)
        self.assertEqual(result.severity, "NONE")

    def test_returns_explainable_evidence(self):
        result = compare_code(
            self.vulnerable_code,
            self.patched_code,
            self.vulnerable_code
        )
        self.assertTrue(result.restored_vulnerable_lines)
        self.assertTrue(result.missing_security_lines)
        self.assertTrue(result.explanation)

    def test_does_not_flag_unrelated_code_change(self):
        new_code = """
def get_user(query):
    logger.info("Fetching user")
    return database.execute(
        "SELECT * FROM users WHERE name = ?",
        (query,)
    )
"""
        result = compare_code(
            self.vulnerable_code,
            self.patched_code,
            new_code
        )
        self.assertFalse(result.vulnerable_code_reintroduced)

    def test_does_not_flag_empty_code(self):
        result = compare_code(
            self.vulnerable_code,
            self.patched_code,
            ""
        )
        self.assertFalse(result.vulnerable_code_reintroduced)


if __name__ == "__main__":
    unittest.main(verbosity=2)
