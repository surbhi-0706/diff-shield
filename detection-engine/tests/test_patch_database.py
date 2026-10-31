
import json
import sys
import tempfile
import unittest
from pathlib import Path

ENGINE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENGINE_ROOT))

from vulnerability_intel.patch_database import (
    load_database,
    find_advisories,
)


class TestPatchDatabase(unittest.TestCase):

    def test_loads_database(self):
        records = load_database()

        self.assertGreater(len(records), 0)

    def test_finds_matching_package(self):
        results = find_advisories("demo-db-client", "pypi")

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["advisory_id"], "DEMO-DS-001")

    def test_package_search_is_case_insensitive(self):
        results = find_advisories("DEMO-DB-CLIENT", "PYPI")

        self.assertEqual(len(results), 1)

    def test_returns_empty_for_unknown_package(self):
        results = find_advisories("unknown-package", "pypi")

        self.assertEqual(results, [])

    def test_rejects_unsupported_ecosystem(self):
        with self.assertRaises(ValueError):
            find_advisories("demo-db-client", "unknown")

    def test_rejects_duplicate_advisory_ids(self):
        sample = {
            "advisories": [
                {
                    "advisory_id": "DEMO-1",
                    "package_name": "package-a",
                    "ecosystem": "pypi",
                    "vulnerability_type": "SQL Injection",
                    "severity": "HIGH",
                    "description": "Test record",
                    "vulnerable_patterns": ["unsafe query"],
                    "security_patterns": ["safe query"],
                },
                {
                    "advisory_id": "demo-1",
                    "package_name": "package-b",
                    "ecosystem": "npm",
                    "vulnerability_type": "XSS",
                    "severity": "MEDIUM",
                    "description": "Another test record",
                    "vulnerable_patterns": ["unsafe output"],
                    "security_patterns": ["safe output"],
                },
            ]
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "database.json"
            path.write_text(json.dumps(sample), encoding="utf-8")

            with self.assertRaises(ValueError):
                load_database(path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
