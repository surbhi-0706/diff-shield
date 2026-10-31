
import sys
import unittest
from pathlib import Path

ENGINE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENGINE_ROOT))

from analyzers.diff_analyzer import parse_unified_diff, analyze_diff


class TestDiffAnalyzer(unittest.TestCase):

    def setUp(self):
        self.diff = """\
diff --git a/example.py b/example.py
index 1234567..abcdef0 100644
--- a/example.py
+++ b/example.py
@@ -1,4 +1,4 @@
 def get_user(query):
-    database.execute("SELECT * FROM users WHERE name = ?", (query,))
+    database.execute("SELECT * FROM users WHERE name = '" + query + "'")
"""

    def test_extracts_added_and_deleted_lines(self):
        files = parse_unified_diff(self.diff)

        self.assertEqual(len(files), 1)
        self.assertEqual(files[0].filename, "example.py")
        self.assertTrue(files[0].added_lines)
        self.assertTrue(files[0].deleted_lines)

    def test_detects_suspicious_diff(self):
        result = analyze_diff(
            self.diff,
            vulnerable_patterns=[
                'database.execute("SELECT * FROM users WHERE name = \'" + query + "\'")'
            ],
            security_patterns=[
                'database.execute("SELECT * FROM users WHERE name = ?", (query,))'
            ],
        )

        self.assertTrue(result.suspicious)
        self.assertTrue(result.added_vulnerable_lines)
        self.assertTrue(result.removed_security_lines)

    def test_does_not_flag_unrelated_diff(self):
        result = analyze_diff(
            self.diff,
            vulnerable_patterns=["some unrelated vulnerable line"],
            security_patterns=["some unrelated security line"],
        )

        self.assertFalse(result.suspicious)

    def test_returns_explanation(self):
        result = analyze_diff(self.diff, [], [])
        self.assertTrue(result.explanation)

    def test_handles_empty_diff(self):
        files = parse_unified_diff("")
        self.assertEqual(files, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
