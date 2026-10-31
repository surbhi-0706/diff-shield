import sys
import unittest
from pathlib import Path

ENGINE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENGINE_ROOT))

from analyzers.ast_analyzer import (
    analyze_python_code,
    contains_ast_pattern,
    get_node_fingerprints,
    parse_python,
)


class TestASTAnalyzer(unittest.TestCase):
    def setUp(self):
        self.vulnerable_pattern = """
database.execute(
    "SELECT * FROM users WHERE name = '" + query + "'"
)
"""
        self.security_pattern = """
database.execute(
    "SELECT * FROM users WHERE name = ?",
    (query,)
)
"""

    def test_parses_valid_python(self):
        tree = parse_python(self.security_pattern)
        self.assertIsNotNone(tree)

    def test_rejects_invalid_python(self):
        with self.assertRaises(ValueError):
            parse_python("def broken(:")

    def test_generates_ast_fingerprints(self):
        fingerprints = get_node_fingerprints(self.security_pattern)
        self.assertTrue(fingerprints)

    def test_matches_multiline_and_single_line_code(self):
        single_line = (
            'database.execute("SELECT * FROM users WHERE name = ?", (query,))'
        )
        self.assertTrue(
            contains_ast_pattern(single_line, self.security_pattern)
        )

    def test_matches_expression_inside_function_return(self):
        source_code = """
def get_user(query):
    return database.execute(
        "SELECT * FROM users WHERE name = ?",
        (query,)
    )
"""
        self.assertTrue(
            contains_ast_pattern(source_code, self.security_pattern)
        )

    def test_does_not_match_different_string_content(self):
        different_query = """
database.execute(
    "SELECT * FROM users WHERE name = ?",
    (username,)
)
"""
        self.assertFalse(
            contains_ast_pattern(different_query, self.security_pattern)
        )

    def test_detects_vulnerable_structure_without_security_pattern(self):
        source_code = """
def get_user(query):
    return database.execute(
        "SELECT * FROM users WHERE name = '" + query + "'"
    )
"""
        result = analyze_python_code(
            source_code,
            [self.vulnerable_pattern],
            [self.security_pattern],
        )
        self.assertTrue(result.vulnerable_pattern_found)
        self.assertFalse(result.security_pattern_found)
        self.assertTrue(result.suspicious)

    def test_recognizes_security_pattern(self):
        source_code = """
def get_user(query):
    return database.execute(
        "SELECT * FROM users WHERE name = ?",
        (query,)
    )
"""
        result = analyze_python_code(
            source_code,
            [self.vulnerable_pattern],
            [self.security_pattern],
        )
        self.assertFalse(result.vulnerable_pattern_found)
        self.assertTrue(result.security_pattern_found)
        self.assertFalse(result.suspicious)

    def test_reports_when_both_patterns_exist(self):
        source_code = self.vulnerable_pattern + "\n" + self.security_pattern
        result = analyze_python_code(
            source_code,
            [self.vulnerable_pattern],
            [self.security_pattern],
        )
        self.assertTrue(result.vulnerable_pattern_found)
        self.assertTrue(result.security_pattern_found)
        self.assertFalse(result.suspicious)

    def test_rejects_empty_pattern_lists(self):
        with self.assertRaises(ValueError):
            analyze_python_code("print('hello')", [], [self.security_pattern])

        with self.assertRaises(ValueError):
            analyze_python_code("print('hello')", [self.vulnerable_pattern], [])

    def test_returns_explanation(self):
        result = analyze_python_code(
            "print('hello')",
            [self.vulnerable_pattern],
            [self.security_pattern],
        )
        self.assertTrue(result.explanation)


if __name__ == "__main__":
    unittest.main(verbosity=2)
