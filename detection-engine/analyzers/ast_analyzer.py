
"""
DIFF SHIELD - Python AST Analyzer

Compares Python code structures instead of raw source lines.

AST matching ignores formatting and indentation differences,
but preserves meaningful syntax and string values.

This is structural pattern matching, not full semantic analysis.
"""

import ast
from dataclasses import dataclass


@dataclass
class ASTAnalysis:
    vulnerable_pattern_found: bool
    security_pattern_found: bool
    suspicious: bool
    matched_vulnerable_patterns: list[str]
    matched_security_patterns: list[str]
    explanation: str


def parse_python(source_code: str) -> ast.Module:
    """Parse Python source code into an AST."""

    if not isinstance(source_code, str):
        raise ValueError("Python source code must be a string.")

    try:
        return ast.parse(source_code)
    except SyntaxError as error:
        raise ValueError(
            f"Invalid Python syntax at line {error.lineno}: {error.msg}"
        ) from error


def get_node_fingerprints(source_code: str) -> set[str]:
    """
    Return structural fingerprints for every AST node.

    Location attributes such as line numbers and column offsets
    are excluded, so formatting differences do not affect matching.
    """

    tree = parse_python(source_code)

    return {
        ast.dump(node, annotate_fields=True, include_attributes=False)
        for node in ast.walk(tree)
    }


def contains_ast_pattern(
    source_code: str,
    pattern_code: str,
) -> bool:
    """Check whether a pattern's AST structure exists in source code."""

    pattern_tree = parse_python(pattern_code)

    if not pattern_tree.body:
        raise ValueError("AST pattern cannot be empty.")

    # A pattern may contain multiple statements. Every top-level
    # statement must be present in the candidate source.
    source_fingerprints = get_node_fingerprints(source_code)

    for statement in pattern_tree.body:
        statement_fingerprints = {
            ast.dump(node, annotate_fields=True, include_attributes=False)
            for node in (
                (statement, statement.value)
                if isinstance(statement, ast.Expr)
                else (statement,)
            )
        }

        if not statement_fingerprints.intersection(source_fingerprints):
            return False

    return True


def analyze_python_code(
    source_code: str,
    vulnerable_patterns: list[str],
    security_patterns: list[str],
) -> ASTAnalysis:
    """
    Look for known vulnerable structures and security protections
    in a complete Python source snapshot.

    A suspicious result requires a vulnerable pattern to be present
    and none of the supplied security patterns to be present.
    """

    if not vulnerable_patterns:
        raise ValueError("At least one vulnerable pattern is required.")

    if not security_patterns:
        raise ValueError("At least one security pattern is required.")

    matched_vulnerable = [
        pattern
        for pattern in vulnerable_patterns
        if contains_ast_pattern(source_code, pattern)
    ]

    matched_security = [
        pattern
        for pattern in security_patterns
        if contains_ast_pattern(source_code, pattern)
    ]

    vulnerable_found = bool(matched_vulnerable)
    security_found = bool(matched_security)

    suspicious = vulnerable_found and not security_found

    if suspicious:
        explanation = (
            "A known vulnerable Python code structure was found, "
            "and none of the supplied security patterns were found. "
            "Manual security review is recommended."
        )
    elif vulnerable_found and security_found:
        explanation = (
            "A known vulnerable structure and a supplied security "
            "pattern were both found. The code needs contextual review."
        )
    elif security_found:
        explanation = (
            "A supplied security pattern was found, and no known "
            "vulnerable pattern was detected."
        )
    else:
        explanation = (
            "No supplied vulnerable or security pattern was found. "
            "This does not prove that the code is safe."
        )

    return ASTAnalysis(
        vulnerable_pattern_found=vulnerable_found,
        security_pattern_found=security_found,
        suspicious=suspicious,
        matched_vulnerable_patterns=matched_vulnerable,
        matched_security_patterns=matched_security,
        explanation=explanation,
    )
