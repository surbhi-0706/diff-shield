
"""
DIFF SHIELD - Historical Patch Regression Detector

Initial MVP:
Compares vulnerable, patched, and newly modified source code.

This is a heuristic detector, not a proof of exploitability.
"""

from dataclasses import dataclass, asdict
from difflib import SequenceMatcher
from typing import Any
import re


@dataclass
class DetectionResult:
    vulnerable_code_reintroduced: bool
    severity: str
    confidence: float
    explanation: str
    restored_vulnerable_lines: list[str]
    missing_security_lines: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def normalize_line(line: str) -> str:
    """Normalize whitespace for basic line comparisons."""
    return re.sub(r"\s+", " ", line).strip()


def meaningful_lines(code: str) -> list[str]:
    """Extract non-empty normalized source lines."""
    return [
        normalize_line(line)
        for line in code.splitlines()
        if normalize_line(line)
    ]


def compare_code(
    original_vulnerable: str,
    patched_code: str,
    new_code: str,
) -> DetectionResult:
    """
    Compare three versions of a code fragment.

    A suspicious regression requires evidence that:
    1. Previously vulnerable code has returned.
    2. A protection introduced by the historical patch is absent.
    """

    vulnerable_lines = meaningful_lines(original_vulnerable)
    patched_lines = meaningful_lines(patched_code)
    current_lines = meaningful_lines(new_code)

    vulnerable_set = set(vulnerable_lines)
    patched_set = set(patched_lines)
    current_set = set(current_lines)

    # Lines present in the vulnerable version but removed
    # by the historical security patch.
    vulnerable_behavior = vulnerable_set - patched_set

    # Lines introduced by the security patch.
    security_protections = patched_set - vulnerable_set

    # Check whether vulnerable lines have returned.
    restored_lines = sorted(
        vulnerable_behavior & current_set
    )

    # Check whether historical security protections are missing.
    missing_lines = sorted(
        security_protections - current_set
    )

    # Both signals are required for this initial detector.
    is_regression = bool(restored_lines and missing_lines)

    if is_regression:
        overlap = len(restored_lines) + len(missing_lines)
        total = max(
            1,
            len(vulnerable_behavior) + len(security_protections)
        )

        confidence = min(0.95, 0.60 + (overlap / total) * 0.35)
        severity = "HIGH"

        explanation = (
            "Previously vulnerable code patterns appear to have "
            "returned, while security-related lines introduced "
            "by the historical patch are missing."
        )

    else:
        confidence = 0.0
        severity = "NONE"

        explanation = (
            "The initial line-based detector did not find both "
            "required regression signals. This does not guarantee "
            "that the code is secure."
        )

    return DetectionResult(
        vulnerable_code_reintroduced=is_regression,
        severity=severity,
        confidence=round(confidence, 2),
        explanation=explanation,
        restored_vulnerable_lines=restored_lines,
        missing_security_lines=missing_lines,
    )
