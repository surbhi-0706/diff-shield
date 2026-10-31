
"""
DIFF SHIELD - Combined Detection Pipeline

Combines:
1. Historical vulnerability intelligence
2. Git diff pattern analysis
3. Optional Python AST analysis

A NO_MATCH result does not prove that code is safe.
"""

from dataclasses import dataclass, asdict
from typing import Any, Optional

from analyzers.diff_analyzer import analyze_diff
from analyzers.ast_analyzer import analyze_python_code
from vulnerability_intel.patch_database import find_advisories


@dataclass
class AdvisoryAssessment:
    advisory_id: str
    vulnerability_type: str
    severity: str
    suspicious: bool
    added_vulnerable_lines: list[str]
    removed_security_lines: list[str]
    explanation: str
    detection_methods: list[str]


@dataclass
class PipelineResult:
    package_name: str
    ecosystem: str
    status: str
    assessed_advisories: int
    assessments: list[AdvisoryAssessment]
    explanation: str
    ast_analysis_performed: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def run_detection(
    package_name: str,
    ecosystem: str,
    diff_text: str,
    records: Optional[list[dict[str, Any]]] = None,
    source_code: Optional[str] = None,
    language: Optional[str] = None,
) -> PipelineResult:
    """
    Run historical vulnerability checks against a package diff.

    source_code:
        Optional complete updated source file. Required for AST analysis.

    language:
        Source language, currently supporting "python" for AST analysis.

    records:
        Optional advisory records, primarily useful for tests.
    """

    if not isinstance(package_name, str) or not package_name.strip():
        raise ValueError("Package name must be a non-empty string.")

    if not isinstance(ecosystem, str) or not ecosystem.strip():
        raise ValueError("Ecosystem must be a non-empty string.")

    if not isinstance(diff_text, str):
        raise ValueError("Diff text must be a string.")

    if source_code is not None and not isinstance(source_code, str):
        raise ValueError("Source code must be a string.")

    normalized_language = language.strip().lower() if language else None

    if source_code is not None and not normalized_language:
        raise ValueError(
            "Specify the source language when providing source code."
        )

    if normalized_language not in (None, "python"):
        raise ValueError(
            f"AST analysis does not yet support: {normalized_language}"
        )

    advisories = find_advisories(
        package_name=package_name,
        ecosystem=ecosystem,
        records=records,
    )

    if not advisories:
        return PipelineResult(
            package_name=package_name,
            ecosystem=ecosystem,
            status="NOT_ASSESSED",
            assessed_advisories=0,
            assessments=[],
            explanation=(
                "No matching historical advisory was found. "
                "The package has not been assessed by the current "
                "historical pattern database."
            ),
            ast_analysis_performed=False,
        )

    assessments = []
    ast_analysis_performed = False

    for advisory in advisories:

        # Method 1: Analyze added and deleted Git diff lines.
        diff_result = analyze_diff(
            diff_text=diff_text,
            vulnerable_patterns=advisory["vulnerable_patterns"],
            security_patterns=advisory["security_patterns"],
        )

        detection_methods = []

        if diff_result.suspicious:
            detection_methods.append("git_diff")

        # Method 2: Analyze the complete updated Python source.
        ast_result = None

        if source_code is not None and normalized_language == "python":
            ast_result = analyze_python_code(
                source_code=source_code,
                vulnerable_patterns=advisory["vulnerable_patterns"],
                security_patterns=advisory["security_patterns"],
            )

            ast_analysis_performed = True

            if ast_result.suspicious:
                detection_methods.append("python_ast")

        # A finding is suspicious if either method identifies it.
        suspicious = (
            diff_result.suspicious
            or (ast_result is not None and ast_result.suspicious)
        )

        explanations = [diff_result.explanation]

        if ast_result is not None:
            explanations.append(
                "Python AST analysis: " + ast_result.explanation
            )

        assessments.append(
            AdvisoryAssessment(
                advisory_id=advisory["advisory_id"],
                vulnerability_type=advisory["vulnerability_type"],
                severity=advisory["severity"],
                suspicious=suspicious,
                added_vulnerable_lines=(
                    diff_result.added_vulnerable_lines
                ),
                removed_security_lines=(
                    diff_result.removed_security_lines
                ),
                explanation=" ".join(explanations),
                detection_methods=detection_methods,
            )
        )

    suspicious_found = any(
        assessment.suspicious for assessment in assessments
    )

    if suspicious_found:
        status = "SUSPICIOUS"
        explanation = (
            "At least one historical advisory produced suspicious "
            "evidence. Review the reported code and detection methods."
        )
    else:
        status = "NO_MATCH"
        explanation = (
            "No supplied historical pattern produced both required "
            "regression signals. This does not prove that the code is safe."
        )

    return PipelineResult(
        package_name=package_name,
        ecosystem=ecosystem,
        status=status,
        assessed_advisories=len(advisories),
        assessments=assessments,
        explanation=explanation,
        ast_analysis_performed=ast_analysis_performed,
    )
