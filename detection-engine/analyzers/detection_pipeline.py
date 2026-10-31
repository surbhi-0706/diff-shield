
"""
DIFF SHIELD - Combined Detection Pipeline

Connects historical patch intelligence with Git diff analysis.

Important:
NO_MATCH does not mean that a change is safe.
NOT_ASSESSED means no matching historical advisory was available.
"""

from dataclasses import dataclass, asdict
from typing import Any, Optional

from analyzers.diff_analyzer import analyze_diff
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


@dataclass
class PipelineResult:
    package_name: str
    ecosystem: str
    status: str
    assessed_advisories: int
    assessments: list[AdvisoryAssessment]
    explanation: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def run_detection(
    package_name: str,
    ecosystem: str,
    diff_text: str,
    records: Optional[list[dict[str, Any]]] = None,
) -> PipelineResult:
    """
    Run historical pattern checks against a package's Git diff.

    records is optional and mainly useful for tests. When omitted,
    the curated historical database is loaded automatically.
    """

    if not isinstance(package_name, str) or not package_name.strip():
        raise ValueError("Package name must be a non-empty string.")

    if not isinstance(ecosystem, str) or not ecosystem.strip():
        raise ValueError("Ecosystem must be a non-empty string.")

    if not isinstance(diff_text, str):
        raise ValueError("Diff text must be a string.")

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
                "This package has not been assessed by the current "
                "historical pattern database."
            ),
        )

    assessments = []

    for advisory in advisories:
        diff_result = analyze_diff(
            diff_text=diff_text,
            vulnerable_patterns=advisory["vulnerable_patterns"],
            security_patterns=advisory["security_patterns"],
        )

        assessments.append(
            AdvisoryAssessment(
                advisory_id=advisory["advisory_id"],
                vulnerability_type=advisory["vulnerability_type"],
                severity=advisory["severity"],
                suspicious=diff_result.suspicious,
                added_vulnerable_lines=(
                    diff_result.added_vulnerable_lines
                ),
                removed_security_lines=(
                    diff_result.removed_security_lines
                ),
                explanation=diff_result.explanation,
            )
        )

    suspicious_found = any(
        assessment.suspicious for assessment in assessments
    )

    if suspicious_found:
        status = "SUSPICIOUS"
        explanation = (
            "At least one historical advisory matched both a "
            "known vulnerable addition and a removed security pattern. "
            "Manual security review is recommended."
        )
    else:
        status = "NO_MATCH"
        explanation = (
            "Historical advisories were available, but the current "
            "exact-line checks did not find both regression signals. "
            "This does not prove that the change is safe."
        )

    return PipelineResult(
        package_name=package_name,
        ecosystem=ecosystem,
        status=status,
        assessed_advisories=len(advisories),
        assessments=assessments,
        explanation=explanation,
    )
