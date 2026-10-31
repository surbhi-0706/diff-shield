
"""
DIFF SHIELD - Git Diff Analyzer

Extracts added and deleted source lines from a unified Git diff.
This is an initial parser, not a complete Git patch implementation.
"""

from dataclasses import dataclass, field


@dataclass
class FileDiff:
    filename: str
    added_lines: list[str] = field(default_factory=list)
    deleted_lines: list[str] = field(default_factory=list)


@dataclass
class DiffAnalysis:
    suspicious: bool
    added_vulnerable_lines: list[str]
    removed_security_lines: list[str]
    explanation: str


def parse_unified_diff(diff_text: str) -> list[FileDiff]:
    """Extract added and deleted lines, grouped by file."""

    files = []
    current_file = None

    for line in diff_text.splitlines():

        if line.startswith("diff --git "):
            current_file = None
            continue

        if line.startswith("+++ "):
            filename = line[4:].strip()

            if filename == "/dev/null":
                continue

            if filename.startswith("b/"):
                filename = filename[2:]

            current_file = FileDiff(filename=filename)
            files.append(current_file)
            continue

        if line.startswith("--- "):
            continue

        if current_file is None:
            continue

        if line.startswith("+") and not line.startswith("+++"):
            current_file.added_lines.append(line[1:])

        elif line.startswith("-") and not line.startswith("---"):
            current_file.deleted_lines.append(line[1:])

    return files


def analyze_diff(
    diff_text: str,
    vulnerable_patterns: list[str],
    security_patterns: list[str],
) -> DiffAnalysis:
    """
    Look for known vulnerable patterns being added and known
    security protections being deleted.

    Exact normalized line matching only.
    """

    files = parse_unified_diff(diff_text)

    added = {
        line.strip()
        for file in files
        for line in file.added_lines
        if line.strip()
    }

    deleted = {
        line.strip()
        for file in files
        for line in file.deleted_lines
        if line.strip()
    }

    vulnerable = {line.strip() for line in vulnerable_patterns}
    protections = {line.strip() for line in security_patterns}

    added_vulnerable = sorted(added & vulnerable)
    removed_security = sorted(deleted & protections)

    suspicious = bool(added_vulnerable and removed_security)

    if suspicious:
        explanation = (
            "The diff adds a known vulnerable code pattern and "
            "removes a known security protection."
        )
    else:
        explanation = (
            "The diff did not contain both a known vulnerable "
            "addition and a known security-protection deletion. "
            "This does not prove the change is safe."
        )

    return DiffAnalysis(
        suspicious=suspicious,
        added_vulnerable_lines=added_vulnerable,
        removed_security_lines=removed_security,
        explanation=explanation,
    )
