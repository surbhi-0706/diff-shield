
"""
DIFF SHIELD - Git Diff Analyzer

Extracts added and deleted lines from unified Git diffs.
Normalizes harmless whitespace before matching known patterns.

Limitations:
- Matching is line-based.
- This is not a language-aware parser.
- It does not prove that code is safe or exploitable.
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


def normalize_code_line(line: str) -> str:
    """
    Normalize harmless whitespace outside quoted strings.

    Preserves spaces inside:
    - Single-quoted strings
    - Double-quoted strings
    - Backtick-quoted strings

    Normalizes spacing around parentheses, brackets,
    braces and commas.
    """

    result = []
    quote = None
    escaped = False
    pending_space = False

    opening = "([{"
    closing = ")]}"

    for char in line.strip():

        # Preserve string contents exactly.
        if quote is not None:
            result.append(char)

            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None

            continue

        # Start of a quoted string.
        if char in ("'", '"', "`"):

            if pending_space and result:
                if result[-1] not in opening and result[-1] != ",":
                    result.append(" ")

            result.append(char)
            quote = char
            pending_space = False
            continue

        # Whitespace outside strings.
        if char.isspace():
            pending_space = True
            continue

        # Normalize spacing before closing punctuation.
        if char in closing or char == ",":
            if result and result[-1] == " ":
                result.pop()

            result.append(char)
            pending_space = False
            continue

        # Normalize spacing after opening punctuation.
        if char in opening:
            if pending_space and result and result[-1] == " ":
                result.pop()

            result.append(char)
            pending_space = False
            continue

        # Keep one space between ordinary tokens.
        if pending_space and result:
            result.append(" ")

        result.append(char)
        pending_space = False

    return "".join(result).strip()


def parse_unified_diff(diff_text: str) -> list[FileDiff]:
    """
    Extract added and deleted lines from a unified Git diff.

    Groups changes by filename and ignores diff metadata.
    """

    files = []
    current_file = None

    for line in diff_text.splitlines():

        if line.startswith("diff --git "):
            current_file = None
            continue

        if line.startswith("+++ "):
            filename = line[4:].strip()

            if filename == "/dev/null":
                current_file = None
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
    Detect known vulnerable additions and removed security patterns.

    Matching uses normalized individual lines.
    """

    files = parse_unified_diff(diff_text)

    added = {
        normalize_code_line(line)
        for file in files
        for line in file.added_lines
        if normalize_code_line(line)
    }

    deleted = {
        normalize_code_line(line)
        for file in files
        for line in file.deleted_lines
        if normalize_code_line(line)
    }

    vulnerable = {
        normalize_code_line(line)
        for line in vulnerable_patterns
        if normalize_code_line(line)
    }

    protections = {
        normalize_code_line(line)
        for line in security_patterns
        if normalize_code_line(line)
    }

    added_vulnerable = sorted(added & vulnerable)
    removed_security = sorted(deleted & protections)

    suspicious = bool(
        added_vulnerable and removed_security
    )

    if suspicious:
        explanation = (
            "The diff adds a known vulnerable code pattern and "
            "removes a known security protection."
        )
    else:
        explanation = (
            "The diff did not contain both a known vulnerable "
            "addition and a known security-protection deletion. "
            "This does not prove that the change is safe."
        )

    return DiffAnalysis(
        suspicious=suspicious,
        added_vulnerable_lines=added_vulnerable,
        removed_security_lines=removed_security,
        explanation=explanation,
    )
