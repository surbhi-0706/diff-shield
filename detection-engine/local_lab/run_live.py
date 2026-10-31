
"""
DIFF SHIELD - Local Live Testing Lab

Watches current.py for changes, compares it with baseline.py,
and runs the existing detection pipeline automatically.

Press Ctrl+C to stop.
"""

import difflib
import sys
import time
from pathlib import Path

# Locate the detection-engine directory.
ENGINE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENGINE_ROOT))

from analyzers.detection_pipeline import run_detection


BASELINE_FILE = Path(__file__).resolve().parent / "baseline.py"
CURRENT_FILE = Path(__file__).resolve().parent / "current.py"

PACKAGE_NAME = "demo-db-client"
ECOSYSTEM = "pypi"

POLL_INTERVAL = 1.0


def read_source(path: Path) -> str:
    """Read a Python source file."""
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    return path.read_text(encoding="utf-8")


def create_diff(old_source: str, new_source: str) -> str:
    """Create a unified Git-style diff between two source snapshots."""

    return "".join(
        difflib.unified_diff(
            old_source.splitlines(keepends=True),
            new_source.splitlines(keepends=True),
            fromfile="a/example.py",
            tofile="b/example.py",
        )
    )


def run_once() -> None:
    """Run DIFF SHIELD against the current test file."""

    baseline = read_source(BASELINE_FILE)
    current = read_source(CURRENT_FILE)

    diff_text = create_diff(baseline, current)

    result = run_detection(
        package_name=PACKAGE_NAME,
        ecosystem=ECOSYSTEM,
        diff_text=diff_text,
        source_code=current,
        language="python",
    )

    print("\n" + "=" * 60)
    print("             DIFF SHIELD - LIVE SCAN")
    print("=" * 60)

    print(f"Package:       {result.package_name}")
    print(f"Ecosystem:     {result.ecosystem}")
    print(f"Status:        {result.status}")
    print(f"Advisories:    {result.assessed_advisories}")
    print(f"AST performed: {result.ast_analysis_performed}")

    for assessment in result.assessments:
        print("\nAdvisory:", assessment.advisory_id)
        print("Severity:", assessment.severity)
        print("Methods:", assessment.detection_methods or ["No match"])

        print("\nAdded vulnerable lines:")
        for line in assessment.added_vulnerable_lines:
            print("  +", line)

        print("\nRemoved security lines:")
        for line in assessment.removed_security_lines:
            print("  -", line)

        print("\nExplanation:")
        print(assessment.explanation)

    print("\nOverall explanation:")
    print(result.explanation)
    print("=" * 60)


def main() -> None:
    """Run an initial scan, then watch current.py for changes."""

    print("DIFF SHIELD local live testing started.")
    print(f"Watching: {CURRENT_FILE}")
    print("Change current.py to trigger another scan.")
    print("Press Ctrl+C to stop.")

    last_modified = None

    try:
        while True:
            modified = CURRENT_FILE.stat().st_mtime_ns

            if modified != last_modified:
                last_modified = modified

                try:
                    run_once()
                except (ValueError, FileNotFoundError) as error:
                    print(f"\nScan could not complete: {error}")

            time.sleep(POLL_INTERVAL)

    except KeyboardInterrupt:
        print("\nDIFF SHIELD live testing stopped.")


if __name__ == "__main__":
    main()
