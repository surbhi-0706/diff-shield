
import sys
import unittest
from datetime import datetime, timezone, timedelta
from pathlib import Path

ENGINE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENGINE_ROOT))

from analyzers.adaptive_policy import evaluate_policy


class TestAdaptivePolicy(unittest.TestCase):

    def setUp(self):
        self.now = datetime(
            2026, 10, 31, 12, 0,
            tzinfo=timezone.utc
        )

    def test_clean_pr(self):
        result = evaluate_policy(
            suspicious=False,
            now=self.now
        )

        self.assertEqual(result.status, "CLEAN")
        self.assertFalse(result.merge_blocked)

    def test_high_confidence_threat(self):
        result = evaluate_policy(
            suspicious=True,
            confidence=0.97,
            risk_score=95,
            severity="CRITICAL",
            evidence_count=3,
            now=self.now
        )

        self.assertEqual(result.status, "HIGH_CONFIDENCE")
        self.assertTrue(result.merge_blocked)
        self.assertTrue(result.prepare_recovery)

    def test_uncertain_threat(self):
        result = evaluate_policy(
            suspicious=True,
            confidence=0.65,
            risk_score=60,
            severity="MEDIUM",
            evidence_count=1,
            now=self.now
        )

        expected = (
            self.now + timedelta(hours=12)
        ).isoformat()

        self.assertEqual(result.status, "REVIEW_REQUIRED")
        self.assertTrue(result.merge_blocked)
        self.assertEqual(result.hold_until, expected)

    def test_insufficient_evidence_requires_review(self):
        result = evaluate_policy(
            suspicious=True,
            confidence=0.99,
            risk_score=99,
            severity="CRITICAL",
            evidence_count=1,
            now=self.now
        )

        self.assertEqual(result.status, "REVIEW_REQUIRED")
        self.assertFalse(result.prepare_recovery)

    def test_invalid_confidence(self):
        with self.assertRaises(ValueError):
            evaluate_policy(
                suspicious=True,
                confidence=1.5,
                now=self.now
            )

    def test_invalid_risk_score(self):
        with self.assertRaises(ValueError):
            evaluate_policy(
                suspicious=True,
                risk_score=120,
                now=self.now
            )


if __name__ == "__main__":
    unittest.main()
