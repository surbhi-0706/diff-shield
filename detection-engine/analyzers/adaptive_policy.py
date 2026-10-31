
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, timezone
from typing import Optional


HOLD_HOURS = 12


@dataclass
class PolicyDecision:
    status: str
    merge_blocked: bool
    prepare_recovery: bool
    review_required: bool
    hold_until: Optional[str]
    confidence: float
    risk_score: int
    explanation: str

    def to_dict(self):
        return asdict(self)


def evaluate_policy(
    suspicious: bool,
    confidence: float = 0.0,
    risk_score: int = 0,
    severity: str = "LOW",
    evidence_count: int = 0,
    now: Optional[datetime] = None,
) -> PolicyDecision:

    if not isinstance(suspicious, bool):
        raise ValueError("suspicious must be boolean")

    if not isinstance(confidence, (int, float)) or isinstance(confidence, bool) or not 0 <= confidence <= 1:
        raise ValueError("confidence must be between 0 and 1")

    if not isinstance(risk_score, int) or isinstance(risk_score, bool) or not 0 <= risk_score <= 100:
        raise ValueError("risk_score must be an integer between 0 and 100")

    if not isinstance(evidence_count, int) or isinstance(evidence_count, bool) or evidence_count < 0:
        raise ValueError("evidence_count must be a non-negative integer")

    severity = severity.upper()

    if severity not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        raise ValueError("Invalid severity")

    if now is None:
        now = datetime.now(timezone.utc)

    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("now must be timezone-aware")

    if not suspicious:
        return PolicyDecision(
            status="CLEAN",
            merge_blocked=False,
            prepare_recovery=False,
            review_required=False,
            hold_until=None,
            confidence=float(confidence),
            risk_score=risk_score,
            explanation="No suspicious change was reported.",
        )

    high_confidence = (
        confidence >= 0.90
        and risk_score >= 85
        and evidence_count >= 2
        and severity in {"HIGH", "CRITICAL"}
    )

    if high_confidence:
        return PolicyDecision(
            status="HIGH_CONFIDENCE",
            merge_blocked=True,
            prepare_recovery=True,
            review_required=True,
            hold_until=None,
            confidence=float(confidence),
            risk_score=risk_score,
            explanation=(
                "Multiple strong security indicators were found. "
                "Block merging and prepare a corrective pull request "
                "for maintainer approval."
            ),
        )

    deadline = now + timedelta(hours=HOLD_HOURS)

    return PolicyDecision(
        status="REVIEW_REQUIRED",
        merge_blocked=True,
        prepare_recovery=False,
        review_required=True,
        hold_until=deadline.isoformat(),
        confidence=float(confidence),
        risk_score=risk_score,
        explanation=(
            "Suspicious changes require investigation. "
            "Keep the PR blocked and escalate after 12 hours "
            "if the finding remains unresolved."
        ),
    )
