"""Pattern-based sensitive data detection with explainable scoring."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass

from .validators import luhn_valid

PATTERNS: dict[str, re.Pattern[str]] = {
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "ssn_us": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "phone": re.compile(r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
    "credit_card": re.compile(r"\b(?:\d[ -]?){13,19}\b"),
}

# Base risk by type (0–10 scale is capped later)
RISK_BASE_BY_TYPE: dict[str, float] = {
    "credit_card": 4.0,
    "ssn_us": 4.0,
    "email": 2.0,
    "phone": 2.0,
}

# Context boost terms for explainable scoring
RISK_CONTEXT_BOOST_TERMS: dict[str, float] = {
    "ssn": 0.5,
    "visa": 0.5,
    "mastercard": 0.5,
    "password": 0.5,
}


@dataclass(slots=True)
class Finding:
    """Single detection finding for review and reporting.

    Attributes:
        detector:
            Name of the detector that triggered (e.g. "email", "credit_card").
        match:
            The exact substring that matched.
        start:
            Start character offset of the match.
        end:
            End character offset of the match.
        risk_score:
            Final numeric score (0–10 capped). Higher means higher risk.
        why:
            Human-readable scoring explanation string ("base=...+boost=...").
    """

    detector: str
    match: str
    start: int
    end: int
    risk_score: float
    why: str

    def to_dict(self) -> dict[str, object]:
        """Return a stable, serializable representation of this finding."""
        return asdict(self)


def _validate_detector_hit(detector: str, value: str) -> bool:
    """Return True if the candidate should be kept after validation."""
    if detector == "credit_card":
        return luhn_valid(value)
    return True


def _score_with_context(detector: str, context_window: str) -> tuple[float, str]:
    """Return (score, why) based on base risk and context terms."""
    base = RISK_BASE_BY_TYPE.get(detector, 2.0)
    lower_ctx = context_window.lower()

    applied_boost = 0.0
    for word, inc in RISK_CONTEXT_BOOST_TERMS.items():
        if word in lower_ctx:
            # take the max boost term seen in context
            applied_boost = max(applied_boost, inc)

    score = min(10.0, base + applied_boost)
    why = f"base={base} + context_boost={applied_boost:.1f}"
    return score, why


def detect(text: str, *, file_name: str | None = None) -> list[Finding]:
    """Run all detectors on input text and return a list of Finding objects."""
    findings: list[Finding] = []

    for detector_name, pattern in PATTERNS.items():
        for match_obj in pattern.finditer(text):
            raw_value = match_obj.group(0)

            if not _validate_detector_hit(detector_name, raw_value):
                continue

            # Will handle our scoring and explainability.
            left_idx = max(0, match_obj.start() - 40)
            right_idx = min(len(text), match_obj.end() + 40)
            window = text[left_idx:right_idx]

            score, why = _score_with_context(detector_name, window)

            findings.append(
                Finding(
                    detector=detector_name,
                    match=raw_value,
                    start=match_obj.start(),
                    end=match_obj.end(),
                    risk_score=score,
                    why=why,
                )
            )

    return findings


# Developer note:
