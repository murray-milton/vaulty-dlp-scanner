"""Report generation utilities (JSON export + human summary)."""

from __future__ import annotations

import json
from pathlib import Path

from .detectors import Finding


def to_json(findings: list[Finding], outfile: Path) -> None:
    """Write findings to JSON using a stable schema.
    Examples:
        >>> from pathlib import Path
        >>> f = Finding(
        ...     detector="email",
        ...     match="a@b.com",
        ...     start=0,
        ...     end=6,
        ...     risk_score=2.0,
        ...     why="base=2.0 + context_boost=0.0",
        ... )
        >>> to_json([f], Path("data/reports/example.json"))  # doctest: +SKIP
    """
    payload = [f.to_dict() for f in findings]
    outfile.parent.mkdir(parents=True, exist_ok=True)
    outfile.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def human_summary(findings: list[Finding]) -> str:
    """Return a human-friendly summary with category counts only.
    Examples:
        >>> f = Finding(
        ...     detector="email",
        ...     match="a@b.com",
        ...     start=0,
        ...     end=6,
        ...     risk_score=2.0,
        ...     why="base=2.0 + context_boost=0.0",
        ... )
        >>> "email" in human_summary([f])
        True
    """
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.detector] = counts.get(finding.detector, 0) + 1

    if not counts:
        return "Findings Summary:\n- No issues detected"

    lines = [f"- {detector}: {count}" for detector, count in sorted(counts.items())]
    return "Findings Summary:\n" + "\n".join(lines)


# Developer note:
