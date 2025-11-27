"""Report generation utilities."""

from __future__ import annotations

import json
from pathlib import Path

from .detectors import Finding


def to_json(findings: list[Finding], outfile: Path, return_as_string: bool = False) -> str | None:
    payload = [f.to_dict() for f in findings]
    json_str = json.dumps(payload, indent=2)

    if return_as_string:
        return json_str

    outfile.parent.mkdir(parents=True, exist_ok=True)
    outfile.write_text(json_str, encoding="utf-8")
    return None


def human_summary(findings: list[Finding]) -> str:
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.detector] = counts.get(finding.detector, 0) + 1

    if not counts:
        return "Findings Summary:\n- No issues detected"

    lines = [f"- {detector}: {count}" for detector, count in sorted(counts.items())]
    return "Findings Summary:\n" + "\n".join(lines)
