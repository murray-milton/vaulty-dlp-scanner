"""High-level scanning orchestration."""

from __future__ import annotations

from pathlib import Path

from . import extractors as ex
from .detectors import Finding, detect

SUPPORTED_SUFFIXES = {".txt", ".csv", ".pdf"}


def read_any(path: Path) -> str:

    suffix = path.suffix.lower()
    if suffix == ".txt":
        _, text = ex.from_txt(path)
    elif suffix == ".csv":
        _, text = ex.from_csv(path)
    elif suffix == ".pdf":
        _, text = ex.from_pdf(path)
    else:
        raise ValueError(f"Unsupported file type: {suffix}")
    return text


def scan_file(path: Path) -> list[Finding]:
    """Extract text and run detectors, returning normalized findings."""
    return detect(read_any(path))


# Developer note:
# Keep orchestration glue-thin; business rules live in detectors/reporting.
