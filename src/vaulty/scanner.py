"""High-level orchestration: extractor selection + detection."""

from __future__ import annotations

import mimetypes
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .detectors import Finding, detect

SUPPORTED_SUFFIXES = {".txt", ".csv", ".pdf"}

SUPPORTED_MIME_TYPES = {
    "text/plain",
    "text/csv",
    "application/pdf",
}

ExtractorFunc = Callable[[Path], tuple[str, str]]


def _pick_extractor(path: Path) -> ExtractorFunc | None:
    """Return the correct extractor function for a file, if supported."""

    # ✅ CRITICAL FIX: Import extractors lazily to prevent global memory instability
    from .extractors import from_csv, from_pdf, from_txt

    suffix = path.suffix.lower()

    if suffix == ".txt":
        return from_txt
    if suffix == ".csv":
        return from_csv
    if suffix == ".pdf":
        return from_pdf

    mime_type, _ = mimetypes.guess_type(str(path))
    if mime_type == "text/plain":
        return from_txt
    if mime_type == "text/csv":
        return from_csv
    if mime_type == "application/pdf":
        return from_pdf

    return None


def read_any(path: Path) -> str:
    """Return text content from a supported file type."""
    extractor = _pick_extractor(path)
    if extractor is None:
        raise ValueError(f"Unsupported or unknown file type: {path}")

    _kind, text = extractor(path)
    return text


def scan_file(
    input_path: str | Path,
    *,
    options: dict[str, Any] | None = None,
) -> list[Finding]:
    """Scan a file by extracting text and running detectors."""
    path = Path(input_path)

    try:
        file_text = read_any(path)
    except ValueError:
        return []

    findings = detect(file_text, file_name=path.name)
    return findings
