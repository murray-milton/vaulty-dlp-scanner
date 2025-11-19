"""Deterministic text extraction from TXT, CSV, and PDF files."""

from __future__ import annotations

from pathlib import Path

from pdfminer.high_level import extract_text as pdf_extract_text


def from_txt(path: str | Path) -> tuple[str, str]:
    """Extract text from a UTF-8 (or near) TXT file."""
    with open(path, encoding="utf-8", errors="ignore") as handle:
        return "text", handle.read()


def from_csv(path: str | Path) -> tuple[str, str]:
    """Extract CSV as plain text (preserves rows verbatim)."""
    with open(path, encoding="utf-8", errors="ignore") as handle:
        return "csv", handle.read()


def from_pdf(path: str | Path) -> tuple[str, str]:
    """Extract text from PDF using pdfminer.six."""
    return "pdf", pdf_extract_text(str(path))


# Developer note:
# We keep extractors side-effect free except for file reads.
