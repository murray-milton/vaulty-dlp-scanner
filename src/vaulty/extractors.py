# vaulty/extractors.py (Ensure your code follows this pattern)

from __future__ import annotations

import csv  # Keep lightweight imports here
from pathlib import Path

# 🚫 DELETE all imports related to pdfminer, pypdf, or heavy libraries from here!

# ---------------------------------------------------------
# TEXT Extractor (Lightweight)
# ---------------------------------------------------------


def from_txt(path: Path) -> tuple[str, str]:
    """Read content from a text file."""
    # No external imports needed
    return "text", path.read_text(encoding="utf-8")


# ---------------------------------------------------------
# CSV Extractor (Lightweight)
# ---------------------------------------------------------


def from_csv(path: Path) -> tuple[str, str]:
    """Read content from a CSV file and return concatenated text."""
    # Only uses the global 'csv' library (lightweight)
    all_text = []
    with path.open("r", newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        for row in reader:
            all_text.extend(row)
    return "csv", " ".join(all_text)


# ---------------------------------------------------------
# PDF Extractor (CRITICAL - LAZY IMPORT HEAVY MODULES)
# ---------------------------------------------------------


def from_pdf(path: Path) -> tuple[str, str]:
    """Read content from a PDF file."""
    # ✅ CRITICAL FIX: The memory-intensive import must be inside the function.
    from io import StringIO

    from pdfminer.high_level import extract_text_to_fp

    output_string = StringIO()

    # Use pdfminer logic here
    with path.open("rb") as input_file:
        extract_text_to_fp(input_file, output_string)

    return "pdf", output_string.getvalue()
