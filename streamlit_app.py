"""
Wrapper file for safe Streamlit Cloud deployment.

This file adds the local `src/` directory to PYTHONPATH so `vaulty` can be imported,
then imports and runs the actual Streamlit UI from `vaulty.app_streamlit`.
"""

from __future__ import annotations

import sys
from pathlib import Path

# ---------------------------------------------------------
# Add /src to PATH so Streamlit Cloud can import vaulty/*
# ---------------------------------------------------------
ROOT = Path(__file__).resolve().parent
SRC_DIR = ROOT / "src"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

# ---------------------------------------------------------
# Import the real app (this runs the UI)
# ---------------------------------------------------------
from vaulty import app_streamlit as _app  # noqa: E402,F401


def main() -> None:
    """Entry point for local debugging."""
    # Importing _app is enough to construct the UI
    _ = _app


if __name__ == "__main__":
    main()
