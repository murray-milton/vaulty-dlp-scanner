"""
Wrapper file for safe Streamlit Cloud deployment.

This file does two things:
1. Adds the local `src/` directory to PYTHONPATH so `vaulty` can be imported.
2. Imports `vaulty.app_streamlit`, which builds the actual Streamlit UI.

Streamlit runs this file with `streamlit run streamlit_app.py`,
so simply importing `vaulty.app_streamlit` is enough to render the app.
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
    """Entry point for local debugging.

    Streamlit executes this file directly via `streamlit run streamlit_app.py`.
    Importing `vaulty.app_streamlit` at module import time is enough to
    construct and render the UI.
    """
    # We don't need to call anything here; the imported module already
    # calls Streamlit APIs at the top level.
    _ = _app  # keep linters happy


if __name__ == "__main__":
    main()
