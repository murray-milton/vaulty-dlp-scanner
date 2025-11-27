"""
Wrapper file for safe Streamlit Cloud deployment.
"""

from __future__ import annotations

import sys
from pathlib import Path

# ---------------------------------------------------------
# 1. Add /src to PATH so Streamlit Cloud can import vaulty/*
# ---------------------------------------------------------
ROOT = Path(__file__).resolve().parent
SRC_DIR = ROOT / "src"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

# ---------------------------------------------------------
# 2. CRITICAL FIX: Ensure vaulty modules are registered
# ---------------------------------------------------------

# We import the required sub-modules *before* the main app to ensure
# they are registered in sys.modules, resolving the dataclasses bug.
try:
    # Use the built-in __import__ to force module registration.
    __import__("vaulty.detectors")
    __import__("vaulty.scanner")
except ImportError as e:
    # ✅ FIX: Raise the new exception 'from e' to comply with B904
    raise ImportError(f"Failed to import vaulty module during startup fix: {e}") from e

# ---------------------------------------------------------
# 3. Import the real app (this runs the UI)
# ---------------------------------------------------------
from vaulty import app_streamlit as _app  # noqa: E402,F401


def main() -> None:
    """Entry point for local debugging."""
    _ = _app  # keep linters happy


if __name__ == "__main__":
    main()
