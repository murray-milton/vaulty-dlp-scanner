"""
Wrapper file for safe Streamlit Cloud deployment.
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
# Import main Streamlit application (after path fix)
# noqa: E402 ← Only ignore for THIS line
# ---------------------------------------------------------
from vaulty.app_streamlit import *  # noqa: E402,F401,F403
