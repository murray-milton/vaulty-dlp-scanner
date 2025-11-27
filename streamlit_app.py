# ruff: noqa: F401, F403, E402
"""
Streamlit Cloud entrypoint for Vaulty.


"""

from __future__ import annotations

import sys
from pathlib import Path

from vaulty.app_streamlit import *

ROOT = Path(__file__).resolve().parent
SRC_DIR = ROOT / "src"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))
