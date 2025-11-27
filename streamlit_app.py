# ruff: noqa: F401, F403, E402
"""
Streamlit Cloud entrypoint for Vaulty.

This wrapper:
- Adds ./src to sys.path so that the `vaulty` package can be imported
  correctly on Streamlit Cloud.
- Then imports the real app module, which builds the UI.
"""

from __future__ import annotations

import sys
from pathlib import Path

# ---------------------------------------------------------------------
# Ensure `src/` is importable (so `import vaulty` works on Streamlit)
# ---------------------------------------------------------------------
ROOT = Path(__file__).resolve().parent
SRC_DIR = ROOT / "src"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

# ---------------------------------------------------------------------
# Import everything from the real app module.
# The UI is defined inside `vaulty.app_streamlit`.
# ---------------------------------------------------------------------
from vaulty.app_streamlit import *  # noqa: F401,F403,E402
