"""
Wrapper file for safe Streamlit Cloud deployment.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC_DIR = ROOT / "src"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))


def main() -> None:
    """Entrypoint kept for clarity; Streamlit executes app on import."""
    return None


if __name__ == "__main__":
    main()
