"""Utility helpers for logging and filename safety.

Security:
    - We never log raw PII.
    - Filenames are sanitized before writing reports.
"""

from __future__ import annotations

import logging
import re

SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9_.-]+")


def get_logger(name: str) -> logging.Logger:
    """Return a configured logger that avoids duplicate handlers."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
        logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    return logger


def safe_filename(name: str) -> str:
    """Return a filesystem-friendly filename with dangerous characters removed."""
    cleaned = SAFE_NAME_RE.sub("_", name)
    return cleaned.strip("_") or "upload"
