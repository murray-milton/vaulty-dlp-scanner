"""Validation utilities for sensitive-data candidates."""

from __future__ import annotations


def digits_only(text: str) -> str:
    """Return only the digits in text."""
    return "".join(ch for ch in text if ch.isdigit())


def luhn_valid(candidate: str) -> bool:
    """Return True if candidate passes the Luhn checksum (credit cards)."""
    s = digits_only(candidate)
    if not (13 <= len(s) <= 19):
        return False

    total = 0
    reversed_digits = list(map(int, reversed(s)))
    for index, digit in enumerate(reversed_digits):
        new_val = digit
        if index % 2 == 1:
            new_val *= 2
            if new_val > 9:
                new_val -= 9
        total += new_val

    return total % 10 == 0
