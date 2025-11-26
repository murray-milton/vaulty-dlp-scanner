from pathlib import Path

import pytest

from vaulty.scanner import read_any, scan_file


def test_unsupported_file_suffix(tmp_path: Path) -> None:
    md_file = tmp_path / "x.md"
    md_file.write_text("# hello", encoding="utf-8")

    with pytest.raises(ValueError):
        read_any(md_file)


def test_scan_file_txt(tmp_path: Path) -> None:
    test_file = tmp_path / "doc.txt"
    test_file.write_text(
        "Email: a@b.com SSN: 123-45-6789 Phone: 555-123-4567",
        encoding="utf-8",
    )

    out = scan_file(test_file)
    names = {f.detector for f in out}

    assert "email" in names
    assert "ssn_us" in names
    assert "phone" in names
