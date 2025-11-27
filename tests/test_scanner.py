"""Tests for the high-level scanner module."""

from pathlib import Path

from vaulty.scanner import read_any, scan_file


def test_read_any_txt(tmp_path: Path) -> None:
    f = tmp_path / "test.txt"
    f.write_text("Hello World", encoding="utf-8")
    content = read_any(f)
    assert content == "Hello World"


def test_scan_file_txt(tmp_path: Path) -> None:
    test_file = tmp_path / "doc.txt"
    test_file.write_text(
        "Email: a@b.com SSN: 123-45-6789 Phone: 555-123-4567",
        encoding="utf-8",
    )

    findings, text = scan_file(test_file)

    names = {f.detector for f in findings}

    assert "email" in names
    assert "ssn_us" in names
    assert "phone" in names
    assert len(findings) == 3
    assert "Email: a@b.com" in text


def test_scan_file_no_findings(tmp_path: Path) -> None:
    test_file = tmp_path / "clean.txt"
    test_file.write_text("Just some clean text.", encoding="utf-8")

    findings, text = scan_file(test_file)

    assert len(findings) == 0
    assert text == "Just some clean text."
