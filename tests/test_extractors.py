from pathlib import Path

from vaulty.extractors import from_csv, from_txt


def test_from_txt(tmp_path: Path) -> None:
    test_file = tmp_path / "a.txt"
    test_file.write_text("hello äöü", encoding="utf-8")

    kind, text = from_txt(test_file)
    assert kind == "text"
    assert "hello" in text


def test_from_csv(tmp_path: Path) -> None:
    test_file = tmp_path / "a.csv"
    test_file.write_text("email,name\nx@y.com,John", encoding="utf-8")

    kind, text = from_csv(test_file)
    assert kind == "csv"
    assert "x@y.com" in text
    assert "John" in text
