from vaulty.detectors import detect


def test_email_detection() -> None:
    text = "Contact me at user.name+tag@sub.example.co.uk"
    out = detect(text)
    assert any(f.detector == "email" for f in out)


def test_credit_card_luhn_filters_false_positives() -> None:
    text = "Number: 4111 1111 1111 1112"
    out = detect(text)
    assert not any(f.detector == "credit_card" for f in out)


def test_credit_card_valid_passes() -> None:
    text = "Visa: 4111-1111-1111-1111"
    out = detect(text)
    assert any(f.detector == "credit_card" for f in out)


def test_empty_text_is_safe() -> None:
    assert detect("") == []


# Developer Notes and revisions
