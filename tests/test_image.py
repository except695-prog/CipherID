"""Tests for image extraction (QR / barcode / OCR).

QR + barcode tests run when pyzbar is importable AND a QR can be generated.
OCR tests are skipped unless a Tesseract binary is on PATH.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from cipherid.image import IMAGE_SUFFIXES, backend_status, extract_from_image, is_image_path

try:
    import qrcode  # noqa: F401
    HAVE_QRCODE = True
except ImportError:
    HAVE_QRCODE = False


def _gen_qr(payload: str, tmp_path: Path) -> Path:
    import qrcode
    img = qrcode.make(payload)
    out = tmp_path / "qr.png"
    img.save(out)
    return out


def test_is_image_path():
    assert is_image_path("flag.png")
    assert is_image_path("dir/foo.JPG")
    assert not is_image_path("data.txt")
    assert not is_image_path("script.py")
    assert IMAGE_SUFFIXES  # non-empty


def test_backend_status_returns_dict():
    status = backend_status()
    assert set(status.keys()) >= {"pillow", "pyzbar", "pytesseract", "tesseract_binary"}


@pytest.mark.skipif(not HAVE_QRCODE, reason="qrcode lib not installed")
@pytest.mark.skipif(not backend_status()["pyzbar"], reason="pyzbar not installed")
def test_qr_roundtrip(tmp_path):
    payload = "flag{qr_test_payload}"
    path = _gen_qr(payload, tmp_path)
    items = extract_from_image(path, ocr=False)
    assert any(i.text == payload for i in items), [i.text for i in items]
    assert any("qr" in i.source for i in items)


@pytest.mark.skipif(not HAVE_QRCODE, reason="qrcode lib not installed")
@pytest.mark.skipif(not backend_status()["pyzbar"], reason="pyzbar not installed")
def test_qr_then_engine_pipeline(tmp_path):
    """QR holds base64-encoded flag; full pipeline should reach the flag."""
    import base64

    from cipherid.engine import Engine
    plaintext = b"flag{qr_into_b64}"
    payload = base64.b64encode(plaintext).decode()
    path = _gen_qr(payload, tmp_path)

    items = extract_from_image(path, ocr=False)
    assert items, "no QR decoded"
    extracted_text = items[0].text

    engine = Engine()
    res = engine.auto_decode(extracted_text, flag_format="flag{}")
    assert res.flag_match == "flag{qr_into_b64}"


def test_extract_from_nonexistent_returns_empty(tmp_path):
    items = extract_from_image(tmp_path / "does-not-exist.png", ocr=False)
    assert items == []
