"""Image preprocessing: pull text out of QR codes, barcodes, and screenshots.

This is a *preprocessing* step. After extraction, the resulting text is fed
back into the normal :class:`Engine` pipeline.

Backends used (all optional — graceful fallback if a backend isn't installed):
  - Pillow            — image loading (required for any image input).
  - pyzbar            — QR Code, Data Matrix, PDF417, Aztec, 1-D barcodes.
  - pytesseract + tesseract binary — OCR for screenshots / scanned text.

Optimization features:
  - Multi-pass decoding with different image preprocessing
  - Automatic contrast/brightness adjustment
  - Grayscale and binarization fallbacks
  - Rotation handling (0/90/180/270 degrees)
  - Multiple QR code detection in single image
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

IMAGE_SUFFIXES = {
    ".png", ".jpg", ".jpeg", ".bmp", ".gif", ".webp",
    ".tif", ".tiff", ".ppm", ".pgm", ".ico",
}


@dataclass
class ExtractedItem:
    """One piece of text recovered from an image."""
    source: str             # "qrcode" | "barcode" | "ocr" | "pdf417" | ...
    text: str
    bbox: tuple[int, int, int, int] | None = None  # x, y, w, h


def is_image_path(p: str | os.PathLike) -> bool:
    return Path(p).suffix.lower() in IMAGE_SUFFIXES


def extract_from_image(path: str | os.PathLike, *, ocr: bool = True) -> list[ExtractedItem]:
    """Extract text from an image file.

    Returns a list of :class:`ExtractedItem`. Empty list means nothing was
    decodable with the available backends.

    `ocr=False` skips OCR entirely (useful when you only care about codes).

    Decoding strategy:
      1. Try original image
      2. Try with contrast enhancement
      3. Try grayscale + binarization
      4. Try rotated versions (90/180/270)
      5. Fall back to OCR if no codes found
    """
    items: list[ExtractedItem] = []
    img = _open_image(path)
    if img is None:
        return items

    # Pass 1: Try original image
    items.extend(_decode_codes(img))
    if items:
        return items

    # Pass 2: Try enhanced contrast
    enhanced = _enhance_contrast(img)
    items.extend(_decode_codes(enhanced))
    if items:
        return items

    # Pass 3: Try grayscale + adaptive threshold
    bw = _to_grayscale_binary(img)
    items.extend(_decode_codes(bw))
    if items:
        return items

    # Pass 4: Try rotated versions
    for angle in [90, 180, 270]:
        rotated = img.rotate(angle, expand=True)
        items.extend(_decode_codes(rotated))
        if items:
            return items
        # Also try enhanced rotated
        rot_enhanced = _enhance_contrast(rotated)
        items.extend(_decode_codes(rot_enhanced))
        if items:
            return items

    # Pass 5: Try OCR as fallback
    if ocr:
        items.extend(_run_ocr(img))

    return items


# ---------------------------------------------------------------
# Image preprocessing helpers
# ---------------------------------------------------------------

def _open_image(path):
    try:
        from PIL import Image
    except ImportError:
        return None
    try:
        return Image.open(path).convert("RGB")
    except Exception:
        return None


def _enhance_contrast(img):
    """Enhance image contrast for better code detection."""
    try:
        from PIL import ImageEnhance, ImageFilter
        # Increase contrast
        enhancer = ImageEnhance.Contrast(img)
        img = enhancer.enhance(2.0)
        # Increase sharpness
        enhancer = ImageEnhance.Sharpness(img)
        img = enhancer.enhance(1.5)
        return img
    except Exception:
        return img


def _to_grayscale_binary(img):
    """Convert to grayscale and apply adaptive thresholding."""
    try:
        from PIL import Image, ImageFilter
        # Convert to grayscale
        gray = img.convert("L")
        # Apply median filter to reduce noise
        gray = gray.filter(ImageFilter.MedianFilter(3))
        # Apply binary threshold
        threshold = 128
        binary = gray.point(lambda x: 255 if x > threshold else 0, '1')
        # Convert back to RGB for pyzbar
        return binary.convert("RGB")
    except Exception:
        return img


def _decode_codes(img) -> list[ExtractedItem]:
    """Decode QR codes and barcodes from image."""
    try:
        from pyzbar.pyzbar import decode as zbar_decode
    except Exception:
        # ImportError, or FileNotFoundError when libzbar shared lib is missing
        return []
    try:
        results = zbar_decode(img)
    except Exception:
        return []
    out: list[ExtractedItem] = []
    for r in results:
        try:
            text = r.data.decode("utf-8", errors="replace")
        except Exception:
            continue
        if not text:
            continue
        kind = (r.type or "code").lower()  # 'qrcode', 'code128', 'ean13', 'pdf417', ...
        rect = (r.rect.left, r.rect.top, r.rect.width, r.rect.height) if r.rect else None
        out.append(ExtractedItem(source=kind, text=text, bbox=rect))
    return out


def _run_ocr(img) -> list[ExtractedItem]:
    """Run OCR on image using Tesseract."""
    try:
        import pytesseract
    except ImportError:
        return []
    try:
        text = pytesseract.image_to_string(img)
    except pytesseract.TesseractNotFoundError:
        return []
    except Exception:
        return []
    text = (text or "").strip()
    if not text:
        return []
    return [ExtractedItem(source="ocr", text=text)]


def backend_status() -> dict[str, bool]:
    """Return which optional backends are usable right now.

    Useful for UI hints ("OCR unavailable — install Tesseract").
    """
    status = {"pillow": False, "pyzbar": False, "pytesseract": False, "tesseract_binary": False}
    try:
        import PIL  # noqa: F401
        status["pillow"] = True
    except ImportError:
        pass
    try:
        import pyzbar.pyzbar  # noqa: F401
        status["pyzbar"] = True
    except Exception:
        pass
    try:
        import pytesseract
        status["pytesseract"] = True
        try:
            pytesseract.get_tesseract_version()
            status["tesseract_binary"] = True
        except Exception:
            pass
    except ImportError:
        pass
    return status
