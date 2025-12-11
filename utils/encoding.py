#!/usr/bin/env python3
"""
Utilities for robust text file reading with encoding fallbacks.

Goal: avoid crashes like "'utf-8' codec can't decode byte 0xA0" when scanning
XML files that were saved with legacy encodings (e.g., Windows-1252) or contain
non-breaking spaces.
"""

from typing import Optional, Tuple


def _detect_encoding(data: bytes) -> Optional[str]:
    """Detect encoding using chardet if available; else None."""
    try:
        import chardet  # type: ignore
    except Exception:
        return None

    result = chardet.detect(data)
    enc = result.get("encoding") if isinstance(result, dict) else None
    if enc:
        # Normalize common labels
        enc_lower = enc.lower()
        if enc_lower in {"utf_8", "utf8"}:
            return "utf-8"
        return enc
    return None


def read_text_safely(
    file_path: str,
    prefer: Tuple[str, ...] = ("utf-8", "utf-8-sig"),
    fallbacks: Tuple[str, ...] = ("cp1252", "latin-1"),
    normalize_nbsp: bool = True,
) -> str:
    """
    Read a text file robustly with encoding auto-detection and fallbacks.

    Order:
    1) Try preferred encodings
    2) Try chardet detection if available
    3) Try fallbacks

    Also optionally normalizes non-breaking spaces (U+00A0) to regular spaces
    to reduce XML parse issues.
    """
    # Try preferred encodings first
    for enc in prefer:
        try:
            with open(file_path, "r", encoding=enc) as f:
                text = f.read()
            return text.replace("\u00A0", " ") if normalize_nbsp else text
        except UnicodeDecodeError:
            pass

    # Try detection on raw bytes
    try:
        with open(file_path, "rb") as f:
            data = f.read()
    except Exception:
        # If even bytes read fails, re-raise
        raise

    detected = _detect_encoding(data)
    if detected:
        try:
            text = data.decode(detected)
            return text.replace("\u00A0", " ") if normalize_nbsp else text
        except UnicodeDecodeError:
            pass

    # Try fallbacks
    for enc in fallbacks:
        try:
            with open(file_path, "r", encoding=enc, errors="strict") as f:
                text = f.read()
            return text.replace("\u00A0", " ") if normalize_nbsp else text
        except UnicodeDecodeError:
            continue

    # Last resort: decode as latin-1 with replacement to avoid crash
    with open(file_path, "r", encoding="latin-1", errors="replace") as f:
        text = f.read()
    return text.replace("\u00A0", " ") if normalize_nbsp else text
