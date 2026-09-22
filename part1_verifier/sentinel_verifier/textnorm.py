from __future__ import annotations

import re
import unicodedata

_ZERO_WIDTH = re.compile(r"[\u200B-\u200D\u2060\uFEFF]")
_WS = re.compile(r"\s+")
_SEPARATORS = re.compile(r"[^\w]+", flags=re.UNICODE)


def normalize_text(text: str, *, collapse_whitespace: bool = True) -> tuple[str, bool]:
    original = text
    text = unicodedata.normalize("NFKC", text)
    text = _ZERO_WIDTH.sub("", text)
    if collapse_whitespace:
        text = _WS.sub(" ", text).strip()
    return text, text != original


def strip_separators(text: str) -> str:
    return _SEPARATORS.sub("", text)


def alnum_fold(text: str) -> str:
    normalized, _ = normalize_text(text)
    return "".join(ch.lower() for ch in normalized if ch.isalnum())


def token_set(text: str) -> set[str]:
    normalized, _ = normalize_text(text)
    return {t.lower() for t in re.findall(r"[A-Za-z0-9_]{2,}", normalized)}
