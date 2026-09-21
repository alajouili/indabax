"""C2 - text normalizer.

De-obfuscates text so the classifier reads what a human would read: invisible
and bidi control characters are removed, compatibility characters (full-width
letters, ligatures) are folded with NFKC, and letters spread out with single
spaces ("i g n o r e") are re-joined.

Case is preserved on purpose: the classifier sees the original casing.
Lowercasing, if ever needed, is a comparison-time concern of the caller.

Pure and deterministic. It records *what* it changed so the trace can say so.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

ZERO_WIDTH_STRIPPED = "ZERO_WIDTH_STRIPPED"
BIDI_CONTROL_STRIPPED = "BIDI_CONTROL_STRIPPED"
UNICODE_NFKC_APPLIED = "UNICODE_NFKC_APPLIED"
SPACED_LETTERS_COLLAPSED = "SPACED_LETTERS_COLLAPSED"

# Bidirectional formatting controls (Trojan-Source style reordering).
_BIDI = frozenset({0x061C, 0x200E, 0x200F, *range(0x202A, 0x202F), *range(0x2066, 0x206A)})

# Invisible characters an adversary can splice between letters. Includes Unicode
# "tag" characters and variation selectors, which are used to smuggle hidden text.
_ZERO_WIDTH = frozenset(
    {
        0x00AD,  # soft hyphen
        0x180E,  # Mongolian vowel separator
        0x200B,  # zero width space
        0x200C,  # zero width non-joiner
        0x200D,  # zero width joiner
        0x2060,  # word joiner
        0x2061, 0x2062, 0x2063, 0x2064,  # invisible math operators
        0xFEFF,  # zero width no-break space / BOM
        *range(0xFE00, 0xFE10),  # variation selectors
        *range(0xE0000, 0xE0080),  # tag characters
        *range(0xE0100, 0xE01F0),  # variation selectors supplement
    }
)

_KEEP_CONTROLS = frozenset({"\t", "\n", "\r"})
_INLINE_SPACE = re.compile(r"[^\S\n]+")
_BLANK_LINES = re.compile(r"\n{3,}")


@dataclass(frozen=True)
class NormalizationResult:
    text: str
    applied: tuple[str, ...]

    @property
    def changed_meaning(self) -> bool:
        """True if something an adversary could have used to hide text was undone."""
        return bool(self.applied)


def _strip_invisible(text: str) -> tuple[str, bool, bool]:
    """Remove bidi controls, zero-width chars and stray control characters."""
    kept: list[str] = []
    saw_bidi = saw_invisible = False
    for ch in text:
        code = ord(ch)
        if code in _BIDI:
            saw_bidi = True
        elif code in _ZERO_WIDTH or (unicodedata.category(ch) == "Cc" and ch not in _KEEP_CONTROLS):
            saw_invisible = True
        else:
            kept.append(ch)
    return "".join(kept), saw_bidi, saw_invisible


def _has_letter_compat_rewrite(text: str) -> bool:
    """True if NFKC rewrites a letter/digit into another letter/digit (e.g. full-width 'ｉ' -> 'i').

    Typographic rewrites such as '…', non-breaking spaces or '™' are ignored so
    ordinary email text does not look like obfuscation.
    """
    for ch in set(text):
        if ord(ch) < 128 or not ch.isalnum():
            continue
        folded = unicodedata.normalize("NFKC", ch)
        if folded != ch and any(c.isalnum() for c in folded):
            return True
    return False


def _spaced_letters_pattern(min_run: int) -> re.Pattern[str]:
    letter = r"[^\W\d_]"
    return re.compile(rf"(?<!\w){letter}(?: {letter}){{{min_run - 1},}}(?!\w)")


_PATTERN_CACHE: dict[int, re.Pattern[str]] = {}


def normalize(text: str, *, spaced_letters_min_run: int = 4) -> NormalizationResult:
    """Return the cleaned text and the list of obfuscation techniques that were undone."""
    applied: list[str] = []

    text, saw_bidi, saw_invisible = _strip_invisible(text)
    if saw_invisible:
        applied.append(ZERO_WIDTH_STRIPPED)
    if saw_bidi:
        applied.append(BIDI_CONTROL_STRIPPED)

    if _has_letter_compat_rewrite(text):
        applied.append(UNICODE_NFKC_APPLIED)
    text = unicodedata.normalize("NFKC", text)

    pattern = _PATTERN_CACHE.setdefault(spaced_letters_min_run, _spaced_letters_pattern(spaced_letters_min_run))
    text, n_collapsed = pattern.subn(lambda m: m.group(0).replace(" ", ""), text)
    if n_collapsed:
        applied.append(SPACED_LETTERS_COLLAPSED)

    # Layout-only cleanup: not obfuscation, so it is not recorded.
    text = _INLINE_SPACE.sub(" ", text)
    text = _BLANK_LINES.sub("\n\n", text).strip()
    return NormalizationResult(text=text, applied=tuple(applied))


def merge_applied(*results: NormalizationResult) -> tuple[str, ...]:
    """Ordered union of the techniques recorded across several normalized strings."""
    seen: dict[str, None] = {}
    for result in results:
        for code in result.applied:
            seen.setdefault(code, None)
    return tuple(seen)