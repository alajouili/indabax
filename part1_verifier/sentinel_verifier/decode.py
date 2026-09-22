from __future__ import annotations

import base64
import binascii
import codecs
import re
import string
from dataclasses import dataclass
from urllib.parse import unquote

from .config import EncodingRules
from .textnorm import normalize_text


@dataclass(frozen=True)
class DecodedVariant:
    text: str
    path: tuple[str, ...]

    @property
    def depth(self) -> int:
        return len(self.path)


_HEX = re.compile(r"^[0-9A-Fa-f]+$")
_B64 = re.compile(r"^[A-Za-z0-9+/=_-]+$")
_URL = re.compile(r"%[0-9A-Fa-f]{2}")


def _printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    printable = sum(ch in string.printable or ch.isprintable() for ch in text)
    return printable / len(text)


def _accept(text: str, rules: EncodingRules) -> str | None:
    if not text or len(text) > rules.max_decoded_chars:
        return None
    normalized, _ = normalize_text(text)
    if len(normalized) < rules.min_candidate_chars:
        return None
    if _printable_ratio(normalized) < rules.min_printable_ratio:
        return None
    return normalized


def _decode_once(text: str, rules: EncodingRules) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    enabled = set(rules.enabled)

    if "url" in enabled and _URL.search(text):
        decoded = unquote(text)
        if decoded != text and (accepted := _accept(decoded, rules)):
            out.append(("url", accepted))

    compact = re.sub(r"\s+", "", text)
    if "base64" in enabled and len(compact) >= rules.min_candidate_chars and _B64.fullmatch(compact):
        try:
            padded = compact + "=" * ((4 - len(compact) % 4) % 4)
            decoded = base64.b64decode(padded, altchars=b"-_", validate=True).decode("utf-8")
            if (accepted := _accept(decoded, rules)) and accepted != text:
                out.append(("base64", accepted))
        except (binascii.Error, UnicodeDecodeError, ValueError):
            pass

    if "hex" in enabled and len(compact) >= rules.min_candidate_chars and len(compact) % 2 == 0 and _HEX.fullmatch(compact):
        try:
            decoded = bytes.fromhex(compact).decode("utf-8")
            if (accepted := _accept(decoded, rules)) and accepted != text:
                out.append(("hex", accepted))
        except (ValueError, UnicodeDecodeError):
            pass

    if "rot13" in enabled and len(text) >= rules.min_candidate_chars:
        decoded = codecs.decode(text, "rot_13")
        if decoded != text and (accepted := _accept(decoded, rules)):
            out.append(("rot13", accepted))

    if "reversed" in enabled and len(text) >= rules.min_candidate_chars:
        decoded = text[::-1]
        if decoded != text and (accepted := _accept(decoded, rules)):
            out.append(("reversed", accepted))

    # deterministic de-duplication
    seen: set[tuple[str, str]] = set()
    unique: list[tuple[str, str]] = []
    for item in out:
        if item not in seen:
            seen.add(item)
            unique.append(item)
    return unique


def decode_variants(text: str, rules: EncodingRules) -> list[DecodedVariant]:
    normalized, _ = normalize_text(text)
    root = DecodedVariant(normalized, ())
    results: list[DecodedVariant] = [root]
    frontier = [root]
    seen_text = {normalized}

    for _ in range(rules.max_depth):
        next_frontier: list[DecodedVariant] = []
        for variant in frontier:
            for method, decoded in _decode_once(variant.text, rules):
                if decoded in seen_text:
                    continue
                seen_text.add(decoded)
                child = DecodedVariant(decoded, variant.path + (method,))
                results.append(child)
                next_frontier.append(child)
        frontier = next_frontier
        if not frontier:
            break

    return results
