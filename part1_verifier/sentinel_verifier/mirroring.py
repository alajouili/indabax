from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable

from .config import EncodingRules, MirroringRules, ScanRules
from .decode import decode_variants
from .schema import Finding, FindingSeverity
from .textnorm import normalize_text, token_set


@dataclass(frozen=True)
class MirroringResult:
    flags: tuple[str, ...]
    findings: tuple[Finding, ...]
    decoded_variants: int


def _strings(value: Any, ignored: set[str], path: str = "") -> Iterable[tuple[str, str]]:
    if isinstance(value, dict):
        for key in sorted(value, key=str):
            if str(key) in ignored:
                continue
            child = f"{path}.{key}" if path else str(key)
            yield from _strings(value[key], ignored, child)
    elif isinstance(value, list):
        for i, item in enumerate(value):
            yield from _strings(item, ignored, f"{path}[{i}]")
    elif isinstance(value, str):
        yield path, value


def _matches_any(text: str, patterns: list[str]) -> str | None:
    for pattern in patterns:
        if re.search(pattern, text):
            return pattern
    return None


def _similarity(a: str, b: str, min_overlap: int) -> float:
    ta, tb = token_set(a), token_set(b)
    if len(ta & tb) < min_overlap or not ta or not tb:
        return 0.0
    return len(ta & tb) / len(ta | tb)


def analyze_mirroring(
    source_bundle: Any,
    action: dict[str, Any] | None,
    rules: MirroringRules,
    encoding_rules: EncodingRules,
    scan_rules: ScanRules,
) -> MirroringResult:
    flags: list[str] = []
    findings: list[Finding] = []
    decoded_count = 0
    ignored = set(scan_rules.ignored_field_names)
    source_strings = list(_strings(source_bundle, ignored))[: scan_rules.max_records * 8]

    for path, raw in source_strings:
        raw = raw[: scan_rules.max_field_chars]
        normalized, changed = normalize_text(raw)
        if changed:
            flags.append("OBFUSCATION_NORMALIZED")
        variants = decode_variants(normalized, encoding_rules)
        decoded_count += max(0, len(variants) - 1)
        for variant in variants:
            pat = _matches_any(variant.text, rules.imperative_patterns)
            if pat:
                code = "ENCODED_INSTRUCTION" if variant.path else "INSTRUCTION_MIRRORING"
                flags.append(code)
                findings.append(
                    Finding(
                        code=code,
                        severity=FindingSeverity.HIGH,
                        evidence=(" -> ".join(variant.path) if variant.path else "imperative instruction in content"),
                        location=path,
                    )
                )
                break
            if _matches_any(variant.text, rules.authority_patterns):
                flags.append("AUTHORITY_CLAIM")
                findings.append(Finding(code="AUTHORITY_CLAIM", severity=FindingSeverity.MEDIUM, evidence="authority claim in content", location=path))
                break

    # Cross-record reassembly: consecutive fragments can reconstruct an imperative instruction.
    texts = [normalize_text(t[: scan_rules.max_field_chars])[0] for _, t in source_strings]
    window = min(rules.fragment_join_window, len(texts))
    for size in range(2, window + 1):
        for start in range(0, len(texts) - size + 1):
            pieces = texts[start : start + size]
            joined_space = " ".join(pieces)
            joined_compact = "".join(pieces)

            # Flag only when at least one configured pattern appears after
            # reassembly but not in any individual fragment. This avoids
            # relabeling an already-complete instruction as fragmented.
            spans_boundary = False
            for pattern in rules.imperative_patterns:
                joined_match = re.search(pattern, joined_space) or re.search(pattern, joined_compact)
                individual_match = any(re.search(pattern, piece) for piece in pieces)
                if joined_match and not individual_match:
                    spans_boundary = True
                    break

            if spans_boundary:
                flags.append("FRAGMENTED_INSTRUCTION")
                findings.append(Finding(code="FRAGMENTED_INSTRUCTION", severity=FindingSeverity.HIGH, evidence=f"reassembled {size} adjacent fragments", location="records"))
                break
        if "FRAGMENTED_INSTRUCTION" in flags:
            break

    # Proposed action description substantially mirrors source content.
    if action:
        action_text = str(action.get("description") or action.get("instruction") or action.get("tool") or "")
        if action_text:
            for path, text in source_strings:
                sim = _similarity(action_text, text, rules.min_overlap_tokens)
                if sim >= rules.similarity_threshold:
                    flags.append("INSTRUCTION_MIRRORING")
                    findings.append(Finding(code="INSTRUCTION_MIRRORING", severity=FindingSeverity.MEDIUM, evidence=f"token_jaccard={sim:.3f}", location=path))
                    break

    return MirroringResult(
        tuple(sorted(set(flags))),
        tuple(sorted(findings, key=lambda f: (f.code, f.location, f.evidence))),
        decoded_count,
    )
