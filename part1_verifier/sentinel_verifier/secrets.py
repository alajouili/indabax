from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable

from .config import SecretRules
from .schema import Finding, FindingSeverity, Sensitivity


@dataclass(frozen=True)
class SecretHit:
    value: str
    name: str
    location: str


@dataclass(frozen=True)
class SecretScanResult:
    hits: tuple[SecretHit, ...]
    findings: tuple[Finding, ...]
    sensitivity: Sensitivity


def _walk(value: Any, path: str = "") -> Iterable[tuple[str, Any]]:
    if isinstance(value, dict):
        for key in sorted(value, key=str):
            child = f"{path}.{key}" if path else str(key)
            yield child, value[key]
            yield from _walk(value[key], child)
    elif isinstance(value, list):
        for i, item in enumerate(value):
            child = f"{path}[{i}]"
            yield child, item
            yield from _walk(item, child)


def scan_secrets(value: Any, rules: SecretRules) -> SecretScanResult:
    hits: list[SecretHit] = []
    findings: list[Finding] = []
    key_regexes = [re.compile(p) for p in rules.key_name_patterns]
    value_patterns = [(p.name, re.compile(p.regex)) for p in rules.value_patterns]

    for path, item in _walk(value):
        key = path.rsplit(".", 1)[-1].split("[", 1)[0]
        if any(rx.search(key) for rx in key_regexes) and isinstance(item, (str, int, float)):
            text = str(item)
            if len(text) >= 8:
                hits.append(SecretHit(text, "secret_key_name", path))

        if isinstance(item, str):
            for name, rx in value_patterns:
                for match in rx.finditer(item):
                    matched = match.group(0)
                    hits.append(SecretHit(matched, name, path))

    dedup: dict[tuple[str, str, str], SecretHit] = {(h.value, h.name, h.location): h for h in hits}
    hits = sorted(dedup.values(), key=lambda h: (h.location, h.name, h.value))
    for hit in hits:
        findings.append(
            Finding(
                code="SECRET_SHAPE_DETECTED",
                severity=FindingSeverity.HIGH,
                evidence=hit.name,
                location=hit.location,
            )
        )

    sensitivity = Sensitivity.SECRET if hits else Sensitivity.NONE
    return SecretScanResult(tuple(hits), tuple(findings), sensitivity)
