from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .config import TrustRules
from .schema import TrustLevel


@dataclass(frozen=True)
class ProvenanceResult:
    trust_level: TrustLevel
    trust_basis: tuple[str, ...]
    influence_sources: tuple[str, ...]


def _domain(value: str) -> str:
    value = value.strip().lower()
    if "@" in value:
        return value.rsplit("@", 1)[1]
    if "://" in value:
        host = value.split("://", 1)[1].split("/", 1)[0]
        return host.split(":", 1)[0]
    return value


def _to_level(value: str) -> TrustLevel:
    try:
        return TrustLevel(value)
    except Exception:
        return TrustLevel.UNKNOWN


def resolve_provenance(source: dict[str, Any] | None, records: list[dict[str, Any]], rules: TrustRules) -> ProvenanceResult:
    source = source or {}
    stype = str(source.get("type", "unknown")).lower()
    sender = str(source.get("sender") or source.get("author") or source.get("url") or "").strip()
    basis: list[str] = [f"SOURCE_TYPE:{stype.upper()}"]
    influence: list[str] = []

    if sender:
        influence.append(f"{stype}:{sender}")

    if stype in {t.lower() for t in rules.explicitly_untrusted_types}:
        level = _to_level(rules.external_level)
        basis.append("EXPLICITLY_UNTRUSTED_TYPE")
    elif sender and sender.lower() in {x.lower() for x in rules.trusted_senders}:
        level = TrustLevel.TRUSTED_INTERNAL
        basis.append("TRUSTED_SENDER")
    elif sender and _domain(sender) in {d.lower() for d in rules.internal_domains}:
        level = _to_level(rules.internal_level)
        basis.append("INTERNAL_DOMAIN")
    elif stype == "email" and sender:
        level = _to_level(rules.external_level)
        basis.append("EXTERNAL_SENDER")
    else:
        level = _to_level(rules.default_by_type.get(stype, rules.default))
        basis.append("TYPE_DEFAULT")

    for record in records:
        rtype = str(record.get("type", "record"))
        origin = str(record.get("sender") or record.get("author") or record.get("url") or record.get("id") or "")
        if origin:
            influence.append(f"{rtype}:{origin}")

    return ProvenanceResult(level, tuple(sorted(set(basis))), tuple(sorted(set(influence))))
