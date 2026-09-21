from __future__ import annotations

from typing import Any

from .models import Action, CombinedSignals, ParsedProposal, TrustLevel


def describe_action(action: Action | None) -> str:
    """Stable text representation used when an action description is needed."""
    if action is None:
        return ""
    parts = [action.tool]
    for key in sorted(action.params):
        value = action.params[key]
        if isinstance(value, (str, int, float, bool)) or value is None:
            parts.extend([str(key), str(value)])
        else:
            parts.extend([str(key), repr(value)])
    return " ".join(parts)


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _flags(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple, set)):
        return [str(v) for v in value]
    return [str(value)]


def _unit_float(value: Any, default: float = 0.0) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    return max(0.0, min(1.0, number))


def parse_proposal(raw: dict[str, Any]) -> ParsedProposal:
    """Parse flat or nested Part 1/Part 2 outputs into one stable contract.

    Missing security evidence fails conservatively: unknown trust, permission=False,
    and INPUT_INCOMPLETE when the Part 2 core fields are unavailable.
    """
    if not isinstance(raw, dict):
        raw = {}

    p1 = _as_dict(raw.get("part1")) or raw
    p2 = _as_dict(raw.get("part2")) or raw

    id1 = p1.get("action_id")
    id2 = p2.get("action_id")
    top_id = raw.get("action_id")

    known_ids = [str(x) for x in (top_id, id1, id2) if x not in (None, "")]
    if len(set(known_ids)) > 1:
        raise ValueError(f"Part 1 / Part 2 action_id mismatch: {known_ids}")
    action_id = known_ids[0] if known_ids else "UNKNOWN_ACTION"

    structural_flags = _flags(p1.get("structural_flags"))
    content_flags = _flags(p2.get("content_flags"))

    part1_core_present = all(k in p1 for k in ("trust_level", "permission_ok"))
    part2_core_present = all(k in p2 for k in ("ml_confidence", "semantic_similarity"))

    if not part1_core_present and "PART1_INPUT_INCOMPLETE" not in structural_flags:
        structural_flags.append("PART1_INPUT_INCOMPLETE")
    if not part2_core_present and "INPUT_INCOMPLETE" not in content_flags:
        content_flags.append("INPUT_INCOMPLETE")

    trust_raw = str(p1.get("trust_level", TrustLevel.UNKNOWN.value))
    try:
        trust = TrustLevel(trust_raw)
    except ValueError:
        trust = TrustLevel.UNKNOWN
        structural_flags.append("UNKNOWN_TRUST_LEVEL")

    action_raw = raw.get("action") or raw.get("proposed_action")
    action = None
    if isinstance(action_raw, dict) and action_raw.get("tool"):
        action = Action.model_validate(action_raw)

    description = raw.get("proposed_action_description")
    if not description and action is not None:
        description = describe_action(action)

    combined = CombinedSignals(
        action_id=action_id,
        trust_level=trust,
        permission_ok=bool(p1.get("permission_ok", False)),
        structural_flags=sorted(set(structural_flags)),
        ml_label=p2.get("ml_label"),
        ml_confidence=_unit_float(p2.get("ml_confidence"), 0.0),
        semantic_similarity=_unit_float(p2.get("semantic_similarity"), 0.0),
        content_flags=sorted(set(content_flags)),
        action=action,
        proposed_action_description=str(description) if description else None,
    )
    return ParsedProposal(combined=combined, raw=raw)
