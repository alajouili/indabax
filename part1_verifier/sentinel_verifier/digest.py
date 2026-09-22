from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )


def action_digest(action: dict[str, Any] | None) -> str:
    """Deterministic SHA-256 digest of the proposed action only.

    The action_id/scenario id is deliberately excluded so it cannot influence
    verification. If a starter kit supplies a canonical digest fixture, compare
    this function against that fixture in test_kit_compat.py.
    """
    payload = canonical_json(action or {})
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def canonical_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (dict, list, tuple)):
        return canonical_json(value)
    return str(value)
