"""C1 - the contract guard.

Defines the four frozen output fields, the flag vocabulary Part 3 writes reason
codes against, and a lenient input parser. Parsing never raises: anything
malformed is coerced or defaulted and reported through ``missing_fields`` so
``analyze()`` can still return a valid object.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from enum import StrEnum
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

UNKNOWN_ACTION_ID = "unknown"
MAX_ACTION_ID_CHARS = 256
REQUIRED_FIELDS: tuple[str, ...] = (
    "action_id",
    "user_task",
    "proposed_action_description",
    "instruction_content",
)


class Label(StrEnum):
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


class Flag(StrEnum):
    """Frozen vocabulary. Declaration order is the output order."""

    ML_FLAGGED_INJECTION = "ML_FLAGGED_INJECTION"
    LOW_TASK_SIMILARITY = "LOW_TASK_SIMILARITY"
    ACTION_RESEMBLES_UNTRUSTED_SOURCE = "ACTION_RESEMBLES_UNTRUSTED_SOURCE"
    OBFUSCATION_NORMALIZED = "OBFUSCATION_NORMALIZED"
    CONTENT_TRUNCATED = "CONTENT_TRUNCATED"
    INPUT_INCOMPLETE = "INPUT_INCOMPLETE"


_FLAG_ORDER = {flag: i for i, flag in enumerate(Flag)}


def coerce_text(value: Any) -> str:
    """Best-effort conversion of an arbitrary JSON value to text. Never raises; None -> ''."""
    try:
        if value is None:
            return ""
        if isinstance(value, str):
            return value
        if isinstance(value, (bytes, bytearray)):
            return bytes(value).decode("utf-8", errors="replace")
        if isinstance(value, (list, tuple, dict)):
            return json.dumps(value, sort_keys=True, default=str, ensure_ascii=False)
        return str(value)
    except Exception:  # noqa: BLE001 - the guard must never raise
        return ""


class AnalyzeInput(BaseModel):
    """What the orchestrator sends. Unknown keys are ignored, never used for decisions."""

    model_config = ConfigDict(extra="ignore")

    action_id: str = ""
    user_task: str = ""
    proposed_action_description: str = ""
    instruction_content: str = ""

    @field_validator(*REQUIRED_FIELDS, mode="before")
    @classmethod
    def _coerce(cls, value: Any) -> str:
        return coerce_text(value)


def parse_input(raw: Any) -> tuple[AnalyzeInput, tuple[str, ...]]:
    """Parse ``raw`` into an :class:`AnalyzeInput` plus the names of missing/empty required fields."""
    payload: dict[str, Any] = {}
    if isinstance(raw, Mapping):
        payload = {str(k): v for k, v in raw.items() if isinstance(k, str)}
    try:
        parsed = AnalyzeInput.model_validate(payload)
    except Exception:  # noqa: BLE001
        parsed = AnalyzeInput()
    missing = tuple(name for name in REQUIRED_FIELDS if not getattr(parsed, name).strip())
    action_id = parsed.action_id.strip()[:MAX_ACTION_ID_CHARS] or UNKNOWN_ACTION_ID
    return parsed.model_copy(update={"action_id": action_id}), missing


UnitFloat = Annotated[float, Field(ge=0.0, le=1.0)]


class AnalyzeOutput(BaseModel):
    """What Part 3 consumes. The first five fields are frozen; ``details`` is additive only."""

    model_config = ConfigDict(use_enum_values=False)

    action_id: str
    ml_label: Label
    ml_confidence: UnitFloat
    semantic_similarity: UnitFloat
    content_flags: list[Flag] = Field(default_factory=list)
    details: dict[str, Any] = Field(default_factory=dict)

    @field_validator("ml_confidence", "semantic_similarity", mode="after")
    @classmethod
    def _four_decimals(cls, value: float) -> float:
        return round(float(value), 4)

    @field_validator("content_flags", mode="after")
    @classmethod
    def _dedupe_and_order(cls, flags: list[Flag]) -> list[Flag]:
        return sorted(set(flags), key=_FLAG_ORDER.__getitem__)

    def to_dict(self) -> dict[str, Any]:
        """Plain JSON-serialisable dict (enums become their string values)."""
        return self.model_dump(mode="json")


def fallback_output(
    action_id: str = UNKNOWN_ACTION_ID,
    *,
    missing_fields: tuple[str, ...] = (),
    error: str | None = None,
    thresholds_version: str | None = None,
    latency_ms: int | None = None,
) -> AnalyzeOutput:
    """The degraded-but-valid answer: benign, zero confidence, INPUT_INCOMPLETE.

    NOTE: this fails *open* for this module by contract. Part 3 must treat
    INPUT_INCOMPLETE as "no ML evidence available", not as "content is safe".
    """
    details: dict[str, Any] = {"degraded": error is not None, "missing_fields": list(missing_fields)}
    if error is not None:
        details["error"] = error[:300]
    if thresholds_version is not None:
        details["thresholds_version"] = thresholds_version
    if latency_ms is not None:
        details["latency_ms"] = latency_ms
    return AnalyzeOutput(
        action_id=action_id,
        ml_label=Label.BENIGN,
        ml_confidence=0.0,
        semantic_similarity=0.0,
        content_flags=[Flag.INPUT_INCOMPLETE],
        details=details,
    )