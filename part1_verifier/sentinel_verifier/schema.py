from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class TrustLevel(StrEnum):
    TRUSTED_USER = "TRUSTED_USER"
    TRUSTED_INTERNAL = "TRUSTED_INTERNAL"
    INTERNAL = "INTERNAL"
    UNTRUSTED_EXTERNAL = "UNTRUSTED_EXTERNAL"
    UNKNOWN = "UNKNOWN"


class Sensitivity(StrEnum):
    NONE = "NONE"
    POSSIBLE_SECRET = "POSSIBLE_SECRET"
    SECRET = "SECRET"


class FindingSeverity(StrEnum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


FLAG_VOCABULARY = frozenset(
    {
        "SENSITIVE_DATA_PROPAGATION",
        "DESTRUCTIVE_ACTION_REQUEST",
        "UNTRUSTED_MEMORY_POLICY_WRITE",
        "INPUT_INCOMPLETE",
        "MALFORMED_INPUT",
        "UNTRUSTED_SOURCE",
        "UNKNOWN_SOURCE",
        "TOOL_NOT_ALLOWED",
        "MISSING_PREREQUISITE",
        "CONFIRMATION_REQUIRED",
        "ENCODED_INSTRUCTION",
        "FRAGMENTED_INSTRUCTION",
        "INSTRUCTION_MIRRORING",
        "SECRET_SHAPE_DETECTED",
        "SECRET_TO_EXTERNAL_SINK",
        "EXTERNAL_RECIPIENT",
        "CONSEQUENTIAL_ACTION",
        "CONTROL_CHANGE",
        "MEMORY_WRITE",
        "AUTHORITY_CLAIM",
        "OBFUSCATION_NORMALIZED",
    }
)


class DefenseRequestView(BaseModel):
    """Lenient view over a challenge/starter-kit request.

    Unknown fields are preserved so Part 1 can operate across small schema changes.
    """

    model_config = ConfigDict(extra="allow")

    action_id: str = "UNKNOWN_ACTION"
    proposed_action: dict[str, Any] | None = None
    instruction_source: dict[str, Any] | None = None
    agent_role: str | None = None
    user_task: str | None = None
    records: list[dict[str, Any]] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    confirmed: bool | None = None


class Finding(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    code: str
    severity: FindingSeverity
    evidence: str = ""
    location: str = ""


class VerifierDetails(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    action_digest: str = ""
    decoded_variants: int = 0
    influence_sources: tuple[str, ...] = ()
    scan_truncated: bool = False
    rules_version: str = "unknown"


class VerifierResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    action_id: str
    trust_level: TrustLevel
    trust_basis: tuple[str, ...]
    permission_ok: bool | None
    structural_flags: tuple[str, ...]
    findings: tuple[Finding, ...]
    sensitivity: Sensitivity
    details: VerifierDetails


def fail_closed_result(action_id: str = "UNKNOWN_ACTION", reason: str = "malformed input") -> VerifierResult:
    finding = Finding(
        code="MALFORMED_INPUT",
        severity=FindingSeverity.CRITICAL,
        evidence=reason[:240],
        location="request",
    )
    return VerifierResult(
        action_id=action_id or "UNKNOWN_ACTION",
        trust_level=TrustLevel.UNKNOWN,
        trust_basis=("FAIL_CLOSED",),
        permission_ok=False,
        structural_flags=("INPUT_INCOMPLETE", "MALFORMED_INPUT"),
        findings=(finding,),
        sensitivity=Sensitivity.NONE,
        details=VerifierDetails(),
    )
