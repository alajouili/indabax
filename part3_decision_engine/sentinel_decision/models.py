from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class TrustLevel(str, Enum):
    TRUSTED_INTERNAL = "TRUSTED_INTERNAL"
    TRUSTED_USER = "TRUSTED_USER"
    UNTRUSTED_EXTERNAL = "UNTRUSTED_EXTERNAL"
    UNKNOWN = "UNKNOWN"


class Outcome(str, Enum):
    ALLOW = "ALLOW"
    REWRITE = "REWRITE"
    ESCALATE = "ESCALATE"
    BLOCK = "BLOCK"


class HumanResponse(str, Enum):
    NOT_REQUIRED = "NOT_REQUIRED"
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    DENIED = "DENIED"
    TIMEOUT = "TIMEOUT"


class ActionLifecycle(str, Enum):
    PROPOSED = "PROPOSED"
    REWRITE_REQUIRED = "REWRITE_REQUIRED"
    ESCALATED = "ESCALATED"
    APPROVED = "APPROVED"
    DENIED = "DENIED"
    BLOCKED = "BLOCKED"
    EXECUTED = "EXECUTED"
    FAILED = "FAILED"


class Action(BaseModel):
    model_config = ConfigDict(extra="allow")

    tool: str = Field(min_length=1)
    params: dict[str, Any] = Field(default_factory=dict)


class Part1Signals(BaseModel):
    model_config = ConfigDict(extra="ignore")

    action_id: str
    trust_level: TrustLevel = TrustLevel.UNKNOWN
    permission_ok: bool = False
    structural_flags: list[str] = Field(default_factory=list)

    @field_validator("structural_flags", mode="before")
    @classmethod
    def _list_flags(cls, value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, str):
            return [value]
        return list(value)


class Part2Signals(BaseModel):
    model_config = ConfigDict(extra="ignore")

    action_id: str
    ml_label: str | None = None
    ml_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    semantic_similarity: float = Field(default=0.0, ge=0.0, le=1.0)
    content_flags: list[str] = Field(default_factory=list)

    @field_validator("content_flags", mode="before")
    @classmethod
    def _list_flags(cls, value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, str):
            return [value]
        return list(value)


class CombinedSignals(BaseModel):
    model_config = ConfigDict(extra="allow")

    action_id: str
    trust_level: TrustLevel = TrustLevel.UNKNOWN
    permission_ok: bool = False
    structural_flags: list[str] = Field(default_factory=list)
    ml_label: str | None = None
    ml_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    semantic_similarity: float = Field(default=0.0, ge=0.0, le=1.0)
    content_flags: list[str] = Field(default_factory=list)
    action: Action | None = None
    proposed_action_description: str | None = None


class ScoreContribution(BaseModel):
    name: str
    points: float
    reason: str


class ScoreResult(BaseModel):
    raw_score: float
    risk_score: int
    contributions: list[ScoreContribution]
    reason_codes: list[str]


class OverrideResult(BaseModel):
    minimum_outcome: Outcome | None = None
    forced_outcome: Outcome | None = None
    reason_codes: list[str] = Field(default_factory=list)
    explanation_fragments: list[str] = Field(default_factory=list)


class HumanCase(BaseModel):
    action_id: str
    risk_score: int
    proposed_outcome: Outcome
    reason_codes: list[str]
    explanation: str
    action: Action | None = None


class RewriteResult(BaseModel):
    original_action: Action | None = None
    rewritten_action: Action | None = None
    requirements: list[str] = Field(default_factory=list)
    requires_reevaluation: bool = True


class Verdict(BaseModel):
    action_id: str
    risk_score: int = Field(ge=0, le=100)
    outcome: Outcome
    human_response: HumanResponse = HumanResponse.NOT_REQUIRED
    executed: bool = False
    reason_codes: list[str] = Field(default_factory=list)
    explanation: str
    policy_version: str
    rewrite: RewriteResult | None = None
    executor_result: Any | None = None


class ParsedProposal(BaseModel):
    combined: CombinedSignals
    raw: dict[str, Any]
