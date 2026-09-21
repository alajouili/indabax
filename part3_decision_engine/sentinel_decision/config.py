from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from .models import Outcome


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ScoreWeights(StrictModel):
    permission_denied: float = Field(ge=0)
    ml_confidence: float = Field(ge=0)
    semantic_drift: float = Field(ge=0)
    action_impact: float = Field(ge=0)
    session_history: float = Field(ge=0)


class Caps(StrictModel):
    structural_flags: float = Field(ge=0)
    content_flags: float = Field(ge=0)
    total: float = Field(default=100.0, gt=0)


class SimilarityPolicy(StrictModel):
    safe_similarity: float = Field(ge=0, le=1)
    critical_similarity: float = Field(ge=0, le=1)

    @model_validator(mode="after")
    def _order(self):
        if self.critical_similarity > self.safe_similarity:
            raise ValueError("critical_similarity must be <= safe_similarity")
        return self


class Thresholds(StrictModel):
    rewrite: int = Field(ge=0, le=100)
    escalate: int = Field(ge=0, le=100)
    block: int = Field(ge=0, le=100)

    @model_validator(mode="after")
    def _ordered(self):
        if not (self.rewrite < self.escalate < self.block):
            raise ValueError("thresholds must satisfy rewrite < escalate < block")
        return self


class OverridePolicy(StrictModel):
    permission_denied_minimum: Outcome
    input_incomplete_minimum: Outcome
    critical_structural_flags: dict[str, Outcome] = Field(default_factory=dict)
    critical_content_flags: dict[str, Outcome] = Field(default_factory=dict)
    high_ml_confidence: float = Field(ge=0, le=1)
    high_ml_with_untrusted_minimum: Outcome
    very_low_similarity_minimum: Outcome


class RewritePolicy(StrictModel):
    enabled: bool = True
    redact_param_keys: list[str] = Field(default_factory=list)
    external_recipient_keys: list[str] = Field(default_factory=list)
    safe_placeholder: str = "[REDACTED_BY_SENTINEL]"
    requirements: list[str] = Field(default_factory=list)


class HumanPolicy(StrictModel):
    default_mode: str = "cli"
    timeout_seconds: int = Field(default=60, ge=1)
    timeout_response: str = "DENIED"


class LoggingPolicy(StrictModel):
    path: str = "logs/trace.jsonl"
    hash_chain: bool = True

    redact_param_keys: list[str] = Field(
        default_factory=lambda: [
            "password",
            "token",
            "secret",
            "api_key",
            "credential",
        ]
    )

    safe_placeholder: str = "[REDACTED_BY_SENTINEL]"


class StatePolicy(StrictModel):
    max_history: int = Field(default=100, ge=1)
    suspicious_event_points: float = Field(default=5.0, ge=0)
    max_session_points: float = Field(default=15.0, ge=0)


class ActionCategory(StrictModel):
    tools: list[str] = Field(default_factory=list)
    impact: int = Field(default=0, ge=0, le=100)


class Policy(StrictModel):
    version: str
    weights: ScoreWeights
    trust_points: dict[str, float]
    structural_flag_points: dict[str, float]
    content_flag_points: dict[str, float]
    caps: Caps
    similarity: SimilarityPolicy
    thresholds: Thresholds
    overrides: OverridePolicy
    rewrite: RewritePolicy
    human: HumanPolicy
    logging: LoggingPolicy
    state: StatePolicy
    categories: dict[str, ActionCategory] = Field(default_factory=dict)


DEFAULT_POLICY = Path(__file__).resolve().parent.parent / "config" / "policy.yaml"


def load_policy(path: str | Path | None = None) -> Policy:
    target = Path(path) if path else DEFAULT_POLICY
    data: Any = yaml.safe_load(target.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"policy file must contain a mapping: {target}")
    return Policy.model_validate(data)
