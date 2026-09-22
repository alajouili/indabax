from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class TrustRules(StrictModel):
    default: str = "UNKNOWN"
    default_by_type: dict[str, str] = Field(default_factory=dict)
    internal_domains: list[str] = Field(default_factory=list)
    trusted_senders: list[str] = Field(default_factory=list)
    explicitly_untrusted_types: list[str] = Field(default_factory=list)
    external_level: str = "UNTRUSTED_EXTERNAL"
    internal_level: str = "INTERNAL"


class RolePermissionRules(StrictModel):
    allowed_tools: list[str] = Field(default_factory=list)
    prerequisites: dict[str, list[str]] = Field(default_factory=dict)
    confirmation_required: list[str] = Field(default_factory=list)


class PermissionRules(StrictModel):
    unknown_role_policy: Literal["unknown", "deny"] = "unknown"
    roles: dict[str, RolePermissionRules] = Field(default_factory=dict)


class ScanRules(StrictModel):
    max_text_chars: int = 50000
    max_records: int = 64
    max_field_chars: int = 12000
    ignored_field_names: list[str] = Field(default_factory=list)


class NormalizationRules(StrictModel):
    strip_zero_width: bool = True
    collapse_whitespace: bool = True
    strip_separators_for_fold: bool = True


class EncodingRules(StrictModel):
    enabled: list[str] = Field(default_factory=list)
    max_depth: int = 2
    min_printable_ratio: float = 0.8
    min_candidate_chars: int = 8
    max_decoded_chars: int = 12000


class SecretPattern(StrictModel):
    name: str
    regex: str


class SecretRules(StrictModel):
    key_name_patterns: list[str] = Field(default_factory=list)
    value_patterns: list[SecretPattern] = Field(default_factory=list)


class SinkRules(StrictModel):
    external_tools: list[str] = Field(default_factory=list)
    internal_domains: list[str] = Field(default_factory=list)
    recipient_keys: list[str] = Field(default_factory=list)


class MirroringRules(StrictModel):
    imperative_patterns: list[str] = Field(default_factory=list)
    authority_patterns: list[str] = Field(default_factory=list)
    similarity_threshold: float = 0.72
    min_overlap_tokens: int = 4
    fragment_join_window: int = 8


class ActionShapeRules(StrictModel):
    consequential_tools: list[str] = Field(default_factory=list)
    control_change_tools: list[str] = Field(default_factory=list)
    memory_write_tools: list[str] = Field(default_factory=list)
    recipient_keys: list[str] = Field(default_factory=list)


class Rules(StrictModel):
    version: str
    trust: TrustRules
    permissions: PermissionRules
    scan: ScanRules
    normalization: NormalizationRules
    encoding: EncodingRules
    secrets: SecretRules
    sinks: SinkRules
    mirroring: MirroringRules
    action_shape: ActionShapeRules


DEFAULT_RULES_PATH = Path(__file__).resolve().parents[1] / "config" / "rules.yaml"


def load_rules(path: str | Path | None = None) -> Rules:
    selected = Path(path) if path else DEFAULT_RULES_PATH
    raw = yaml.safe_load(selected.read_text(encoding="utf-8"))
    return Rules.model_validate(raw)
