"""Typed loader for ``config/thresholds.yaml``.

Single source of truth for every tunable number. Unknown keys are rejected so a
typo in the YAML fails at load time instead of silently falling back to a
default. Cross-field invariants (e.g. overlap < window) are checked here so the
rest of the code can trust the values.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Annotated

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

MODULE_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG_PATH = MODULE_ROOT / "config" / "thresholds.yaml"
CONFIG_ENV_VAR = "SENTINEL_ML_THRESHOLDS"

Unit = Annotated[float, Field(ge=0.0, le=1.0)]
PositiveInt = Annotated[int, Field(ge=1)]


class ConfigError(RuntimeError):
    """Raised when the thresholds file is missing, unreadable, or invalid."""


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ClassifierModelConfig(_Strict):
    id: str
    revision: str | None = None
    injection_label: str
    max_length: Annotated[int, Field(ge=32, le=512)] = 512
    batch_size: PositiveInt = 8


class EmbedderModelConfig(_Strict):
    id: str
    revision: str | None = None
    batch_size: PositiveInt = 8


class ModelsConfig(_Strict):
    classifier: ClassifierModelConfig
    embedder: EmbedderModelConfig
    hf_home: str = "models/.hf"
    num_threads: PositiveInt = 1


class NormalizationConfig(_Strict):
    spaced_letters_min_run: Annotated[int, Field(ge=3)] = 4


class ChunkingConfig(_Strict):
    enabled: bool = True
    window_words: Annotated[int, Field(ge=8)] = 150
    overlap_words: Annotated[int, Field(ge=0)] = 40
    max_chunks: Annotated[int, Field(ge=2)] = 32
    max_word_chars: Annotated[int, Field(ge=4)] = 32

    @model_validator(mode="after")
    def _overlap_smaller_than_window(self) -> ChunkingConfig:
        if self.overlap_words >= self.window_words:
            raise ValueError("chunking.overlap_words must be smaller than window_words")
        return self


class InjectionConfig(_Strict):
    flag_threshold: Unit


class SimilarityConfig(_Strict):
    drift_threshold: Unit
    authorship_margin: Annotated[float, Field(ge=0.0, le=1.0)]
    authorship_min_injection: Unit


class FusionConfig(_Strict):
    uncorroborated_weight: Unit
    corroboration_weight: Unit
    min_injection_for_corroboration: Unit
    ramp_width: Annotated[float, Field(gt=0.0, le=1.0)]

class LabelsConfig(_Strict):
    suspicious: Unit
    malicious: Unit

    @model_validator(mode="after")
    def _ordered(self) -> LabelsConfig:
        if self.suspicious >= self.malicious:
            raise ValueError("labels.suspicious must be below labels.malicious")
        return self


class EvidenceConfig(_Strict):
    localize_min_score: Unit
    max_sentences: PositiveInt = 24
    min_sentence_words: PositiveInt = 5
    min_sentence_chars: PositiveInt = 30
    context_radius: Annotated[int, Field(ge=0, le=3)] = 1
    max_chars: Annotated[int, Field(ge=40)] = 400

class LatencyConfig(_Strict):
    budget_ms: PositiveInt = 3000


class Config(_Strict):
    version: str
    calibrated: bool = False
    models: ModelsConfig
    normalization: NormalizationConfig
    chunking: ChunkingConfig
    injection: InjectionConfig
    similarity: SimilarityConfig
    fusion: FusionConfig
    labels: LabelsConfig
    evidence: EvidenceConfig
    latency: LatencyConfig

    def hf_home_path(self) -> Path:
        """Absolute HF cache directory (relative values resolve against the module root)."""
        path = Path(self.models.hf_home)
        return path if path.is_absolute() else MODULE_ROOT / path


def load_config(path: str | os.PathLike[str] | None = None) -> Config:
    """Load and validate a thresholds file. ``None`` uses $SENTINEL_ML_THRESHOLDS, then the default."""
    resolved = Path(path or os.environ.get(CONFIG_ENV_VAR) or DEFAULT_CONFIG_PATH)
    try:
        raw = yaml.safe_load(resolved.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError(f"cannot read thresholds file {resolved}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in {resolved}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError(f"{resolved} must contain a YAML mapping at the top level")
    try:
        return Config.model_validate(raw)
    except ValueError as exc:  # pydantic.ValidationError is a ValueError
        raise ConfigError(f"invalid thresholds in {resolved}: {exc}") from exc


@lru_cache(maxsize=1)
def get_config() -> Config:
    """Process-wide config (default path). Tests/ablations pass explicit Config objects instead."""
    return load_config()