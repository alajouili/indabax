"""Singleton loader for the two models, with offline mode enforced.

Loading DeBERTa per request costs seconds, so both models load once per process.
Offline is enforced three ways: the HF offline env vars are set at import time (before
any Hugging Face import), ``local_files_only=True`` is passed to every loader, and the
cache directory is explicit. A missing cache therefore fails fast instead of reaching
for the network mid-demo.
"""

from __future__ import annotations

import os
import threading
from dataclasses import dataclass
from pathlib import Path

from .classifier import InjectionScorer
from .config import Config, get_config
from .embeddings import TextEncoder

# Must run before transformers / huggingface_hub / sentence_transformers are imported.
os.environ["HF_HUB_OFFLINE"] = "1"
os.environ["TRANSFORMERS_OFFLINE"] = "1"


class ModelLoadError(RuntimeError):
    """The models could not be loaded from the local cache."""


@dataclass(frozen=True)
class Models:
    classifier: InjectionScorer
    encoder: TextEncoder
    classifier_version: str
    embedder_version: str


_LOCK = threading.Lock()
_STATE: dict[str, object] = {"models": None, "key": None}


def _version(model_id: str, revision: str | None) -> str:
    return f"{model_id}@{revision or 'unpinned'}"


def hub_cache_dir(cfg: Config) -> Path:
    """Where the weights live: $HF_HOME if the user set it, else the repo-local models/.hf."""
    home = Path(os.environ.get("HF_HOME") or cfg.hf_home_path())
    return home / "hub"


def _load(cfg: Config) -> Models:
    os.environ.setdefault("HF_HOME", str(cfg.hf_home_path()))
    cache = str(hub_cache_dir(cfg))
    try:
        from .classifier import InjectionClassifier
        from .embeddings import SentenceEncoder

        classifier = InjectionClassifier(cfg.models.classifier, num_threads=cfg.models.num_threads, cache_dir=cache)
        encoder = SentenceEncoder(cfg.models.embedder, num_threads=cfg.models.num_threads, cache_dir=cache)
    except Exception as exc:  # noqa: BLE001 - surface one clear error type to analyze()
        raise ModelLoadError(
            f"could not load models from {cache} in offline mode ({type(exc).__name__}: {exc}). "
            "Run scripts/download_models.py on a connected machine first."
        ) from exc
    return Models(
        classifier=classifier,
        encoder=encoder,
        classifier_version=_version(cfg.models.classifier.id, cfg.models.classifier.revision),
        embedder_version=_version(cfg.models.embedder.id, cfg.models.embedder.revision),
    )


def get_models(cfg: Config | None = None) -> Models:
    """Return the process-wide models, loading them on first use (thread-safe)."""
    cfg = cfg or get_config()
    key = cfg.models.model_dump_json()
    with _LOCK:
        if _STATE["models"] is None or _STATE["key"] not in (key, "injected"):
            _STATE["models"], _STATE["key"] = _load(cfg), key
        return _STATE["models"]  # type: ignore[return-value]


def set_models(models: Models) -> None:
    """Install pre-built models (used by tests to inject deterministic fakes)."""
    with _LOCK:
        _STATE["models"], _STATE["key"] = models, "injected"


def is_loaded() -> bool:
    with _LOCK:
        return _STATE["models"] is not None


def reset_models() -> None:
    with _LOCK:
        _STATE["models"], _STATE["key"] = None, None