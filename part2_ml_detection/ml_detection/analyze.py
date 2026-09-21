"""``analyze(dict) -> dict`` - the module's single entry point.

Pipeline: C1 contract guard -> C2 normalize -> C3 chunk -> C4 classify (max over
chunks, then localize the offending sentence) -> C5 embed (one batched call) ->
C6 cosines -> C7 map to label + flags.

Boundary rules (from the architecture):
  * Return, never decide: there is no allow/block/escalate/rewrite anywhere here.
  * Never raise: any failure yields a valid, degraded object (benign, confidence 0,
    INPUT_INCOMPLETE, ``details.error``).
  * Additive only: the four contract fields never change; extra information goes in ``details``.
  * Only the four input fields are read. Unknown keys (scenario ids, file names...) are
    ignored by construction, so nothing organizer-provided can influence a decision.
"""

from __future__ import annotations

import threading
import time
from typing import Any

from .chunking import chunk_text
from .classifier import localize_evidence, strongest_chunk
from .config import Config, get_config
from .mapping import RawSignals, map_signals
from .models import Models, get_models
from .normalize import merge_applied, normalize
from .schema import (
    UNKNOWN_ACTION_ID,
    AnalyzeInput,
    AnalyzeOutput,
    Flag,
    fallback_output,
    parse_input,
)
from .similarity import compute_similarities

# Models are shared singletons; serialising inference keeps results deterministic under a threaded server.
_INFERENCE_LOCK = threading.Lock()


def _elapsed_ms(started: float) -> int:
    return int((time.perf_counter() - started) * 1000)


def _round(value: float | None) -> float | None:
    return None if value is None else round(float(value), 4)


def _run(
    parsed: AnalyzeInput,
    missing: tuple[str, ...],
    cfg: Config,
    started: float,
    models_override: Models | None,
) -> AnalyzeOutput:

    norm = cfg.normalization

    task = normalize(
        parsed.user_task,
        spaced_letters_min_run=norm.spaced_letters_min_run,
    )

    action = normalize(
        parsed.proposed_action_description,
        spaced_letters_min_run=norm.spaced_letters_min_run,
    )

    content = normalize(
        parsed.instruction_content,
        spaced_letters_min_run=norm.spaced_letters_min_run,
    )

    applied = merge_applied(task, action, content)

    ck = cfg.chunking

    chunks = chunk_text(
        content.text,
        window_words=ck.window_words,
        overlap_words=ck.overlap_words,
        max_chunks=ck.max_chunks,
        max_word_chars=ck.max_word_chars,
        enabled=ck.enabled,
    )

    with _INFERENCE_LOCK:
        models = models_override or get_models(cfg)

        strongest = strongest_chunk(
            chunks.chunks,
            models.classifier,
        )

        evidence_span: str | None = None
        evidence_score = 0.0
        source_text = ""

        if strongest.chunk is not None:
            source_text = strongest.chunk.text

            localized = localize_evidence(
                strongest.chunk.text,
                models.classifier,
                max_sentences=cfg.evidence.max_sentences,
                min_sentence_words=cfg.evidence.min_sentence_words,
                min_sentence_chars=cfg.evidence.min_sentence_chars,
                context_radius=cfg.evidence.context_radius,
                max_chars=cfg.evidence.max_chars,
            )

            if localized.text is not None:
                source_text = localized.text
                evidence_score = localized.score

                if localized.score >= cfg.evidence.localize_min_score:
                    evidence_span = localized.text

        # Embeddings
        named = [
            (name, text)
            for name, text in (
                ("task", task.text),
                ("action", action.text),
                ("source", source_text),
            )
            if text.strip()
        ]

        vectors: dict[str, Any] = {}

        if len(named) >= 2:
            encoded = models.encoder.encode(
                [text for _, text in named]
            )

            if len(encoded) != len(named):
                raise ValueError(
                    f"encoder returned {len(encoded)} vectors "
                    f"for {len(named)} texts"
                )

            vectors = {
                name: vec
                for (name, _), vec in zip(named, encoded)
            }

    sims = compute_similarities(
        vectors.get("task"),
        vectors.get("action"),
        vectors.get("source"),
    )

    mapped = map_signals(
        RawSignals(
            injection_score=strongest.score,
            task_similarity=sims.task_action,
            source_similarity=sims.source_action,
        ),
        cfg,
    )

    flags = list(mapped.flags)

    if applied:
        flags.append(Flag.OBFUSCATION_NORMALIZED)

    if chunks.truncated:
        flags.append(Flag.CONTENT_TRUNCATED)

    if missing:
        flags.append(Flag.INPUT_INCOMPLETE)

    details: dict[str, Any] = {
        "source_similarity": _round(sims.source_action),
        "evidence_span": evidence_span,
        "chunk_index": (
            strongest.chunk.index
            if strongest.chunk is not None
            else None
        ),
        "normalization_applied": list(applied),
        "model_version": models.classifier_version,
        "thresholds_version": cfg.version,
        "latency_ms": _elapsed_ms(started),

        "injection_score": _round(strongest.score),
        "evidence_score": _round(evidence_score),

        "drift_signal": _round(mapped.drift_signal),
        "authorship_signal": _round(mapped.authorship_signal),
        "corroboration": _round(mapped.corroboration),

        "chunks_scanned": len(chunks.chunks),
        "chunks_total": chunks.total_chunks,
        "missing_fields": list(missing),

        "embedder_version": models.embedder_version,
        "thresholds_calibrated": cfg.calibrated,
    }

    return AnalyzeOutput(
        action_id=parsed.action_id,
        ml_label=mapped.label,
        ml_confidence=mapped.confidence,
        semantic_similarity=(
            sims.task_action
            if sims.task_action is not None
            else 0.0
        ),
        content_flags=flags,
        details=details,
    )


def analyze(raw: Any, *, config: Config | None = None, models: Models | None = None) -> dict[str, Any]:
    """Analyze one candidate action. Never raises; always returns a contract-shaped dict.

    ``config`` and ``models`` are optional overrides (calibration ablations, tests, the stub
    detector); the orchestrator simply calls ``analyze(payload)``.
    """
    started = time.perf_counter()
    action_id, missing = UNKNOWN_ACTION_ID, ()
    version: str | None = None
    try:
        parsed, missing = parse_input(raw)
        action_id = parsed.action_id
        cfg = config or get_config()
        version = cfg.version
        return _run(parsed, missing, cfg, started, models).to_dict()
    except Exception as exc:  # noqa: BLE001 - the contract forbids raising
        try:
            return fallback_output(
                action_id,
                missing_fields=missing,
                error=f"{type(exc).__name__}: {exc}",
                thresholds_version=version,
                latency_ms=_elapsed_ms(started),
            ).to_dict()
        except Exception:  # noqa: BLE001 - last resort: a hand-built valid object
            return {
                "action_id": UNKNOWN_ACTION_ID,
                "ml_label": "benign",
                "ml_confidence": 0.0,
                "semantic_similarity": 0.0,
                "content_flags": [Flag.INPUT_INCOMPLETE.value],
                "details": {"degraded": True},
            }