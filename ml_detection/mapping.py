"""C7 - threshold and flag mapper.

Turns the three raw floats into the contract's label, confidence and flags. Pure:
no models, no I/O, every number comes from :class:`~ml_detection.config.Config`.

Fusion rule
-----------
``injection_score`` says the *content* looks like an instruction to the agent. That
alone is weak evidence: security-awareness emails and phishing reports quote
injection phrases legitimately. What makes it dangerous is the agent acting on it,
so the two action-side signals corroborate:

    drift_signal      = ramp(drift_threshold - task_similarity)
    authorship_signal = ramp((source_similarity - task_similarity) - authorship_margin)
    corroboration     = max(drift_signal, authorship_signal)
    fused             = injection_score * (w + (1 - w) * corroboration)

``ramp`` is 0 at the flag threshold and reaches 1 after ``fusion.ramp_width`` more,
so corroboration begins exactly where the corresponding flag fires. ``fused`` is the
contract's ``ml_confidence`` and decides the label. ``ML_FLAGGED_INJECTION`` remains
a pure content signal, independent of the label, so Part 3 can still see that the
content was hostile even when the action did not follow it.
"""

from __future__ import annotations

from dataclasses import dataclass

from .config import Config
from .schema import Flag, Label


@dataclass(frozen=True)
class RawSignals:
    injection_score: float
    task_similarity: float | None  # None = could not be computed (missing input)
    source_similarity: float | None


@dataclass(frozen=True)
class Mapped:
    label: Label
    confidence: float
    flags: tuple[Flag, ...]
    drift_signal: float
    authorship_signal: float
    corroboration: float


def _ramp(excess: float, width: float) -> float:
    return min(1.0, max(0.0, excess / width))


def map_signals(signals: RawSignals, cfg: Config) -> Mapped:
    inj = signals.injection_score
    task_sim, src_sim = signals.task_similarity, signals.source_similarity
    flags: list[Flag] = []

    if inj >= cfg.injection.flag_threshold:
        flags.append(Flag.ML_FLAGGED_INJECTION)

    drift_signal = 0.0
    if task_sim is not None:
        if task_sim < cfg.similarity.drift_threshold:
            flags.append(Flag.LOW_TASK_SIMILARITY)
        drift_signal = _ramp(cfg.similarity.drift_threshold - task_sim, cfg.fusion.ramp_width)

    authorship_signal = 0.0
    if task_sim is not None and src_sim is not None:
        excess = (src_sim - task_sim) - cfg.similarity.authorship_margin
        authorship_signal = _ramp(excess, cfg.fusion.ramp_width)
        if excess > 0 and inj >= cfg.similarity.authorship_min_injection:
            flags.append(Flag.ACTION_RESEMBLES_UNTRUSTED_SOURCE)

    corroboration = max(drift_signal, authorship_signal)

    weight = cfg.fusion.uncorroborated_weight

    injection_path = inj * (
        weight
        + (1.0 - weight) * corroboration
    )

    if inj > cfg.fusion.min_injection_for_corroboration:
        corroboration_path = (
            cfg.fusion.corroboration_weight
            * corroboration
        )
    else:
        corroboration_path = 0.0

    fused = min(
        1.0,
        max(
            0.0,
            injection_path,
            corroboration_path,
        ),
    )
    if fused >= cfg.labels.malicious:
        label = Label.MALICIOUS
    elif fused >= cfg.labels.suspicious:
        label = Label.SUSPICIOUS
    else:
        label = Label.BENIGN

    return Mapped(
        label=label,
        confidence=fused,
        flags=tuple(flags),
        drift_signal=drift_signal,
        authorship_signal=authorship_signal,
        corroboration=corroboration,
    )