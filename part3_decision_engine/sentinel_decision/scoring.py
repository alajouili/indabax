from __future__ import annotations

from .classify import ActionClassification
from .config import Policy
from .models import CombinedSignals, ScoreContribution, ScoreResult
from .state import DecisionState


def _flag_points(flags: list[str], mapping: dict[str, float], unknown_key: str, cap: float):
    total = 0.0
    reasons: list[str] = []
    details: list[ScoreContribution] = []
    for flag in sorted(set(flags)):
        points = float(mapping.get(flag, mapping.get(unknown_key, 0.0)))
        if points <= 0:
            continue
        total += points
        reasons.append(flag)
        details.append(ScoreContribution(name=flag, points=points, reason=f"flag {flag}"))
    if total > cap and total > 0:
        factor = cap / total
        details = [
            ScoreContribution(name=d.name, points=round(d.points * factor, 4), reason=d.reason)
            for d in details
        ]
        total = cap
    return total, reasons, details


def score_signals(
    signals: CombinedSignals,
    policy: Policy,
    action_class: ActionClassification,
    state: DecisionState | None = None,
) -> ScoreResult:
    contributions: list[ScoreContribution] = []
    reason_codes: list[str] = []

    trust_points = float(policy.trust_points.get(signals.trust_level.value, 0.0))
    if trust_points:
        contributions.append(
            ScoreContribution(
                name="trust_level",
                points=trust_points,
                reason=f"source trust is {signals.trust_level.value}",
            )
        )
        reason_codes.append(signals.trust_level.value)

    if not signals.permission_ok:
        contributions.append(
            ScoreContribution(
                name="permission_denied",
                points=policy.weights.permission_denied,
                reason="Part 1 reports permission_ok=false",
            )
        )
        reason_codes.append("PERMISSION_DENIED")

    structural_total, structural_reasons, structural_details = _flag_points(
        signals.structural_flags,
        policy.structural_flag_points,
        "UNKNOWN_STRUCTURAL_FLAG",
        policy.caps.structural_flags,
    )
    contributions.extend(structural_details)
    reason_codes.extend(structural_reasons)

    ml_points = policy.weights.ml_confidence * signals.ml_confidence
    if ml_points:
        contributions.append(
            ScoreContribution(
                name="ml_confidence",
                points=round(ml_points, 4),
                reason=f"ML confidence={signals.ml_confidence:.4f}",
            )
        )
        if signals.ml_confidence >= policy.overrides.high_ml_confidence:
            reason_codes.append("HIGH_ML_CONFIDENCE")

    safe = policy.similarity.safe_similarity
    similarity = signals.semantic_similarity
    if similarity < safe and safe > 0:
        drift_fraction = min(1.0, max(0.0, (safe - similarity) / safe))
        drift_points = policy.weights.semantic_drift * drift_fraction
        contributions.append(
            ScoreContribution(
                name="semantic_drift",
                points=round(drift_points, 4),
                reason=f"semantic similarity={similarity:.4f} below safe target={safe:.4f}",
            )
        )
        reason_codes.append("SEMANTIC_DRIFT")

    content_total, content_reasons, content_details = _flag_points(
        signals.content_flags,
        policy.content_flag_points,
        "UNKNOWN_CONTENT_FLAG",
        policy.caps.content_flags,
    )
    contributions.extend(content_details)
    reason_codes.extend(content_reasons)

    if action_class.impact > 0 and policy.weights.action_impact > 0:
        impact_points = policy.weights.action_impact * (action_class.impact / 100.0)
        contributions.append(
            ScoreContribution(
                name="action_impact",
                points=round(impact_points, 4),
                reason=f"action category={action_class.category}, impact={action_class.impact}",
            )
        )
        reason_codes.append(f"ACTION_CATEGORY_{action_class.category.upper()}")

    if state is not None:
        session_points = state.session_risk_points(policy)
        if session_points:
            weighted = min(policy.weights.session_history, session_points)
            contributions.append(
                ScoreContribution(
                    name="session_history",
                    points=round(weighted, 4),
                    reason=f"prior suspicious events={state.suspicious_events()}",
                )
            )
            reason_codes.append("SESSION_RISK_ACCUMULATED")

    raw_score = sum(item.points for item in contributions)
    raw_score = max(0.0, min(policy.caps.total, raw_score))
    risk_score = int(round(raw_score))

    # Preserve order while de-duplicating.
    seen: set[str] = set()
    unique_reasons = []
    for code in reason_codes:
        if code not in seen:
            seen.add(code)
            unique_reasons.append(code)

    return ScoreResult(
        raw_score=round(raw_score, 4),
        risk_score=risk_score,
        contributions=contributions,
        reason_codes=unique_reasons,
    )
