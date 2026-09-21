from __future__ import annotations

from .config import Policy
from .models import CombinedSignals, Outcome, OverrideResult


_SEVERITY = {
    Outcome.ALLOW: 0,
    Outcome.REWRITE: 1,
    Outcome.ESCALATE: 2,
    Outcome.BLOCK: 3,
}


def max_outcome(a: Outcome | None, b: Outcome | None) -> Outcome | None:
    if a is None:
        return b
    if b is None:
        return a
    return a if _SEVERITY[a] >= _SEVERITY[b] else b


def evaluate_overrides(signals: CombinedSignals, policy: Policy) -> OverrideResult:
    minimum: Outcome | None = None
    forced: Outcome | None = None
    reasons: list[str] = []
    explanation: list[str] = []

    if not signals.permission_ok:
        minimum = max_outcome(minimum, policy.overrides.permission_denied_minimum)
        reasons.append("OVERRIDE_PERMISSION_DENIED")
        explanation.append("permission check failed")

    if "INPUT_INCOMPLETE" in signals.content_flags:
        minimum = max_outcome(minimum, policy.overrides.input_incomplete_minimum)
        reasons.append("OVERRIDE_INPUT_INCOMPLETE")
        explanation.append("Part 2 evidence is incomplete")

    for flag in signals.structural_flags:
        outcome = policy.overrides.critical_structural_flags.get(flag)
        if outcome is not None:
            forced = max_outcome(forced, outcome)
            reasons.append(f"OVERRIDE_STRUCTURAL_{flag}")
            explanation.append(f"critical structural flag {flag}")

    for flag in signals.content_flags:
        outcome = policy.overrides.critical_content_flags.get(flag)
        if outcome is not None:
            forced = max_outcome(forced, outcome)
            reasons.append(f"OVERRIDE_CONTENT_{flag}")
            explanation.append(f"critical content flag {flag}")

    if (
        signals.trust_level.value == "UNTRUSTED_EXTERNAL"
        and signals.ml_confidence >= policy.overrides.high_ml_confidence
    ):
        minimum = max_outcome(minimum, policy.overrides.high_ml_with_untrusted_minimum)
        reasons.append("OVERRIDE_UNTRUSTED_HIGH_ML")
        explanation.append("untrusted source with high ML confidence")

    if signals.semantic_similarity <= policy.similarity.critical_similarity:
        minimum = max_outcome(minimum, policy.overrides.very_low_similarity_minimum)
        reasons.append("OVERRIDE_VERY_LOW_SIMILARITY")
        explanation.append("semantic similarity is critically low")

    return OverrideResult(
        minimum_outcome=minimum,
        forced_outcome=forced,
        reason_codes=reasons,
        explanation_fragments=explanation,
    )
