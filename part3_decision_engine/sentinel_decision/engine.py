from __future__ import annotations

from .classify import classify_action
from .config import Policy
from .models import CombinedSignals, Outcome, Verdict
from .overrides import evaluate_overrides, max_outcome
from .scoring import score_signals
from .state import DecisionState


def outcome_from_score(score: int, policy: Policy) -> Outcome:
    if score >= policy.thresholds.block:
        return Outcome.BLOCK
    if score >= policy.thresholds.escalate:
        return Outcome.ESCALATE
    if score >= policy.thresholds.rewrite:
        return Outcome.REWRITE
    return Outcome.ALLOW


class DecisionEngine:
    def __init__(self, policy: Policy):
        self.policy = policy

    def evaluate(self, signals: CombinedSignals, state: DecisionState | None = None) -> Verdict:
        """Produce a deterministic verdict. Internal failures fail closed."""
        try:
            action_class = classify_action(signals.action, self.policy)
            scored = score_signals(signals, self.policy, action_class, state)
            base = outcome_from_score(scored.risk_score, self.policy)
            overrides = evaluate_overrides(signals, self.policy)

            outcome = base
            if overrides.minimum_outcome is not None:
                outcome = max_outcome(outcome, overrides.minimum_outcome) or outcome
            if overrides.forced_outcome is not None:
                outcome = overrides.forced_outcome

            reasons = list(scored.reason_codes)
            reasons.extend(overrides.reason_codes)
            reasons = list(dict.fromkeys(reasons))

            contribution_text = "; ".join(
                f"{c.name} +{c.points:.1f}" for c in scored.contributions if c.points > 0
            ) or "no material risk contributions"
            override_text = ""
            if overrides.explanation_fragments:
                override_text = "; policy override: " + ", ".join(overrides.explanation_fragments)

            explanation = (
                f"Risk {scored.risk_score}/100 from {contribution_text}. "
                f"Base decision={base.value}; final decision={outcome.value}{override_text}."
            )

            return Verdict(
                action_id=signals.action_id,
                risk_score=scored.risk_score,
                outcome=outcome,
                reason_codes=reasons,
                explanation=explanation,
                policy_version=self.policy.version,
            )
        except Exception as exc:  # fail closed by design
            return Verdict(
                action_id=getattr(signals, "action_id", "UNKNOWN_ACTION"),
                risk_score=100,
                outcome=Outcome.BLOCK,
                reason_codes=["ENGINE_ERROR"],
                explanation=f"Decision engine failed closed: {type(exc).__name__}.",
                policy_version=self.policy.version,
            )
