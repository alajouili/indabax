from sentinel_decision.models import Outcome
from sentinel_decision.overrides import evaluate_overrides
from sentinel_decision.signals import parse_proposal


def test_permission_failure_cannot_directly_allow(policy, sample):
    raw = sample("clean")
    raw["permission_ok"] = False
    signals = parse_proposal(raw).combined
    override = evaluate_overrides(signals, policy)
    assert override.minimum_outcome in {Outcome.ESCALATE, Outcome.BLOCK}


def test_critical_structural_flag_forces_block(policy, sample):
    signals = parse_proposal(sample("bad")).combined
    override = evaluate_overrides(signals, policy)
    assert override.forced_outcome is Outcome.BLOCK
