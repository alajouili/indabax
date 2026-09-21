from sentinel_decision.models import ActionLifecycle, Outcome, Verdict
from sentinel_decision.state import DecisionState


def verdict(i: int):
    return Verdict(
        action_id=f"a{i}",
        risk_score=60,
        outcome=Outcome.ESCALATE,
        explanation="test",
        policy_version="test",
    )


def test_session_evidence_accumulates(policy):
    state = DecisionState.from_policy(policy)
    assert state.session_risk_points(policy) == 0
    state.record(verdict(1), ActionLifecycle.DENIED)
    assert state.session_risk_points(policy) > 0


def test_history_is_bounded(policy):
    state = DecisionState(max_history=2)
    state.record(verdict(1), ActionLifecycle.DENIED)
    state.record(verdict(2), ActionLifecycle.DENIED)
    state.record(verdict(3), ActionLifecycle.DENIED)
    assert len(state.history) == 2
