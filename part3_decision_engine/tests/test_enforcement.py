import pytest

from sentinel_decision.enforcement import EnforcementGate
from sentinel_decision.models import Action, HumanResponse, Outcome, Verdict


def v(outcome, response=HumanResponse.NOT_REQUIRED):
    return Verdict(
        action_id="a1",
        risk_score=50,
        outcome=outcome,
        human_response=response,
        explanation="test",
        policy_version="test",
    )


def test_block_and_denied_escalation_get_no_permit():
    gate = EnforcementGate()
    action = Action(tool="send_email", params={})
    assert gate.issue_permit(v(Outcome.BLOCK), action) is None
    assert gate.issue_permit(v(Outcome.ESCALATE, HumanResponse.DENIED), action) is None
    assert gate.issue_permit(v(Outcome.REWRITE), action) is None


def test_allow_and_human_approved_escalation_can_execute_once():
    for verdict in (
        v(Outcome.ALLOW),
        v(Outcome.ESCALATE, HumanResponse.APPROVED),
    ):
        gate = EnforcementGate()
        action = Action(tool="summarize", params={})
        permit = gate.issue_permit(verdict, action)
        assert gate.execute(permit, action, lambda a: a.tool) == "summarize"
        with pytest.raises(PermissionError):
            gate.execute(permit, action, lambda a: a.tool)
