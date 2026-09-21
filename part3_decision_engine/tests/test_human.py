from sentinel_decision.human import DenyAllApprover, ScriptedApprover
from sentinel_decision.models import HumanCase, HumanResponse, Outcome


def case():
    return HumanCase(
        action_id="a1",
        risk_score=55,
        proposed_outcome=Outcome.ESCALATE,
        reason_codes=["TEST"],
        explanation="test",
    )


def test_scripted_approver():
    approver = ScriptedApprover([HumanResponse.APPROVED, HumanResponse.DENIED])
    assert approver.review(case()) is HumanResponse.APPROVED
    assert approver.review(case()) is HumanResponse.DENIED


def test_deny_all_is_safe_default():
    assert DenyAllApprover().review(case()) is HumanResponse.DENIED
