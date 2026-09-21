from sentinel_decision.classify import classify_action
from sentinel_decision.models import Action


def test_action_category_is_policy_driven(policy):
    result = classify_action(Action(tool="transfer_money", params={}), policy)
    assert result.category == "financial"
    assert result.impact == 50


def test_unknown_tool_is_supported(policy):
    result = classify_action(Action(tool="future_tool", params={}), policy)
    assert result.category == "unknown"
