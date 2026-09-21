from sentinel_decision.config import load_policy


def test_policy_loads_and_thresholds_are_ordered(policy):
    assert policy.thresholds.rewrite < policy.thresholds.escalate < policy.thresholds.block
    assert policy.version


def test_default_policy_loads():
    assert load_policy().version
