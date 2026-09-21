from sentinel_decision.classify import classify_action
from sentinel_decision.scoring import score_signals
from sentinel_decision.signals import parse_proposal


def test_clean_scores_lower_than_bad(policy, sample):
    clean = parse_proposal(sample("clean")).combined
    bad = parse_proposal(sample("bad")).combined
    clean_score = score_signals(clean, policy, classify_action(clean.action, policy)).risk_score
    bad_score = score_signals(bad, policy, classify_action(bad.action, policy)).risk_score
    assert clean_score < bad_score
    assert 0 <= clean_score <= 100
    assert 0 <= bad_score <= 100


def test_scoring_is_deterministic(policy, sample):
    signals = parse_proposal(sample("mixed")).combined
    action_class = classify_action(signals.action, policy)
    a = score_signals(signals, policy, action_class)
    b = score_signals(signals, policy, action_class)
    assert a == b
