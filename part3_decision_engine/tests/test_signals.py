import pytest

from sentinel_decision.models import TrustLevel
from sentinel_decision.signals import parse_proposal


def test_flat_input_parses(sample):
    parsed = parse_proposal(sample("clean"))
    assert parsed.combined.trust_level is TrustLevel.TRUSTED_INTERNAL
    assert parsed.combined.semantic_similarity == 0.93


def test_mismatched_action_ids_are_rejected():
    raw = {
        "part1": {"action_id": "a", "trust_level": "TRUSTED_INTERNAL", "permission_ok": True},
        "part2": {"action_id": "b", "ml_confidence": 0.0, "semantic_similarity": 1.0},
    }
    with pytest.raises(ValueError):
        parse_proposal(raw)
