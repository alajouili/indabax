import hashlib
import os

import pytest

from sentinel_verifier.digest import action_digest, canonical_json


def test_digest_is_canonical_and_order_independent():
    a = {"tool":"send_email","params":{"body":"hi","to":"a@example.com"}}
    b = {"params":{"to":"a@example.com","body":"hi"},"tool":"send_email"}
    assert action_digest(a) == action_digest(b)
    expected = hashlib.sha256(canonical_json(a).encode("utf-8")).hexdigest()
    assert action_digest(a) == expected


def test_optional_official_starter_kit_vector():
    expected = os.getenv("STARTER_KIT_EXPECTED_DIGEST")
    if not expected:
        pytest.skip("No official starter-kit digest vector supplied")
    action = {"tool":"read_document","params":{"id":"doc-1"}}
    assert action_digest(action) == expected
