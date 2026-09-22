from sentinel_verifier.config import load_rules
from sentinel_verifier.provenance import resolve_provenance


def test_trusted_sender():
    r = resolve_provenance({"type":"email","sender":"security@corp.local"}, [], load_rules().trust)
    assert r.trust_level.value == "TRUSTED_INTERNAL"


def test_external_email():
    r = resolve_provenance({"type":"email","sender":"x@outside.com"}, [], load_rules().trust)
    assert r.trust_level.value == "UNTRUSTED_EXTERNAL"
