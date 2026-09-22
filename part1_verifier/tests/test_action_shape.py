from sentinel_verifier.action_shape import analyze_action_shape
from sentinel_verifier.config import load_rules


def test_external_recipient_and_consequential():
    cfg = load_rules()
    r = analyze_action_shape({"tool":"send_email","params":{"to":"x@outside.com"}}, cfg.action_shape, cfg.sinks, cfg.mirroring)
    assert "EXTERNAL_RECIPIENT" in r.flags
    assert "CONSEQUENTIAL_ACTION" in r.flags


def test_control_change():
    cfg = load_rules()
    r = analyze_action_shape({"tool":"change_permissions","params":{}}, cfg.action_shape, cfg.sinks, cfg.mirroring)
    assert "CONTROL_CHANGE" in r.flags
