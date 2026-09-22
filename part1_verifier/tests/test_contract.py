from sentinel_verifier.schema import VerifierResult
from sentinel_verifier.verify import verify


def test_output_shape_is_stable_and_json_serializable():
    result = verify({"action_id": "a", "agent_role": "enterprise_assistant", "proposed_action": {"tool": "read_document", "params": {}}, "instruction_source": {"type": "user", "content": "read it"}})
    assert set(result) == {"action_id", "trust_level", "trust_basis", "permission_ok", "structural_flags", "findings", "sensitivity", "details"}
    VerifierResult.model_validate(result)


def test_never_raise_on_non_object():
    result = verify(["not", "a", "dict"])
    assert result["permission_ok"] is False
    assert "MALFORMED_INPUT" in result["structural_flags"]


def test_fail_closed_on_bad_config(monkeypatch):
    import sentinel_verifier.verify as mod
    result = verify({"action_id": "x"})
    assert "INPUT_INCOMPLETE" in result["structural_flags"]


def test_rules_reject_unknown_keys(tmp_path):
    from pathlib import Path
    import yaml
    from pydantic import ValidationError
    from sentinel_verifier.config import DEFAULT_RULES_PATH, load_rules

    raw = yaml.safe_load(Path(DEFAULT_RULES_PATH).read_text(encoding="utf-8"))
    raw["unexpected_runtime_shortcut"] = {"scenario": "attack"}
    path = tmp_path / "bad_rules.yaml"
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")

    try:
        load_rules(path)
    except ValidationError:
        pass
    else:
        raise AssertionError("Unknown config keys must be rejected")
