import json


def test_hash_chain_verifies(trace):
    trace.append({"action_id": "a1", "outcome": "ALLOW"})
    trace.append({"action_id": "a2", "outcome": "BLOCK"})
    ok, message = trace.verify()
    assert ok, message


def test_tampering_is_detected(trace):
    trace.append({"action_id": "a1", "outcome": "ALLOW"})
    rows = trace.read()
    rows[0]["event"]["outcome"] = "BLOCK"
    trace.path.write_text(json.dumps(rows[0]) + "\n", encoding="utf-8")
    ok, _ = trace.verify()
    assert not ok
def test_sensitive_values_are_redacted(tmp_path):
    from sentinel_decision.tracelog import TraceLog

    trace = TraceLog(
        tmp_path / "trace.jsonl",
        redact_param_keys=[
            "password",
            "token",
            "secret",
            "api_key",
            "credential",
        ],
    )

    trace.append(
        {
            "action_id": "secret-test",
            "input": {
                "action": {
                    "tool": "send_email",
                    "params": {
                        "to": "test@example.com",
                        "token": "SUPER-SECRET-TOKEN",
                        "password": "password123",
                        "nested": {
                            "api_key": "ABC123",
                            "client_secret": "XYZ789",
                        },
                    },
                }
            },
        }
    )

    text = trace.path.read_text(
        encoding="utf-8"
    )

    assert "SUPER-SECRET-TOKEN" not in text
    assert "password123" not in text
    assert "ABC123" not in text
    assert "XYZ789" not in text

    assert "[REDACTED_BY_SENTINEL]" in text

    ok, message = trace.verify()
    assert ok, message