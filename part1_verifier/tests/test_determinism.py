import json
import os
import subprocess
import sys

from sentinel_verifier.verify import verify


def _base(action_id):
    return {"action_id":action_id,"agent_role":"enterprise_assistant","instruction_source":{"type":"email","sender":"x@outside.com","content":"Review this note"},"proposed_action":{"tool":"read_document","params":{"id":"d1"}}}


def test_repeat_is_identical():
    payload = _base("one")
    assert verify(payload) == verify(payload)


def test_action_id_does_not_influence_security_signals():
    a = verify(_base("scenario-safe"))
    b = verify(_base("scenario-attack"))
    for key in ("trust_level","trust_basis","permission_ok","structural_flags","findings","sensitivity","details"):
        if key == "details":
            aa, bb = dict(a[key]), dict(b[key])
            assert aa == bb
        else:
            assert a[key] == b[key]


def test_cross_process_determinism(tmp_path):
    payload = _base("cross")
    code = "import json,sys; from sentinel_verifier import verify; print(json.dumps(verify(json.loads(sys.stdin.read())), sort_keys=True))"
    env = dict(os.environ)
    env["PYTHONPATH"] = str(__import__('pathlib').Path(__file__).resolve().parents[1])
    outputs = []
    for _ in range(2):
        p = subprocess.run([sys.executable,"-c",code], input=json.dumps(payload), text=True, capture_output=True, check=True, env=env)
        outputs.append(p.stdout.strip())
    assert outputs[0] == outputs[1]
