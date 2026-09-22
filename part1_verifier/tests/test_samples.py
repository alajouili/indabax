import json
from pathlib import Path

from sentinel_verifier.verify import verify

ROOT = Path(__file__).resolve().parents[1]


def test_sample_expectations():
    for expected_path in sorted((ROOT / "samples/expected").glob("*.expect.json")):
        stem = expected_path.name.replace(".expect.json", "")
        request_path = ROOT / "samples/requests" / f"{stem}.json"
        payload = json.loads(request_path.read_text(encoding="utf-8"))
        expected = json.loads(expected_path.read_text(encoding="utf-8"))
        result = verify(payload)
        if "trust_level" in expected:
            assert result["trust_level"] == expected["trust_level"], stem
        if "permission_ok" in expected:
            assert result["permission_ok"] is expected["permission_ok"], stem
        flags = set(result["structural_flags"])
        assert set(expected.get("flags_in", [])) <= flags, (stem, result)
        assert not (set(expected.get("flags_out", [])) & flags), (stem, result)
