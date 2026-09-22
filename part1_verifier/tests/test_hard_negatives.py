import json
from pathlib import Path

from sentinel_verifier.verify import verify

ROOT = Path(__file__).resolve().parents[1]


def test_legitimate_base64_stays_clean_of_instruction_flag():
    payload = json.loads((ROOT / "samples/requests/hard_negative_base64.json").read_text())
    result = verify(payload)
    assert "ENCODED_INSTRUCTION" not in result["structural_flags"]


def test_internal_email_not_external_recipient():
    payload = json.loads((ROOT / "samples/requests/safe_internal.json").read_text())
    result = verify(payload)
    assert "EXTERNAL_RECIPIENT" not in result["structural_flags"]
