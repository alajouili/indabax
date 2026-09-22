from __future__ import annotations

import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def sample_dir() -> Path:
    return ROOT / "samples" / "requests"


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def assert_expectation(result: dict, expected: dict) -> None:
    if "trust_level" in expected:
        assert result["trust_level"] == expected["trust_level"]
    if "permission_ok" in expected:
        assert result["permission_ok"] is expected["permission_ok"]
    flags = set(result["structural_flags"])
    assert set(expected.get("flags_in", [])) <= flags
    assert not (set(expected.get("flags_out", [])) & flags)
