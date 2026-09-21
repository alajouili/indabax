from __future__ import annotations

import json
from pathlib import Path

import pytest

from sentinel_decision.config import load_policy
from sentinel_decision.tracelog import TraceLog


ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples" / "proposals"


@pytest.fixture
def policy():
    return load_policy(ROOT / "config" / "policy.yaml")


@pytest.fixture
def sample():
    def _load(name: str):
        return json.loads((SAMPLES / f"{name}.json").read_text(encoding="utf-8"))
    return _load


@pytest.fixture
def trace(tmp_path):
    return TraceLog(tmp_path / "trace.jsonl")
