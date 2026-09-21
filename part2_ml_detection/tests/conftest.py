"""Shared fixtures.

The ``run`` fixture executes a test twice: against the deterministic stand-in backends
(``stub``, always available, verifies the pipeline logic) and against the real models
(``real``, auto-skipped with a clear reason if the weights are not cached). Assertions
are identical for both, so a behavioural requirement that the real models fail shows
up as a real failure rather than being hidden by the stand-ins.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "samples"
sys.path.insert(0, str(SAMPLES))  # makes `stub_detector` importable

from stub_detector import STUB_MODELS  # noqa: E402

from ml_detection.analyze import analyze  # noqa: E402
from ml_detection.config import get_config  # noqa: E402
from ml_detection.models import ModelLoadError, get_models  # noqa: E402

Runner = Callable[..., dict[str, Any]]


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "real_models: needs the cached DeBERTa/MiniLM weights (auto-skipped otherwise)")
    config.addinivalue_line("markers", "offline: verifies the offline guarantee (run in CI with HF_HUB_OFFLINE=1)")


@pytest.fixture(scope="session")
def real_models_reason() -> str | None:
    """None if the real models load from the local cache; otherwise why they cannot."""
    try:
        get_models(get_config())
    except ModelLoadError as exc:
        return str(exc)
    return None


@pytest.fixture(params=["stub", pytest.param("real", marks=pytest.mark.real_models)])
def run(request: pytest.FixtureRequest, real_models_reason: str | None) -> Runner:
    if request.param == "real":
        if real_models_reason is not None:
            pytest.skip(f"real models unavailable: {real_models_reason[:160]}")

        def runner(raw: Any, **kw: Any) -> dict[str, Any]:
            return analyze(raw, **kw)
    else:

        def runner(raw: Any, **kw: Any) -> dict[str, Any]:
            return analyze(raw, models=STUB_MODELS, **kw)

    runner.backend = request.param  # type: ignore[attr-defined]  # lets a test opt out of the stand-in
    return runner


@pytest.fixture
def stub_run() -> Runner:
    return lambda raw, **kw: analyze(raw, models=STUB_MODELS, **kw)


@pytest.fixture(scope="session")
def real_run(real_models_reason: str | None) -> Runner:
    if real_models_reason is not None:
        pytest.skip(f"real models unavailable: {real_models_reason[:160]}")
    return lambda raw, **kw: analyze(raw, **kw)


def sample_names() -> list[str]:
    return sorted(p.stem for p in (SAMPLES / "inputs").glob("*.json"))


def load_sample(name: str) -> dict[str, Any]:
    return json.loads((SAMPLES / "inputs" / f"{name}.json").read_text(encoding="utf-8"))


def load_expectation(name: str) -> dict[str, Any]:
    return json.loads((SAMPLES / "expected" / f"{name}.expect.json").read_text(encoding="utf-8"))


def assert_expectation(result: dict[str, Any], expect: dict[str, Any]) -> None:
    """Check a result against a property-level expectation file."""
    flags = set(result["content_flags"])
    if "ml_label_in" in expect:
        assert result["ml_label"] in expect["ml_label_in"], (result["ml_label"], result["details"])
    for flag in expect.get("flags_include", []):
        assert flag in flags, (flag, sorted(flags), result["details"])
    for flag in expect.get("flags_exclude", []):
        assert flag not in flags, (flag, sorted(flags), result["details"])
    if "semantic_similarity_min" in expect:
        assert result["semantic_similarity"] >= expect["semantic_similarity_min"], result["semantic_similarity"]
    if "semantic_similarity_max" in expect:
        assert result["semantic_similarity"] <= expect["semantic_similarity_max"], result["semantic_similarity"]


def without_latency(result: dict[str, Any]) -> dict[str, Any]:
    """Everything except details.latency_ms is deterministic; latency is wall-clock by nature."""
    clone = json.loads(json.dumps(result))
    clone["details"].pop("latency_ms", None)
    return clone