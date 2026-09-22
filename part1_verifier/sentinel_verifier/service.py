from __future__ import annotations

from typing import Any

try:
    from fastapi import FastAPI
except ImportError as exc:  # pragma: no cover
    raise RuntimeError("Install the 'service' extra to use FastAPI: pip install -e '.[service]'") from exc

from .verify import verify

app = FastAPI(title="SENTINEL Part 1 Verifier", version="0.1.0")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "sentinel-part1-verifier"}


@app.post("/verify")
def verify_endpoint(payload: dict[str, Any]) -> dict[str, Any]:
    return verify(payload)
