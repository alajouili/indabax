from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Callable, Protocol
from urllib.request import Request, urlopen


class Part2Provider(Protocol):
    def analyze(self, payload: dict[str, Any]) -> dict[str, Any]: ...


@dataclass
class InProcessPart2Provider:
    analyzer: Callable[[dict[str, Any]], dict[str, Any]]

    @classmethod
    def from_default(cls) -> "InProcessPart2Provider":
        # Works when the existing Part 2 package is importable on PYTHONPATH.
        from ml_detection.analyze import analyze

        return cls(analyzer=analyze)

    def analyze(self, payload: dict[str, Any]) -> dict[str, Any]:
        return dict(self.analyzer(payload))


@dataclass
class HttpPart2Provider:
    endpoint: str = "http://127.0.0.1:8090/analyze"
    timeout_seconds: float = 10.0

    def analyze(self, payload: dict[str, Any]) -> dict[str, Any]:
        body = json.dumps(payload).encode("utf-8")
        request = Request(
            self.endpoint,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(request, timeout=self.timeout_seconds) as response:
            return json.loads(response.read().decode("utf-8"))
