from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Callable, Protocol
from urllib.request import Request, urlopen


class Part1Provider(Protocol):
    def verify(self, payload: dict[str, Any]) -> dict[str, Any]: ...


@dataclass
class InProcessPart1Provider:
    verifier: Callable[[dict[str, Any]], dict[str, Any]]

    @classmethod
    def from_default(cls) -> "InProcessPart1Provider":
        # Works when the Part 1 package is importable.
        from sentinel_verifier.verify import verify

        return cls(verifier=verify)

    def verify(self, payload: dict[str, Any]) -> dict[str, Any]:
        return dict(self.verifier(payload))


@dataclass
class HttpPart1Provider:
    endpoint: str = "http://127.0.0.1:8091/verify"
    timeout_seconds: float = 10.0

    def verify(self, payload: dict[str, Any]) -> dict[str, Any]:
        body = json.dumps(payload).encode("utf-8")

        request = Request(
            self.endpoint,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        with urlopen(
            request,
            timeout=self.timeout_seconds,
        ) as response:
            return json.loads(
                response.read().decode("utf-8")
            )