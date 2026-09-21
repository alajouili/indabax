from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any


class ReviewStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

        self._lock = threading.Lock()

    def _read(self) -> dict[str, Any]:
        if not self.path.exists():
            return {}

        try:
            return json.loads(
                self.path.read_text(encoding="utf-8")
            )
        except Exception:
            return {}

    def _write(self, data: dict[str, Any]) -> None:
        self.path.write_text(
            json.dumps(
                data,
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )

    def add(
        self,
        action_id: str,
        proposal: dict[str, Any],
        verdict: dict[str, Any],
    ) -> None:

        with self._lock:
            data = self._read()

            data[action_id] = {
                "action_id": action_id,
                "proposal": proposal,
                "verdict": verdict,
            }

            self._write(data)

    def get(
        self,
        action_id: str,
    ) -> dict[str, Any] | None:

        return self._read().get(action_id)

    def list(self) -> list[dict[str, Any]]:
        return list(
            self._read().values()
        )

    def remove(
        self,
        action_id: str,
    ) -> None:

        with self._lock:
            data = self._read()

            data.pop(action_id, None)

            self._write(data)