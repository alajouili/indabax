from __future__ import annotations

import hashlib
import json
import threading
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


_GENESIS = "0" * 64


def _canonical(data: dict[str, Any]) -> bytes:
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _normalize_key(key: str) -> str:
    return (
        key.lower()
        .replace("-", "_")
        .replace(" ", "_")
    )


def _is_sensitive_key(
    key: str,
    sensitive_keys: set[str],
) -> bool:
    normalized = _normalize_key(key)

    # Exact match or contained sensitive term.
    #
    # Examples:
    # token          -> redacted
    # access_token   -> redacted
    # api_token      -> redacted
    # client_secret  -> redacted
    # credentials    -> redacted because it contains "credential"
    return any(
        sensitive in normalized
        for sensitive in sensitive_keys
    )


def redact_sensitive(
    value: Any,
    sensitive_keys: set[str],
    placeholder: str,
) -> Any:
    """Recursively redact sensitive dictionary values.

    The original object is never modified.
    """

    if isinstance(value, dict):
        cleaned: dict[str, Any] = {}

        for key, item in value.items():
            key_text = str(key)

            if _is_sensitive_key(key_text, sensitive_keys):
                cleaned[key] = placeholder
            else:
                cleaned[key] = redact_sensitive(
                    item,
                    sensitive_keys,
                    placeholder,
                )

        return cleaned

    if isinstance(value, list):
        return [
            redact_sensitive(
                item,
                sensitive_keys,
                placeholder,
            )
            for item in value
        ]

    if isinstance(value, tuple):
        return [
            redact_sensitive(
                item,
                sensitive_keys,
                placeholder,
            )
            for item in value
        ]

    return deepcopy(value)


class TraceLog:
    def __init__(
        self,
        path: str | Path,
        *,
        redact_param_keys: list[str] | None = None,
        safe_placeholder: str = "[REDACTED_BY_SENTINEL]",
    ):
        self.path = Path(path)
        self.path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        self._lock = threading.Lock()

        self._sensitive_keys = {
            _normalize_key(key)
            for key in (
                redact_param_keys
                or [
                    "password",
                    "token",
                    "secret",
                    "api_key",
                    "credential",
                ]
            )
        }

        self._safe_placeholder = safe_placeholder

    def _last(self) -> tuple[int, str]:
        if (
            not self.path.exists()
            or self.path.stat().st_size == 0
        ):
            return 0, _GENESIS

        last = None

        with self.path.open(
            "r",
            encoding="utf-8",
        ) as fh:
            for line in fh:
                if line.strip():
                    last = json.loads(line)

        if last is None:
            return 0, _GENESIS

        return int(last["seq"]), str(last["hash"])

    def append(
        self,
        event: dict[str, Any],
    ) -> dict[str, Any]:
        # CRITICAL:
        # redact BEFORE hashing and BEFORE writing.
        #
        # Therefore the secret never appears in the persistent
        # trace and the hash protects the redacted representation.
        safe_event = redact_sensitive(
            event,
            self._sensitive_keys,
            self._safe_placeholder,
        )

        with self._lock:
            seq, prev_hash = self._last()

            record = {
                "seq": seq + 1,
                "timestamp": datetime.now(
                    timezone.utc
                ).isoformat(),
                "event": safe_event,
                "prev_hash": prev_hash,
            }

            record["hash"] = hashlib.sha256(
                _canonical(record)
            ).hexdigest()

            with self.path.open(
                "a",
                encoding="utf-8",
                newline="\n",
            ) as fh:
                fh.write(
                    json.dumps(
                        record,
                        sort_keys=True,
                        ensure_ascii=False,
                    )
                    + "\n"
                )

            return record

    def read(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []

        return [
            json.loads(line)
            for line in self.path.read_text(
                encoding="utf-8"
            ).splitlines()
            if line.strip()
        ]

    def verify(self) -> tuple[bool, str]:
        previous = _GENESIS
        expected_seq = 1

        for record in self.read():
            if record.get("seq") != expected_seq:
                return (
                    False,
                    f"sequence mismatch at record "
                    f"{expected_seq}",
                )

            if record.get("prev_hash") != previous:
                return (
                    False,
                    f"previous hash mismatch at record "
                    f"{expected_seq}",
                )

            supplied = record.get("hash")

            unsigned = {
                key: value
                for key, value in record.items()
                if key != "hash"
            }

            computed = hashlib.sha256(
                _canonical(unsigned)
            ).hexdigest()

            if supplied != computed:
                return (
                    False,
                    f"hash mismatch at record "
                    f"{expected_seq}",
                )

            previous = supplied
            expected_seq += 1

        return (
            True,
            f"verified {expected_seq - 1} record(s)",
        )