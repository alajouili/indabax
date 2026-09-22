from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from .config import EncodingRules, SecretRules, SinkRules
from .decode import decode_variants
from .schema import Finding, FindingSeverity, Sensitivity
from .secrets import SecretHit, scan_secrets
from .textnorm import alnum_fold


@dataclass(frozen=True)
class DataflowResult:
    flags: tuple[str, ...]
    findings: tuple[Finding, ...]
    sensitivity: Sensitivity
    watch_values: tuple[str, ...]


def _walk_strings(value: Any, path: str = "") -> Iterable[tuple[str, str]]:
    if isinstance(value, dict):
        for key in sorted(value, key=str):
            child = f"{path}.{key}" if path else str(key)
            yield from _walk_strings(value[key], child)
    elif isinstance(value, list):
        for i, item in enumerate(value):
            yield from _walk_strings(item, f"{path}[{i}]")
    elif isinstance(value, str):
        yield path, value


def _domain(value: str) -> str:
    value = value.strip().lower()
    if "@" in value:
        return value.rsplit("@", 1)[1]
    if "://" in value:
        host = value.split("://", 1)[1].split("/", 1)[0]
        return host.split(":", 1)[0]
    return value


def is_external_sink(action: dict[str, Any] | None, rules: SinkRules) -> bool:
    if not action:
        return False
    tool = str(action.get("tool") or action.get("action") or "")
    if tool not in rules.external_tools:
        return False
    params = action.get("params") if isinstance(action.get("params"), dict) else action
    recipients: list[str] = []
    for key in rules.recipient_keys:
        val = params.get(key) if isinstance(params, dict) else None
        if isinstance(val, str):
            recipients.append(val)
        elif isinstance(val, list):
            recipients.extend(str(x) for x in val)
    if not recipients:
        return True
    internal = {d.lower() for d in rules.internal_domains}
    return any(_domain(r) not in internal for r in recipients)


def analyze_dataflow(
    source_bundle: Any,
    action: dict[str, Any] | None,
    secret_rules: SecretRules,
    sink_rules: SinkRules,
    encoding_rules: EncodingRules,
) -> DataflowResult:
    secret_scan = scan_secrets(source_bundle, secret_rules)
    watch_hits: tuple[SecretHit, ...] = secret_scan.hits
    watch_values = tuple(sorted({h.value for h in watch_hits if len(h.value) >= 8}))
    flags: list[str] = []
    findings: list[Finding] = list(secret_scan.findings)

    if watch_values:
        flags.append("SECRET_SHAPE_DETECTED")

    if watch_values and is_external_sink(action, sink_rules):
        params = action.get("params") if isinstance(action, dict) and isinstance(action.get("params"), dict) else (action or {})
        watch_folds = {alnum_fold(v): v for v in watch_values if alnum_fold(v)}
        leaked: set[str] = set()
        for path, text in _walk_strings(params):
            candidates = decode_variants(text, encoding_rules)
            for variant in candidates:
                folded = alnum_fold(variant.text)
                for wf, original in watch_folds.items():
                    if wf and wf in folded:
                        leaked.add(original)
                        findings.append(
                            Finding(
                                code="SECRET_TO_EXTERNAL_SINK",
                                severity=FindingSeverity.CRITICAL,
                                evidence=f"secret-like value reaches external sink via {path}",
                                location=path,
                            )
                        )
        if leaked:
            flags.append("SECRET_TO_EXTERNAL_SINK")

    sensitivity = Sensitivity.SECRET if watch_values else Sensitivity.NONE
    return DataflowResult(
        tuple(sorted(set(flags))),
        tuple(sorted(findings, key=lambda f: (f.code, f.location, f.evidence))),
        sensitivity,
        watch_values,
    )
