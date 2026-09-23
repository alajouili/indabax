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
def _explicit_sensitive_strings(value: Any) -> tuple[str, ...]:
    found: set[str] = set()

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            sensitivity = str(
                node.get("sensitivity", "")
            ).strip().lower()

            if sensitivity in {
                "confidential",
                "restricted",
            }:
                content = node.get("content")

                if (
                    isinstance(content, str)
                    and len(alnum_fold(content)) >= 24
                ):
                    found.add(content)

            for child in node.values():
                walk(child)

        elif isinstance(node, list):
            for child in node:
                walk(child)

    walk(value)
    return tuple(sorted(found))

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
    explicit_sensitive = _explicit_sensitive_strings(
    source_bundle
)
    watch_hits: tuple[SecretHit, ...] = secret_scan.hits
    watch_values = tuple(sorted({h.value for h in watch_hits if len(h.value) >= 8}))
    flags: list[str] = []
    findings: list[Finding] = list(secret_scan.findings)

    if watch_values:
        flags.append("SECRET_SHAPE_DETECTED")

    if watch_values and action:
        params = (
            action.get("params")
            if isinstance(action, dict)
            and isinstance(action.get("params"), dict)
            else action
        )

        watch_folds = {
            alnum_fold(v): v
            for v in watch_values
            if alnum_fold(v)
        }

        leaked_paths: set[tuple[str, str]] = set()

        for path, text in _walk_strings(params):
            candidates = decode_variants(
                text,
                encoding_rules,
            )

            for variant in candidates:
                folded = alnum_fold(
                    variant.text
                )

                for wf, original in watch_folds.items():
                    if wf and wf in folded:
                        leaked_paths.add(
                            (original, path)
                        )

        tool = str(
            action.get("tool")
            or action.get("action")
            or ""
        )

        # Existing behaviour:
        # secret propagated to an external destination.
        if (
            leaked_paths
            and is_external_sink(
                action,
                sink_rules,
            )
        ):
            flags.append(
                "SECRET_TO_EXTERNAL_SINK"
            )

            for _, path in sorted(leaked_paths):
                findings.append(
                    Finding(
                        code="SECRET_TO_EXTERNAL_SINK",
                        severity=FindingSeverity.CRITICAL,
                        evidence=(
                            "secret-like value reaches "
                            "external sink"
                        ),
                        location=path,
                    )
                )

        # New behaviour:
        # secret propagated into a protected write/output sink.
        if (
            leaked_paths
            and tool in sink_rules.protected_tools
        ):
            flags.append(
                "SENSITIVE_DATA_PROPAGATION"
            )

            for _, path in sorted(leaked_paths):
                findings.append(
                    Finding(
                        code="SENSITIVE_DATA_PROPAGATION",
                        severity=FindingSeverity.CRITICAL,
                        evidence=(
                            "secret-like value is propagated "
                            "into a protected sink"
                        ),
                        location=path,
                    )
                )
        # Explicit confidential/restricted data copied to an
    # external destination.
    if (
        explicit_sensitive
        and action
        and is_external_sink(action, sink_rules)
    ):
        params = (
            action.get("params")
            if isinstance(action.get("params"), dict)
            else action
        )

        propagated = False

        for path, text in _walk_strings(params):
            for variant in decode_variants(
                text,
                encoding_rules,
            ):
                candidate_fold = alnum_fold(
                    variant.text
                )

                if len(candidate_fold) < 24:
                    continue

                for source_text in explicit_sensitive:
                    source_fold = alnum_fold(
                        source_text
                    )

                    if len(source_fold) < 24:
                        continue

                    if (
                        source_fold in candidate_fold
                        or candidate_fold in source_fold
                    ):
                        propagated = True

                        findings.append(
                            Finding(
                                code="SENSITIVE_DATA_PROPAGATION",
                                severity=FindingSeverity.CRITICAL,
                                evidence=(
                                    "confidential or restricted "
                                    "content reaches external sink"
                                ),
                                location=path,
                            )
                        )
                        break

                if propagated:
                    break

            if propagated:
                break

        if propagated:
            flags.append(
                "SENSITIVE_DATA_PROPAGATION"
            )            
    if watch_values:
        sensitivity = Sensitivity.SECRET
    elif explicit_sensitive:
        sensitivity = Sensitivity.POSSIBLE_SECRET
    else:
        sensitivity = Sensitivity.NONE
    return DataflowResult(
        tuple(sorted(set(flags))),
        tuple(sorted(findings, key=lambda f: (f.code, f.location, f.evidence))),
        sensitivity,
        watch_values,
    )
