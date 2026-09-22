from __future__ import annotations

from typing import Any

from pydantic import ValidationError

from .action_shape import analyze_action_shape
from .config import Rules, load_rules
from .dataflow import analyze_dataflow
from .digest import action_digest
from .mirroring import analyze_mirroring
from .permissions import check_permissions
from .provenance import resolve_provenance
from .schema import (
    DefenseRequestView,
    Finding,
    FindingSeverity,
    Sensitivity,
    TrustLevel,
    VerifierDetails,
    VerifierResult,
    fail_closed_result,
)


def _source_bundle(req: DefenseRequestView) -> dict[str, Any]:
    return {
        "instruction_source": req.instruction_source or {},
        "records": req.records,
        "user_task": req.user_task or "",
    }


def _merge_findings(*groups: tuple[Finding, ...]) -> tuple[Finding, ...]:
    dedup: dict[tuple[str, str, str, str], Finding] = {}
    for group in groups:
        for finding in group:
            key = (finding.code, finding.severity.value, finding.location, finding.evidence)
            dedup[key] = finding
    return tuple(sorted(dedup.values(), key=lambda f: (f.code, f.location, f.evidence)))


def verify(payload: dict[str, Any] | Any, *, rules: Rules | None = None) -> dict[str, Any]:
    """Verify a request and return a stable JSON-serializable dict.

    This is the only official Part 1 entry point. It never raises to callers.
    """
    action_id = "UNKNOWN_ACTION"
    try:
        if not isinstance(payload, dict):
            return fail_closed_result(reason="request must be an object").model_dump(mode="json")
        action_id = str(payload.get("action_id") or "UNKNOWN_ACTION")
        cfg = rules or load_rules()
        req = DefenseRequestView.model_validate(payload)

        provenance = resolve_provenance(req.instruction_source, req.records, cfg.trust)
        permissions = check_permissions(req.agent_role, req.proposed_action, req.metadata, req.confirmed, cfg.permissions)
        bundle = _source_bundle(req)
        dataflow = analyze_dataflow(bundle, req.proposed_action, cfg.secrets, cfg.sinks, cfg.encoding)
        mirroring = analyze_mirroring(bundle, req.proposed_action, cfg.mirroring, cfg.encoding, cfg.scan)
        shape = analyze_action_shape(req.proposed_action, cfg.action_shape, cfg.sinks, cfg.mirroring)

        flags = set(permissions.flags) | set(dataflow.flags) | set(mirroring.flags) | set(shape.flags)
        findings = list(_merge_findings(permissions.findings, dataflow.findings, mirroring.findings, shape.findings))

        if provenance.trust_level == TrustLevel.UNTRUSTED_EXTERNAL:
            flags.add("UNTRUSTED_SOURCE")
            findings.append(Finding(code="UNTRUSTED_SOURCE", severity=FindingSeverity.MEDIUM, evidence="external provenance", location="instruction_source"))
        elif provenance.trust_level == TrustLevel.UNKNOWN:
            flags.add("UNKNOWN_SOURCE")

        if req.proposed_action is None or req.agent_role is None:
            flags.add("INPUT_INCOMPLETE")

        sensitivity = dataflow.sensitivity
        result = VerifierResult(
            action_id=req.action_id or action_id,
            trust_level=provenance.trust_level,
            trust_basis=provenance.trust_basis,
            permission_ok=permissions.permission_ok,
            structural_flags=tuple(sorted(flags)),
            findings=_merge_findings(tuple(findings)),
            sensitivity=sensitivity,
            details=VerifierDetails(
                action_digest=action_digest(req.proposed_action),
                decoded_variants=mirroring.decoded_variants,
                influence_sources=provenance.influence_sources,
                scan_truncated=len(req.records) > cfg.scan.max_records,
                rules_version=cfg.version,
            ),
        )
        return result.model_dump(mode="json")
    except (ValidationError, ValueError, TypeError, KeyError) as exc:
        return fail_closed_result(action_id=action_id, reason=f"{type(exc).__name__}: {exc}").model_dump(mode="json")
    except Exception as exc:  # defensive fail-closed boundary
        return fail_closed_result(action_id=action_id, reason=f"internal verifier error: {type(exc).__name__}").model_dump(mode="json")
