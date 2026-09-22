from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .config import PermissionRules
from .schema import Finding, FindingSeverity


@dataclass(frozen=True)
class PermissionResult:
    permission_ok: bool | None
    flags: tuple[str, ...]
    findings: tuple[Finding, ...]


def check_permissions(
    role: str | None,
    action: dict[str, Any] | None,
    metadata: dict[str, Any],
    confirmed: bool | None,
    rules: PermissionRules,
) -> PermissionResult:
    if not action or not isinstance(action, dict):
        return PermissionResult(None, ("INPUT_INCOMPLETE",), ())

    tool = str(action.get("tool") or action.get("action") or "").strip()
    if not tool or not role:
        return PermissionResult(None, ("INPUT_INCOMPLETE",), ())

    role_rules = rules.roles.get(role)
    if role_rules is None:
        if rules.unknown_role_policy == "deny":
            finding = Finding(code="UNKNOWN_ROLE", severity=FindingSeverity.HIGH, evidence=role, location="agent_role")
            return PermissionResult(False, ("TOOL_NOT_ALLOWED",), (finding,))
        return PermissionResult(None, (), ())

    flags: list[str] = []
    findings: list[Finding] = []
    ok = True

    if tool not in role_rules.allowed_tools:
        ok = False
        flags.append("TOOL_NOT_ALLOWED")
        findings.append(Finding(code="TOOL_NOT_ALLOWED", severity=FindingSeverity.HIGH, evidence=tool, location="proposed_action.tool"))

    prereqs = role_rules.prerequisites.get(tool, [])
    for prereq in prereqs:
        available = metadata.get(prereq)
        if not bool(available):
            ok = False
            flags.append("MISSING_PREREQUISITE")
            findings.append(Finding(code="MISSING_PREREQUISITE", severity=FindingSeverity.HIGH, evidence=prereq, location="metadata"))

    if tool in role_rules.confirmation_required and confirmed is not True:
        ok = False
        flags.append("CONFIRMATION_REQUIRED")
        findings.append(Finding(code="CONFIRMATION_REQUIRED", severity=FindingSeverity.MEDIUM, evidence=tool, location="confirmed"))

    return PermissionResult(ok, tuple(sorted(set(flags))), tuple(sorted(findings, key=lambda f: (f.code, f.evidence))))
