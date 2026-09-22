from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from .config import ActionShapeRules, MirroringRules, SinkRules
from .dataflow import is_external_sink
from .schema import Finding, FindingSeverity


@dataclass(frozen=True)
class ActionShapeResult:
    flags: tuple[str, ...]
    findings: tuple[Finding, ...]


def analyze_action_shape(
    action: dict[str, Any] | None,
    shape_rules: ActionShapeRules,
    sink_rules: SinkRules,
    mirroring_rules: MirroringRules,
) -> ActionShapeResult:
    if not action:
        return ActionShapeResult(("INPUT_INCOMPLETE",), ())

    tool = str(action.get("tool") or action.get("action") or "")
    flags: list[str] = []
    findings: list[Finding] = []

    if tool in shape_rules.consequential_tools:
        flags.append("CONSEQUENTIAL_ACTION")
        findings.append(Finding(code="CONSEQUENTIAL_ACTION", severity=FindingSeverity.MEDIUM, evidence=tool, location="proposed_action.tool"))
    if tool in shape_rules.control_change_tools:
        flags.append("CONTROL_CHANGE")
        findings.append(Finding(code="CONTROL_CHANGE", severity=FindingSeverity.HIGH, evidence=tool, location="proposed_action.tool"))
    if tool in shape_rules.memory_write_tools:
        flags.append("MEMORY_WRITE")
        findings.append(Finding(code="MEMORY_WRITE", severity=FindingSeverity.MEDIUM, evidence=tool, location="proposed_action.tool"))
    if is_external_sink(action, sink_rules):
        flags.append("EXTERNAL_RECIPIENT")
        findings.append(Finding(code="EXTERNAL_RECIPIENT", severity=FindingSeverity.MEDIUM, evidence=tool, location="proposed_action"))

    text = str(action.get("description") or "")
    if any(re.search(pattern, text) for pattern in mirroring_rules.authority_patterns):
        flags.append("AUTHORITY_CLAIM")
        findings.append(Finding(code="AUTHORITY_CLAIM", severity=FindingSeverity.MEDIUM, evidence="authority claim in action description", location="proposed_action.description"))

    return ActionShapeResult(tuple(sorted(set(flags))), tuple(sorted(findings, key=lambda f: (f.code, f.location))))
