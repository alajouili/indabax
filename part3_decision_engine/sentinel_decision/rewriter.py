from __future__ import annotations

from copy import deepcopy
from typing import Any

from .config import Policy
from .models import Action, RewriteResult


def _looks_external(value: Any) -> bool:
    text = str(value).lower()
    return "@" in text or text.startswith(("http://", "https://")) or "external" in text


def rewrite_action(action: Action | None, policy: Policy) -> RewriteResult:
    """Create a deterministic safer proposal.

    The rewritten action is NEVER considered executable directly. It must be
    submitted again through the complete SENTINEL pipeline.
    """
    if action is None or not policy.rewrite.enabled:
        return RewriteResult(
            original_action=action,
            rewritten_action=None,
            requirements=list(policy.rewrite.requirements),
            requires_reevaluation=True,
        )

    params = deepcopy(action.params)
    redacted_keys = {k.lower() for k in policy.rewrite.redact_param_keys}
    recipient_keys = {k.lower() for k in policy.rewrite.external_recipient_keys}

    for key in list(params):
        lowered = key.lower()
        if lowered in redacted_keys:
            params[key] = policy.rewrite.safe_placeholder
        elif lowered in recipient_keys and _looks_external(params[key]):
            params[key] = policy.rewrite.safe_placeholder

    rewritten = Action(tool=action.tool, params=params)
    return RewriteResult(
        original_action=action,
        rewritten_action=rewritten,
        requirements=list(policy.rewrite.requirements),
        requires_reevaluation=True,
    )
