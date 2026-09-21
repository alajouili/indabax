from __future__ import annotations

from dataclasses import dataclass

from .config import Policy
from .models import Action


@dataclass(frozen=True)
class ActionClassification:
    category: str
    impact: int


def classify_action(action: Action | None, policy: Policy) -> ActionClassification:
    if action is None:
        return ActionClassification(category="unknown", impact=0)

    tool = action.tool.lower().strip()
    for category, spec in policy.categories.items():
        if tool in {t.lower() for t in spec.tools}:
            return ActionClassification(category=category, impact=spec.impact)
    return ActionClassification(category="unknown", impact=0)
