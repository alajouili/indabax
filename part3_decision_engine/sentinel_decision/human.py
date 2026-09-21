from __future__ import annotations

from collections import deque
from typing import Protocol

from .models import HumanCase, HumanResponse


class Approver(Protocol):
    def review(self, case: HumanCase) -> HumanResponse: ...


class CLIApprover:
    def review(self, case: HumanCase) -> HumanResponse:
        print("\n=== SENTINEL HUMAN REVIEW ===")
        print(f"Action: {case.action_id}")
        print(f"Risk: {case.risk_score}/100")
        print(f"Reasons: {', '.join(case.reason_codes) or 'none'}")
        print(case.explanation)
        answer = input("Approve action? [y/N]: ").strip().lower()
        return HumanResponse.APPROVED if answer in {"y", "yes"} else HumanResponse.DENIED


class ScriptedApprover:
    """Deterministic approver used by tests and reproducible demos."""

    def __init__(self, responses: list[HumanResponse | str]):
        self._responses = deque(HumanResponse(r) for r in responses)

    def review(self, case: HumanCase) -> HumanResponse:
        if not self._responses:
            return HumanResponse.DENIED
        return self._responses.popleft()


class DenyAllApprover:
    def review(self, case: HumanCase) -> HumanResponse:
        return HumanResponse.DENIED


class ApproveAllApprover:
    def review(self, case: HumanCase) -> HumanResponse:
        return HumanResponse.APPROVED
class PendingApprover:
    """Used by the web dashboard.

    It does not approve or deny immediately.
    It leaves the action waiting for human review.
    """

    def review(self, case: HumanCase) -> HumanResponse:
        return HumanResponse.PENDING