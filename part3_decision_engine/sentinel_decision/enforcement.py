from __future__ import annotations

from dataclasses import dataclass
from secrets import token_urlsafe
from typing import Any, Callable

from .models import Action, HumanResponse, Outcome, Verdict


@dataclass(frozen=True)
class ExecutionPermit:
    action_id: str
    token: str


class EnforcementGate:
    """The sole supported path from a SENTINEL verdict to an executor."""

    def __init__(self):
        self._issued: dict[str, str] = {}

    @staticmethod
    def may_execute(verdict: Verdict) -> bool:
        if verdict.outcome is Outcome.ALLOW:
            return True
        if verdict.outcome is Outcome.ESCALATE and verdict.human_response is HumanResponse.APPROVED:
            return True
        return False

    def issue_permit(self, verdict: Verdict, action: Action | None) -> ExecutionPermit | None:
        if action is None or not self.may_execute(verdict):
            return None
        token = token_urlsafe(24)
        self._issued[verdict.action_id] = token
        return ExecutionPermit(action_id=verdict.action_id, token=token)

    def execute(
        self,
        permit: ExecutionPermit | None,
        action: Action | None,
        executor: Callable[[Action], Any],
    ) -> Any:
        if permit is None or action is None:
            raise PermissionError("execution denied: no valid permit")
        expected = self._issued.pop(permit.action_id, None)
        if expected is None or expected != permit.token:
            raise PermissionError("execution denied: invalid or already-used permit")
        return executor(action)
