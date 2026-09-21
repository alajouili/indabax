from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

from .config import Policy
from .models import ActionLifecycle, Outcome, Verdict


@dataclass
class StateEvent:
    action_id: str
    risk_score: int
    outcome: Outcome
    lifecycle: ActionLifecycle
    reason_codes: tuple[str, ...] = ()


@dataclass
class DecisionState:
    """In-memory per-run/session evidence used to expose multi-step accumulation."""

    max_history: int = 100
    history: deque[StateEvent] = field(default_factory=deque)
    lifecycle: dict[str, ActionLifecycle] = field(default_factory=dict)

    @classmethod
    def from_policy(cls, policy: Policy) -> "DecisionState":
        return cls(max_history=policy.state.max_history)

    def suspicious_events(self) -> int:
        return sum(
            1
            for event in self.history
            if event.outcome in {Outcome.REWRITE, Outcome.ESCALATE, Outcome.BLOCK}
        )

    def session_risk_points(self, policy: Policy) -> float:
        points = self.suspicious_events() * policy.state.suspicious_event_points
        return min(policy.state.max_session_points, points)

    def set_lifecycle(self, action_id: str, status: ActionLifecycle) -> None:
        self.lifecycle[action_id] = status

    def record(self, verdict: Verdict, lifecycle: ActionLifecycle) -> None:
        self.lifecycle[verdict.action_id] = lifecycle
        self.history.append(
            StateEvent(
                action_id=verdict.action_id,
                risk_score=verdict.risk_score,
                outcome=verdict.outcome,
                lifecycle=lifecycle,
                reason_codes=tuple(verdict.reason_codes),
            )
        )
        while len(self.history) > self.max_history:
            self.history.popleft()
