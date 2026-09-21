from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from .config import Policy
from .enforcement import EnforcementGate
from .engine import DecisionEngine
from .human import Approver, DenyAllApprover
from .models import (
    Action,
    ActionLifecycle,
    HumanCase,
    HumanResponse,
    Outcome,
    Verdict,
)
from .part2_client import Part2Provider
from .rewriter import rewrite_action
from .signals import parse_proposal
from .state import DecisionState
from .tracelog import TraceLog


class DecisionPipeline:
    def __init__(
        self,
        policy: Policy,
        *,
        approver: Approver | None = None,
        gate: EnforcementGate | None = None,
        trace_log: TraceLog | None = None,
        state: DecisionState | None = None,
        part2_provider: Part2Provider | None = None,
    ):
        self.policy = policy
        self.engine = DecisionEngine(policy)
        self.approver = approver or DenyAllApprover()
        self.gate = gate or EnforcementGate()
        self.state = state or DecisionState.from_policy(policy)
        self.part2_provider = part2_provider
        self.trace_log = trace_log or TraceLog(
        Path(policy.logging.path),
        redact_param_keys=policy.logging.redact_param_keys,
        safe_placeholder=policy.logging.safe_placeholder,
        )

    @staticmethod
    def _needs_part2(raw: dict[str, Any]) -> bool:
        if isinstance(raw.get("part2"), dict):
            p2 = raw["part2"]
            return not all(k in p2 for k in ("ml_confidence", "semantic_similarity"))
        return not all(k in raw for k in ("ml_confidence", "semantic_similarity"))

    @staticmethod
    def _part2_input(raw: dict[str, Any]) -> dict[str, Any]:
        if isinstance(raw.get("part2_input"), dict):
            return dict(raw["part2_input"])
        keys = (
            "action_id",
            "user_task",
            "proposed_action_description",
            "instruction_content",
        )
        return {k: raw[k] for k in keys if k in raw}

    def _attach_part2(self, raw: dict[str, Any]) -> dict[str, Any]:
        if self.part2_provider is None or not self._needs_part2(raw):
            return raw
        merged = dict(raw)
        p2 = self.part2_provider.analyze(self._part2_input(raw))
        merged["part2"] = p2
        return merged

    def _log(self, raw: dict[str, Any], verdict: Verdict) -> None:
        # Log all decision inputs and final output. Do not include execution permits.
        self.trace_log.append(
            {
                "action_id": verdict.action_id,
                "input": raw,
                "verdict": verdict.model_dump(mode="json"),
            }
        )

    def run(
        self,
        proposal: dict[str, Any],
        *,
        executor: Callable[[Action], Any] | None = None,
    ) -> Verdict:
        raw = dict(proposal) if isinstance(proposal, dict) else {}

        try:
            raw = self._attach_part2(raw)
            parsed = parse_proposal(raw)
        except Exception as exc:
            verdict = Verdict(
                action_id=str(raw.get("action_id", "UNKNOWN_ACTION")),
                risk_score=100,
                outcome=Outcome.BLOCK,
                reason_codes=["INVALID_INPUT"],
                explanation=f"Input parsing failed closed: {type(exc).__name__}.",
                policy_version=self.policy.version,
            )
            self.state.record(verdict, ActionLifecycle.BLOCKED)
            self._log(raw, verdict)
            return verdict

        signals = parsed.combined
        self.state.set_lifecycle(signals.action_id, ActionLifecycle.PROPOSED)
        verdict = self.engine.evaluate(signals, self.state)

        if verdict.outcome is Outcome.REWRITE:
            verdict.rewrite = rewrite_action(signals.action, self.policy)
            verdict.executed = False
            self.state.record(verdict, ActionLifecycle.REWRITE_REQUIRED)
            self._log(raw, verdict)
            return verdict

        if verdict.outcome is Outcome.BLOCK:
            verdict.executed = False
            self.state.record(verdict, ActionLifecycle.BLOCKED)
            self._log(raw, verdict)
            return verdict

        if verdict.outcome is Outcome.ESCALATE:
            self.state.set_lifecycle(signals.action_id, ActionLifecycle.ESCALATED)
            case = HumanCase(
                action_id=signals.action_id,
                risk_score=verdict.risk_score,
                proposed_outcome=verdict.outcome,
                reason_codes=verdict.reason_codes,
                explanation=verdict.explanation,
                action=signals.action,
            )
            response = self.approver.review(case)
            verdict.human_response = response

            if response is HumanResponse.PENDING:
                verdict.executed = False

                self.state.record(
                    verdict,
                    ActionLifecycle.ESCALATED,
                )

                self._log(raw, verdict)
                return verdict

            
            if response is not HumanResponse.APPROVED:
                verdict.executed = False
                verdict.reason_codes = list(dict.fromkeys(verdict.reason_codes + ["HUMAN_DENIED"]))
                self.state.record(verdict, ActionLifecycle.DENIED)
                self._log(raw, verdict)
                return verdict
            self.state.set_lifecycle(signals.action_id, ActionLifecycle.APPROVED)

        if executor is None or signals.action is None:
            verdict.executed = False
            self.state.record(verdict, ActionLifecycle.APPROVED)
            self._log(raw, verdict)
            return verdict

        permit = self.gate.issue_permit(verdict, signals.action)
        if permit is None:
            verdict.executed = False
            verdict.reason_codes = list(dict.fromkeys(verdict.reason_codes + ["ENFORCEMENT_DENIED"]))
            self.state.record(verdict, ActionLifecycle.DENIED)
            self._log(raw, verdict)
            return verdict

        try:
            verdict.executor_result = self.gate.execute(permit, signals.action, executor)
            verdict.executed = True
            self.state.record(verdict, ActionLifecycle.EXECUTED)
        except Exception as exc:
            verdict.executed = False
            verdict.reason_codes = list(dict.fromkeys(verdict.reason_codes + ["EXECUTOR_ERROR"]))
            verdict.explanation += f" Executor failed: {type(exc).__name__}."
            self.state.record(verdict, ActionLifecycle.FAILED)

        self._log(raw, verdict)
        return verdict
