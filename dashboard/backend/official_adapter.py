from __future__ import annotations

import hashlib
import json
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


# ============================================================
# OFFICIAL SENTINEL API MODELS
# ============================================================


class _Lenient(BaseModel):
    model_config = ConfigDict(extra="ignore")


class CandidateAction(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal[
        "respond",
        "tool_call",
        "memory_write",
        "request_confirmation",
    ]

    tool: str | None = None

    arguments: dict[
        str,
        str | int | float | bool | None
    ] = Field(default_factory=dict)

    content: str | None = None
    final: bool = False

    confirmation_for: CandidateAction | None = None

    def digest(self) -> str:
        def canonical(value: object) -> object:
            if isinstance(value, str):
                return " ".join(value.split())

            if (
                isinstance(value, float)
                and value.is_integer()
            ):
                return int(value)

            return value

        payload: dict[str, object] = {
            "type": self.type,
            "tool": self.tool,
            "arguments": {
                key: canonical(value)
                for key, value
                in sorted(self.arguments.items())
            },
            "content":
                self.content
                if self.type != "tool_call"
                else None,
        }

        if self.confirmation_for is not None:
            payload["confirmation_for"] = (
                self.confirmation_for.digest()
            )

        encoded = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()

        return hashlib.sha256(
            encoded
        ).hexdigest()[:24]


class Provenance(_Lenient):
    source_type: str
    source_id: str

    trust_level: Literal[
        "system_policy",
        "authenticated_user",
        "trusted_internal",
        "untrusted_internal",
        "untrusted_external",
        "adversary_controlled",
    ]

    origin_actor: str
    retrieved_via: str

    sensitivity: Literal[
        "public",
        "internal",
        "confidential",
        "restricted",
    ] = "internal"


class ProvenanceRecord(_Lenient):
    id: str
    provenance: Provenance


class ConversationItem(_Lenient):
    role: str
    kind: str
    content: str
    provenance_ids: list[str] = Field(
        default_factory=list
    )


class ObservationView(_Lenient):
    kind: str
    content: str
    provenance_ids: list[str] = Field(
        default_factory=list
    )


class HistoryDigest(_Lenient):
    steps_taken: int = 0
    turn_index: int = 0

    tool_calls: list[dict[str, Any]] = Field(
        default_factory=list
    )

    confirmations_granted: list[str] = Field(
        default_factory=list
    )

    blocked_count: int = 0
    escalated_count: int = 0

    least_trusted_seen: str | None = None
    most_sensitive_seen: str | None = None


class OfficialDefenseRequest(_Lenient):
    run_id: str
    step_id: int
    user_goal: str

    conversation: list[ConversationItem] = Field(
        default_factory=list
    )

    observation: ObservationView | None = None

    candidate_action: CandidateAction

    policy_context: dict[str, Any] = Field(
        default_factory=dict
    )

    provenance: list[ProvenanceRecord] = Field(
        default_factory=list
    )

    history_digest: HistoryDigest = Field(
        default_factory=HistoryDigest
    )


class OfficialDefenseDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: Literal[
        "allow",
        "block",
        "escalate",
        "rewrite",
    ]

    risk_score: float = Field(
        ge=0.0,
        le=1.0,
    )

    confidence: float = Field(
        ge=0.0,
        le=1.0,
    )

    reason_codes: list[str] = Field(
        default_factory=list,
        max_length=16,
    )

    explanation: str | None = Field(
        default=None,
        max_length=500,
    )

    rewritten_action: CandidateAction | None = None

    metadata: dict[str, Any] = Field(
        default_factory=dict
    )

    @model_validator(mode="after")
    def validate_rewrite(self):
        if (
            self.decision == "rewrite"
        ) != (
            self.rewritten_action is not None
        ):
            raise ValueError(
                "rewritten_action is required "
                "only for rewrite"
            )

        return self


# ============================================================
# ADAPTER HELPERS
# ============================================================


def _provenance_map(
    request: OfficialDefenseRequest,
) -> dict[str, Provenance]:

    return {
        record.id: record.provenance
        for record in request.provenance
    }


def _relevant_provenance(
    request: OfficialDefenseRequest,
) -> Provenance | None:

    provenance = _provenance_map(request)

    # Prefer provenance of the current observation.
    if request.observation:

        for pid in request.observation.provenance_ids:
            if pid in provenance:
                return provenance[pid]

    # Otherwise use the latest conversation provenance.
    for item in reversed(request.conversation):

        for pid in item.provenance_ids:
            if pid in provenance:
                return provenance[pid]

    return None


def _instruction_content(
    request: OfficialDefenseRequest,
) -> str:

    parts: list[str] = []

    if (
        request.observation
        and request.observation.content
    ):
        parts.append(
            request.observation.content
        )

    # Keep recent context for multi-step attacks.
    for item in request.conversation[-12:]:

        text = item.content.strip()

        if text and text not in parts:
            parts.append(text)

    return "\n\n".join(parts)

def _candidate_matches_user_goal(
    request: OfficialDefenseRequest,
) -> bool:
    action = request.candidate_action

    if action.type != "tool_call":
        return False

    goal = request.user_goal.lower()

    # Use textual parameters such as search queries/document IDs.
    values = [
        str(value).lower().strip()
        for value in action.arguments.values()
        if isinstance(value, str)
    ]

    for value in values:
        words = [
            word
            for word in value.replace("-", " ").split()
            if len(word) >= 4
        ]

        if words and all(word in goal for word in words):
            return True

    return False
def _instruction_source(
    request: OfficialDefenseRequest,
) -> dict[str, Any]:

    provenance = _relevant_provenance(
        request
    )

    content = _instruction_content(
        request
    )
    # If the candidate action is clearly requested by the authenticated
# user's goal, do not incorrectly attribute it to the last document read.
    if _candidate_matches_user_goal(request):
        return {
            "type": "user",
            "content": request.user_goal,
            "source_id": "user_goal",
            "official_trust_level": "authenticated_user",
            "sensitivity": "internal",
        }

    if provenance is None:
        return {
            "type": "user",
            "content": request.user_goal,
            "source_id": "user_goal",
            "official_trust_level": "authenticated_user",
            "sensitivity": "internal",
        }

    trust_type_map = {
        "system_policy": "system",
        "authenticated_user": "user",
        "trusted_internal": "internal_tool",
        "untrusted_internal": "document",
        "untrusted_external": "external_document",
        "adversary_controlled": "external_document",
    }

    return {
        "type": trust_type_map.get(
            provenance.trust_level,
            provenance.source_type,
        ),
        "sender": provenance.origin_actor,
        "author": provenance.origin_actor,
        "source_id": provenance.source_id,
        "content": content,
        "official_trust_level":
            provenance.trust_level,
        "sensitivity":
            provenance.sensitivity,
    }


def _records(
    request: OfficialDefenseRequest,
) -> list[dict[str, Any]]:

    provenance = _provenance_map(
        request
    )

    records: list[dict[str, Any]] = []

    for index, item in enumerate(
        request.conversation
    ):

        record: dict[str, Any] = {
            "id": f"conversation-{index}",
            "type": item.kind,
            "role": item.role,
            "content": item.content,
        }

        if item.provenance_ids:

            prov = provenance.get(
                item.provenance_ids[0]
            )

            if prov is not None:

                record.update(
                    {
                        "source_type":
                            prov.source_type,
                        "author":
                            prov.origin_actor,
                        "trust_level":
                            prov.trust_level,
                        "sensitivity":
                            prov.sensitivity,
                    }
                )

        records.append(record)

    return records


def _action_description(
    action: CandidateAction,
) -> str:

    if action.type == "tool_call":

        return (
            f"{action.tool} "
            f"{json.dumps(action.arguments, sort_keys=True)}"
        )

    if action.type == "respond":
        return f"respond {action.content or ''}"

    if action.type == "memory_write":
        return (
            f"write_memory "
            f"{action.content or ''}"
        )

    if (
        action.type == "request_confirmation"
        and action.confirmation_for
    ):
        return (
            "request human confirmation for "
            + _action_description(
                action.confirmation_for
            )
        )

    return action.type


def _internal_action(
    action: CandidateAction,
) -> dict[str, Any]:

    if action.type == "tool_call":

        return {
            "tool": action.tool or "unknown_tool",
            "params": dict(action.arguments),
        }

    if action.type == "memory_write":

        return {
            "tool": "write_memory",
            "params": {
                "content": action.content or ""
            },
        }

    if action.type == "respond":

        return {
            "tool": "respond",
            "params": {
                "content": action.content or ""
            },
        }

    if (
        action.type == "request_confirmation"
        and action.confirmation_for
    ):

        return {
            "tool": "request_confirmation",
            "params": {
                "for":
                    _action_description(
                        action.confirmation_for
                    )
            },
        }

    return {
        "tool": "unknown_action",
        "params": {},
    }


def build_internal_proposal(
    request: OfficialDefenseRequest,
) -> dict[str, Any]:

    action_id = (
        f"{request.run_id}-"
        f"step-{request.step_id}"
    )

    candidate = request.candidate_action

    confirmed = (
        candidate.digest()
        in request.history_digest.confirmations_granted
    )

    return {
        "action_id": action_id,

        "user_task":
            request.user_goal,

        "proposed_action_description":
            _action_description(candidate),

        "instruction_content":
            _instruction_content(request),

        "proposed_action":
            _internal_action(candidate),

        "instruction_source":
            _instruction_source(request),

        "records":
            _records(request),

        "agent_role":
            "sentinel_official_agent",

        "confirmed":
            confirmed,

        "metadata": {
            "official_run_id":
                request.run_id,

            "official_step_id":
                request.step_id,

            "candidate_type":
                candidate.type,

            "policy_context":
                request.policy_context,

            "history_digest":
                request.history_digest.model_dump(
                    mode="json"
                ),
        },
    }