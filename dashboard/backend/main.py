from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware


ROOT = Path(__file__).resolve().parents[2]

PART3_ROOT = ROOT / "part3_decision_engine"

sys.path.insert(
    0,
    str(PART3_ROOT),
)


from sentinel_decision.config import load_policy
from sentinel_decision.human import (
    PendingApprover,
    ScriptedApprover,
)
from sentinel_decision.models import HumanResponse
from sentinel_decision.pipeline import DecisionPipeline
from sentinel_decision.state import DecisionState
from sentinel_decision.tracelog import TraceLog

from dashboard.backend.review_store import ReviewStore


POLICY_PATH = (
    PART3_ROOT
    / "config"
    / "policy.yaml"
)

TRACE_LOG_PATH = (
    PART3_ROOT
    / "logs"
    / "trace.jsonl"
)

REVIEW_STORE_PATH = (
    ROOT
    / "dashboard"
    / "backend"
    / "data"
    / "pending_reviews.json"
)


policy = load_policy(POLICY_PATH)

trace_log = TraceLog(
    TRACE_LOG_PATH,
    redact_param_keys=policy.logging.redact_param_keys,
    safe_placeholder=policy.logging.safe_placeholder,
)

state = DecisionState.from_policy(policy)

review_store = ReviewStore(
    REVIEW_STORE_PATH
)


app = FastAPI(
    title="SENTINEL Dashboard API",
    version="1.0.0",
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def create_pipeline(approver):
    return DecisionPipeline(
        policy,
        approver=approver,
        trace_log=trace_log,
        state=state,
    )


def read_trace() -> list[dict[str, Any]]:
    return trace_log.read()


@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "service": "sentinel-dashboard",
        "trace_log_exists": TRACE_LOG_PATH.exists(),
    }
@app.get("/api/integrity")
def integrity():
    valid, message = trace_log.verify()

    return {
        "valid": valid,
        "status": "VALID" if valid else "TAMPERED",
        "message": message,
    }

@app.get("/api/decisions")
def decisions():
    records = read_trace()

    result = []

    for record in reversed(records):

        event = record.get(
            "event",
            {},
        )

        verdict = event.get(
            "verdict",
            {},
        )

        input_data = event.get(
            "input",
            {},
        )

        result.append(
            {
                "seq": record.get("seq"),
                "timestamp": record.get("timestamp"),

                "action_id": verdict.get(
                    "action_id",
                    event.get("action_id"),
                ),

                "risk_score": verdict.get(
                    "risk_score",
                    0,
                ),

                "outcome": verdict.get(
                    "outcome"
                ),

                "human_response": verdict.get(
                    "human_response"
                ),

                "executed": verdict.get(
                    "executed",
                    False,
                ),

                "reason_codes": verdict.get(
                    "reason_codes",
                    [],
                ),

                "explanation": verdict.get(
                    "explanation",
                    "",
                ),

                "trust_level": input_data.get(
                    "trust_level"
                ),

                "permission_ok": input_data.get(
                    "permission_ok"
                ),

                "ml_confidence": input_data.get(
                    "ml_confidence"
                ),

                "semantic_similarity": input_data.get(
                    "semantic_similarity"
                ),

                "structural_flags": input_data.get(
                    "structural_flags",
                    [],
                ),

                "content_flags": input_data.get(
                    "content_flags",
                    [],
                ),
            }
        )

    return result


@app.get("/api/stats")
def stats():
    records = read_trace()

    counts = {
        "ALLOW": 0,
        "REWRITE": 0,
        "ESCALATE": 0,
        "BLOCK": 0,
    }

    scores = []

    for record in records:

        verdict = (
            record
            .get("event", {})
            .get("verdict", {})
        )

        outcome = verdict.get(
            "outcome"
        )

        if outcome in counts:
            counts[outcome] += 1

        score = verdict.get(
            "risk_score"
        )

        if isinstance(
            score,
            (int, float),
        ):
            scores.append(score)

    average_risk = (
        round(
            sum(scores) / len(scores),
            1,
        )
        if scores
        else 0
    )

    return {
        "total": len(records),
        "allow": counts["ALLOW"],
        "rewrite": counts["REWRITE"],
        "escalate": counts["ESCALATE"],
        "block": counts["BLOCK"],
        "average_risk": average_risk,
    }


@app.post("/api/evaluate")
def evaluate(
    proposal: dict[str, Any],
):
    pipeline = create_pipeline(
        PendingApprover()
    )

    verdict = pipeline.run(
        proposal
    )

    result = verdict.model_dump(
        mode="json"
    )

    if (
        verdict.outcome.value == "ESCALATE"
        and verdict.human_response
        is HumanResponse.PENDING
    ):
        review_store.add(
            verdict.action_id,
            proposal,
            result,
        )

    return result


@app.get("/api/reviews")
def reviews():
    return review_store.list()


def resolve_review(
    action_id: str,
    response: HumanResponse,
):

    pending = review_store.get(
        action_id
    )

    if pending is None:
        raise HTTPException(
            status_code=404,
            detail="Pending review not found",
        )

    proposal = pending[
        "proposal"
    ]

    pipeline = create_pipeline(
        ScriptedApprover(
            [response]
        )
    )

    verdict = pipeline.run(
        proposal
    )

    review_store.remove(
        action_id
    )

    return verdict.model_dump(
        mode="json"
    )


@app.post(
    "/api/reviews/{action_id}/approve"
)
def approve_review(
    action_id: str,
):
    return resolve_review(
        action_id,
        HumanResponse.APPROVED,
    )


@app.post(
    "/api/reviews/{action_id}/deny"
)
def deny_review(
    action_id: str,
):
    return resolve_review(
        action_id,
        HumanResponse.DENIED,
    )