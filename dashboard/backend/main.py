from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware


# ============================================================
# PATHS
# ============================================================

ROOT = Path(__file__).resolve().parents[2]

PART1_ROOT = ROOT / "part1_verifier"
PART2_ROOT = ROOT / "part2_ml_detection"
PART3_ROOT = ROOT / "part3_decision_engine"

sys.path.insert(0, str(PART1_ROOT))
sys.path.insert(0, str(PART2_ROOT))
sys.path.insert(0, str(PART3_ROOT))


# ============================================================
# PART 2 OFFLINE MODEL CONFIGURATION
# ============================================================

os.environ.setdefault(
    "HF_HOME",
    str(PART2_ROOT / "models" / ".hf"),
)

os.environ.setdefault(
    "HF_HUB_OFFLINE",
    "1",
)

os.environ.setdefault(
    "TRANSFORMERS_OFFLINE",
    "1",
)


# ============================================================
# SENTINEL IMPORTS
# ============================================================

from sentinel_decision.config import load_policy

from sentinel_decision.human import (
    PendingApprover,
    ScriptedApprover,
)

from sentinel_decision.models import HumanResponse

from sentinel_decision.part1_client import (
    InProcessPart1Provider,
)

from sentinel_decision.part2_client import (
    InProcessPart2Provider,
)

from sentinel_decision.pipeline import DecisionPipeline
from sentinel_decision.state import DecisionState
from sentinel_decision.tracelog import TraceLog

from dashboard.backend.review_store import ReviewStore


# ============================================================
# FILE PATHS
# ============================================================

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


# ============================================================
# LOAD SENTINEL
# ============================================================

policy = load_policy(POLICY_PATH)

# Real Part 1
part1_provider = InProcessPart1Provider.from_default()

# Real Part 2
part2_provider = InProcessPart2Provider.from_default()


# ============================================================
# TRACE LOG
# ============================================================

trace_log = TraceLog(
    TRACE_LOG_PATH,
    redact_param_keys=policy.logging.redact_param_keys,
    safe_placeholder=policy.logging.safe_placeholder,
)


# ============================================================
# DECISION STATE
# ============================================================

state = DecisionState.from_policy(policy)


# ============================================================
# HUMAN REVIEW STORE
# ============================================================

review_store = ReviewStore(
    REVIEW_STORE_PATH
)


# ============================================================
# FASTAPI APP
# ============================================================

app = FastAPI(
    title="SENTINEL Dashboard API",
    version="1.0.0",
)


# ============================================================
# CORS
# ============================================================

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


# ============================================================
# PIPELINE FACTORY
# ============================================================

def create_pipeline(approver):
    """
    Create the complete SENTINEL pipeline:

    Part 1
        ↓
    Part 2
        ↓
    Part 3
    """

    return DecisionPipeline(
        policy,
        approver=approver,
        trace_log=trace_log,
        state=state,
        part1_provider=part1_provider,
        part2_provider=part2_provider,
    )


# ============================================================
# TRACE HELPERS
# ============================================================

def read_trace() -> list[dict[str, Any]]:
    return trace_log.read()


# ============================================================
# HEALTH
# ============================================================

@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "service": "sentinel-dashboard",
        "trace_log_exists": TRACE_LOG_PATH.exists(),
        "part1_enabled": True,
        "part2_enabled": True,
        "part3_enabled": True,
        "part2_offline": (
            os.environ.get("HF_HUB_OFFLINE") == "1"
        ),
    }


# ============================================================
# AUDIT LOG INTEGRITY
# ============================================================

@app.get("/api/integrity")
def integrity():
    valid, message = trace_log.verify()

    return {
        "valid": valid,
        "status": (
            "VALID"
            if valid
            else "TAMPERED"
        ),
        "message": message,
    }


# ============================================================
# DECISIONS
# ============================================================

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

        # Support both:
        #
        # old flat format:
        # {
        #   "trust_level": ...
        # }
        #
        # and new real pipeline format:
        # {
        #   "part1": {...},
        #   "part2": {...}
        # }

        part1 = input_data.get(
            "part1",
            {},
        )

        if not isinstance(part1, dict):
            part1 = {}

        part2 = input_data.get(
            "part2",
            {},
        )

        if not isinstance(part2, dict):
            part2 = {}

        trust_level = (
            part1.get("trust_level")
            if part1
            else input_data.get("trust_level")
        )

        permission_ok = (
            part1.get("permission_ok")
            if part1
            else input_data.get("permission_ok")
        )

        structural_flags = (
            part1.get(
                "structural_flags",
                [],
            )
            if part1
            else input_data.get(
                "structural_flags",
                [],
            )
        )

        ml_confidence = (
            part2.get("ml_confidence")
            if part2
            else input_data.get("ml_confidence")
        )

        semantic_similarity = (
            part2.get(
                "semantic_similarity"
            )
            if part2
            else input_data.get(
                "semantic_similarity"
            )
        )

        content_flags = (
            part2.get(
                "content_flags",
                [],
            )
            if part2
            else input_data.get(
                "content_flags",
                [],
            )
        )

        result.append(
            {
                "seq": record.get("seq"),

                "timestamp": record.get(
                    "timestamp"
                ),

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

                # Part 1
                "trust_level": trust_level,

                "permission_ok": permission_ok,

                "structural_flags":
                    structural_flags,

                # Part 2
                "ml_confidence":
                    ml_confidence,

                "semantic_similarity":
                    semantic_similarity,

                "content_flags":
                    content_flags,

                # Additional useful Part 1 info
                "trust_basis": part1.get(
                    "trust_basis",
                    [],
                ),

                "sensitivity": part1.get(
                    "sensitivity"
                ),

                "findings": part1.get(
                    "findings",
                    [],
                ),

                # Additional Part 2 info
                "ml_label": part2.get(
                    "ml_label"
                ),
            }
        )

    return result


# ============================================================
# DASHBOARD STATS
# ============================================================

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
            sum(scores)
            / len(scores),
            1,
        )
        if scores
        else 0
    )

    return {
        "total": len(records),

        "allow":
            counts["ALLOW"],

        "rewrite":
            counts["REWRITE"],

        "escalate":
            counts["ESCALATE"],

        "block":
            counts["BLOCK"],

        "average_risk":
            average_risk,
    }


# ============================================================
# REAL SENTINEL EVALUATION
# ============================================================

@app.post("/api/evaluate")
def evaluate(
    proposal: dict[str, Any],
):

    # Human review stays pending
    # when Part 3 returns ESCALATE.

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
        verdict.outcome.value
        == "ESCALATE"
        and
        verdict.human_response
        is HumanResponse.PENDING
    ):

        review_store.add(
            verdict.action_id,
            proposal,
            result,
        )

    return result


# ============================================================
# DEMO SCENARIOS
# ============================================================

DEMO_SCENARIOS = {
    "safe":
        PART3_ROOT
        / "samples"
        / "proposals"
        / "clean.json",

    "suspicious":
        PART3_ROOT
        / "samples"
        / "proposals"
        / "mixed.json",

    "malicious":
        PART3_ROOT
        / "samples"
        / "proposals"
        / "bad.json",
}


@app.post("/api/demo/{scenario}")
def run_demo_scenario(
    scenario: str,
):

    scenario = scenario.lower()

    path = DEMO_SCENARIOS.get(
        scenario
    )

    if path is None:
        raise HTTPException(
            status_code=404,
            detail="Unknown demo scenario",
        )

    if not path.exists():
        raise HTTPException(
            status_code=500,
            detail=(
                "Scenario file not found: "
                f"{path.name}"
            ),
        )

    proposal = json.loads(
        path.read_text(
            encoding="utf-8"
        )
    )

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
        verdict.outcome.value
        == "ESCALATE"
        and
        verdict.human_response
        is HumanResponse.PENDING
    ):

        review_store.add(
            verdict.action_id,
            proposal,
            result,
        )

    return {
        "scenario": scenario,
        "verdict": result,
    }


# ============================================================
# HUMAN REVIEW LIST
# ============================================================

@app.get("/api/reviews")
def reviews():

    return review_store.list()


# ============================================================
# HUMAN REVIEW RESOLUTION
# ============================================================

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
            detail=(
                "Pending review not found"
            ),
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


# ============================================================
# APPROVE
# ============================================================

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


# ============================================================
# DENY
# ============================================================

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