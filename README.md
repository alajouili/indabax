SENTINEL

SENTINEL is an AI-agent security system designed to analyze proposed actions before execution.

It combines deterministic security signals, machine-learning detection, explainable risk scoring, human validation, enforcement controls, and tamper-evident audit logging.

The project was developed for IndabaX Tunisia.

1. Problem

Enterprise AI agents may receive instructions from users, emails, documents, wikis, tickets, or other external content. Some of these instructions may contain prompt injection, malicious instructions, permission violations, credential exfiltration attempts, semantic drift, poisoned context, or indirect injection.

SENTINEL analyzes the proposed action before allowing it to execute.

2. Architecture

                Incoming Instruction
                        |
                        v
        +-------------------------------+
        | PART 1                        |
        | Structural / Rule Verification|
        |                               |
        | - Source trust                |
        | - Permissions                 |
        | - Structural flags            |
        +-------------------------------+
                        |
                        v
        +-------------------------------+
        | PART 2                        |
        | ML Detection                  |
        |                               |
        | - Prompt injection classifier |
        | - Embeddings                  |
        | - Semantic similarity         |
        | - Evidence localization       |
        +-------------------------------+
                        |
                        v
        +-------------------------------+
        | PART 3                        |
        | Decision & Enforcement Engine |
        |                               |
        | - Risk score 0-100            |
        | - Policy overrides            |
        | - Human review                |
        | - Enforcement gate            |
        | - Audit logging               |
        +-------------------------------+
                        |
                        v
        +-------------------------------+
        | Dashboard                     |
        |                               |
        | ALLOW / REWRITE / ESCALATE    |
        | BLOCK / Human Review / Logs   |
        +-------------------------------+

Note: Part 1 is part of the overall SENTINEL architecture but its implementation is not currently included in this repository. Part 3 accepts Part 1-compatible structural signals as input.

3. Repository Structure

SENTINEL/
├── part2_ml_detection/
│   ├── calibration/
│   ├── config/
│   ├── ml_detection/
│   ├── models/
│   ├── samples/
│   ├── scripts/
│   └── tests/
│
├── part3_decision_engine/
│   ├── config/
│   ├── logs/
│   ├── samples/
│   ├── sentinel_decision/
│   └── tests/
│
├── dashboard/
│   ├── backend/
│   └── frontend/
│
├── .gitignore
└── README.md

Part 2 — ML Detection

Part 2 provides machine-learning-based security analysis. Its main entry point is conceptually:

analyze(input_dict) -> output_dict

Part 2 does not make the final allow/block decision. It produces evidence that Part 3 can use.

Main capabilities

Unicode and text normalization

Sliding-window chunking

Prompt-injection classification

Sentence embeddings

Semantic similarity analysis

Suspicious evidence localization

Risk-signal fusion

Security content flags

Offline model execution

Models

Prompt-injection classifier:

protectai/deberta-v3-base-prompt-injection-v2

Embedding model:

sentence-transformers/all-MiniLM-L6-v2

The model revisions are pinned for reproducibility.

Part 2 Output

Example:

{
  "action_id": "a001",
  "ml_label": "SUSPICIOUS",
  "ml_confidence": 0.84,
  "semantic_similarity": 0.21,
  "content_flags": [
    "ML_FLAGGED_INJECTION",
    "LOW_TASK_SIMILARITY"
  ]
}

Possible flags include:

ML_FLAGGED_INJECTION
LOW_TASK_SIMILARITY
ACTION_RESEMBLES_UNTRUSTED_SOURCE
OBFUSCATION_NORMALIZED
CONTENT_TRUNCATED
INPUT_INCOMPLETE

Part 2 Calibration

Current calibrated configuration:

2026-09-20-c

Evaluation dataset:

82 total examples
75 in-scope examples
17 positive examples
58 negative examples
19 scenarios

Observed calibration results:

Precision: 0.769
Recall:    0.588
F1:        0.667
FPR:       0.052

Hard-negative false-positive rate:

0.0

These results are calibration results on the current project dataset and should not be interpreted as universal production performance.

Part 2 Tests

Current test result:

113 passed
1 skipped

Part 2 has also been verified inside Docker with networking disabled.

Part 3 — Decision & Enforcement Engine

Part 3 consumes security signals and makes the final decision.

Possible outcomes:

ALLOW
REWRITE
ESCALATE
BLOCK

Risk Scoring

Part 3 calculates an explainable score:

0 ------------------------------- 100
Low Risk                      Critical

The score can combine signals such as source trust, permission result, structural flags, ML confidence, semantic similarity, action impact, and content-security flags.

Policy Engine

Configurable policy is stored in:

part3_decision_engine/config/policy.yaml

This keeps security thresholds and policy values separate from the source code.

Hard Safety Overrides

Some conditions can override the normal score-based decision. Examples include permission denial, credential exfiltration, dangerous action categories, very low semantic similarity, and security-policy violations.

This prevents a single numeric score from being the only security control.

Human Review

When an action is classified as ESCALATE, the dashboard can place it in a pending human-review queue. A reviewer can select APPROVE or DENY, and the decision is then sent back through the Part 3 workflow.

AI Action
   |
   v
ESCALATE
   |
   v
PENDING HUMAN REVIEW
   |
   +------ APPROVE
   |
   +------ DENY

Enforcement Gate

The enforcement gate is the final security barrier before an action can execute. A blocked or human-denied action cannot receive an execution permit.

The current dashboard demo does not connect to real destructive tools or external executors, so:

APPROVED != automatically executed

This is intentional for safe demonstration.

Audit Log

Part 3 maintains an append-only audit trail. Sensitive parameter keys such as password, token, secret, api_key, and credential are redacted before being written.

Example:

{
  "token": "[REDACTED_BY_SENTINEL]"
}

Tamper-Evident Hash Chain

Each log record contains a sequence number, previous hash, and current SHA-256 hash.

Record 1
   |
   v
Hash 1
   |
   v
Record 2 + Hash 1
   |
   v
Hash 2
   |
   v
Record 3 + Hash 2

If an existing record is modified, the integrity verification can fail.

The dashboard displays:

✓ Audit Log VALID

or:

✕ Audit Log TAMPERED

This is tamper-evident logging, not an external immutable logging system.

Dashboard

The SENTINEL dashboard uses React, Vite, Recharts, CSS, FastAPI, and Python.

Dashboard Features

total analyzed actions

number of ALLOW decisions

number of BLOCK decisions

number of ESCALATE decisions

average risk score

decision distribution chart

risk timeline

human-review queue

APPROVE / DENY controls

recent decisions

detailed decision inspection

Part 1 / Part 2 / Part 3 signal visualization

risk-level badges

action search

outcome filtering

automatic refresh

API status

system security status

audit-log integrity status

predefined demo scenarios

Demo Scenarios

Three scenarios can be launched directly from the dashboard.

Safe

SAFE → ALLOW

Represents a normal permitted action.

Suspicious

SUSPICIOUS → ESCALATE

The action requires human validation.

Malicious

MALICIOUS → BLOCK

The action is prevented from execution.

Installation

Clone the repository:

git clone https://github.com/alajouili/indabax.git
cd indabax

Create a Python environment on Windows Git Bash:

py -3.11 -m venv .venv
source .venv/Scripts/activate

Install Part 3:

python -m pip install -e ./part3_decision_engine

Install dashboard dependencies:

python -m pip install fastapi uvicorn

Running the Dashboard

Terminal 1 — Backend

From the repository root:

source .venv/Scripts/activate
python -m uvicorn dashboard.backend.main:app --reload --port 8000

Backend:

http://127.0.0.1:8000

API documentation:

http://127.0.0.1:8000/docs

Terminal 2 — Frontend

cd dashboard/frontend
npm install
npm run dev

Frontend:

http://localhost:5173

Running Part 2

Enter Part 2:

cd part2_ml_detection

Install the required dependencies according to the Part 2 project configuration.

Download the pinned models:

python scripts/download_models.py

Run tests:

pytest

Docker — Offline Part 2

Build:

docker build -t sentinel-part2 .

Run without network access:

docker run --rm --network none sentinel-part2

The offline Docker test has successfully completed the Part 2 test suite.

Part 2 ↔ Part 3 Integration

Part 3 includes a Part 2 integration interface in:

part3_decision_engine/sentinel_decision/part2_client.py

An in-process Part 2 → Part 3 integration has been tested.

Proposal
   |
   v
Part 2 Provider
   |
   v
ML Signals
   |
   v
Part 3 Decision Pipeline
   |
   v
ALLOW / REWRITE / ESCALATE / BLOCK

The current dashboard demo scenarios use prepared proposal data. Automatic Part 2 execution can be connected through the Part 2 provider interface.

Security Principles

SENTINEL follows several design principles:

Fail Closed — invalid or malformed critical input should not silently result in execution.

Separation of Responsibilities — Part 2 observes and detects; Part 3 decides and enforces.

Human-in-the-Loop — high-risk or ambiguous cases can require human approval.

Explainability — decisions include risk score, reason codes, security flags, and explanation.

Auditability — security decisions are recorded in a tamper-evident log.

Least Privilege — an AI agent should only perform actions permitted for its role.

Current Limitations

Part 1 implementation is not included in this repository.

The ML calibration dataset is relatively small.

There is currently no independent held-out evaluation dataset.

Part 2 is primarily English-oriented.

Multi-step attacks remain difficult for the current Part 2 detector.

Encoded and heavily obfuscated payloads remain an area for further work.

The dashboard demo does not execute real external actions.

Audit logs are tamper-evident but are not externally anchored in immutable storage.

The dashboard currently uses polling rather than WebSockets.

Production authentication and authorization for the dashboard are not yet implemented.

Future Work

Potential extensions include:

complete Part 1 implementation

automatic Part 1 → Part 2 → Part 3 pipeline

larger multilingual calibration datasets

multi-step attack detection

persistent review database

dashboard authentication

role-based dashboard access

WebSocket live updates

external SIEM integration

signed audit records

remote immutable log storage

containerized complete SENTINEL stack

Kubernetes deployment

monitoring with Prometheus and Grafana

Project Status

Part 1         Architecture / interface defined
Part 2         Implemented
Part 3         Implemented
Dashboard      Implemented
Human Review   Implemented
Audit Integrity Implemented
Docker Part 2  Implemented

SENTINEL is currently a functional security prototype intended for experimentation, demonstration, and further research into safer enterprise AI agents.