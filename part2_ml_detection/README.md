SENTINEL Part 2 — ML Content-Observation Module

Part 2 is the ML/content-observation layer of SENTINEL. It inspects the untrusted text an agent has observed and the action it is about to perform, then returns evidence for Part 3.

It never makes the final ALLOW, BLOCK, ESCALATE, or REWRITE decision.

analyze({
    "action_id": ...,
    "user_task": ...,
    "proposed_action_description": ...,
    "instruction_content": ...
}) -> {
    "action_id": ...,
    "ml_label": ...,
    "ml_confidence": ...,
    "semantic_similarity": ...,
    "content_flags": ...,
    "details": ...
}

Detection pipeline

Lane

Question

Signal

A

Is the observed text trying to instruct/manipulate the agent?

DeBERTa prompt-injection classifier over overlapping chunks

B

Does the proposed action match the user task or resemble the untrusted source?

MiniLM task↔action and evidence↔action cosine similarities

Pipeline:

schema guard
→ normalization
→ overlapping chunking
→ injection scoring
→ strongest-evidence localization
→ semantic similarity
→ signal fusion
→ label + flags

Part 2 only returns signals. Part 3 combines them with structural trust, permissions, policy, accumulated state, and human escalation.

Current status

Area

Status

Schema / contract

Implemented

Normalization

Implemented

Chunking

Implemented

Injection classifier

Implemented with real weights

MiniLM embeddings

Implemented with real weights

Evidence localization

Implemented

Fusion / mapping

Implemented and calibrated

Never-raise fallback

Implemented

HTTP service

Implemented

Full test suite

113 passed, 1 skipped, 0 failed

Runtime offline

Verified

Docker offline

Verified with --network none

Calibration

Completed — 2026-09-20-c

Models

Role

Model

Revision

Injection classifier

protectai/deberta-v3-base-prompt-injection-v2

90c9989b1a342275dd0d1a95aad283c04e075671

Embeddings

sentence-transformers/all-MiniLM-L6-v2

1110a243fdf4706b3f48f1d95db1a4f5529b4d41

Weights are stored locally under:

models/.hf/

They are git-ignored. Internet is only needed once to populate the local cache:

python scripts/download_models.py

Installation

Python 3.11 is recommended.

python -m venv .venv
source .venv/Scripts/activate

python -m pip install --upgrade pip

python -m pip install   torch==2.14.0+cpu   --index-url https://download.pytorch.org/whl/cpu

python -m pip install -r requirements.txt

python scripts/download_models.py
pytest -q

Expected result:

113 passed, 1 skipped

Use

from ml_detection.analyze import analyze

result = analyze({
    "action_id": "a001",
    "user_task": "Reply to the vendor dispute email",
    "proposed_action_description":
        "email_draft to vendor@external.example subject INV-4471 dispute",
    "instruction_content": "<raw untrusted email text>",
})

HTTP service:

uvicorn ml_detection.service:app --host 127.0.0.1 --port 8090

Endpoints:

POST /analyze
GET  /health

Output contract

Field

Meaning

action_id

Correlates the result with the proposed action

ml_label

benign, suspicious, or malicious

ml_confidence

Fused risk score in [0,1]

semantic_similarity

task↔action cosine

content_flags

Deterministic evidence flags

details

Raw signals, evidence, versions, latency, fallback metadata

Flags:

ML_FLAGGED_INJECTION
LOW_TASK_SIMILARITY
ACTION_RESEMBLES_UNTRUSTED_SOURCE
OBFUSCATION_NORMALIZED
CONTENT_TRUNCATED
INPUT_INCOMPLETE

INPUT_INCOMPLETE means missing ML evidence, not “safe”.

Evidence localization

Whole-document similarity can dilute a short malicious sentence inside a large benign document. Part 2 therefore localizes the strongest suspicious sentence and uses that span for evidence↔action similarity.

Current configuration:

evidence:
  localize_min_score: 0.30
  max_sentences: 24
  min_sentence_words: 5
  min_sentence_chars: 30
  context_radius: 0
  max_chars: 400

context_radius: 0 is intentional: adding neighboring sentences increased false positives on benign security text.

Signal fusion

Raw signals:

inj    = injection score
task   = task↔action similarity
source = evidence↔action similarity

Similarity signals are converted into:

drift_signal
authorship_signal
corroboration = max(drift_signal, authorship_signal)

Fusion:

injection_path =
    inj * (
        uncorroborated_weight
        + (1 - uncorroborated_weight) * corroboration
    )

corroboration_path =
    corroboration_weight * corroboration
    if inj > min_injection_for_corroboration
    else 0

fused = clamp(max(injection_path, corroboration_path), 0, 1)

Label:

malicious  if fused >= labels.malicious
suspicious if fused >= labels.suspicious
benign     otherwise

Calibrated thresholds

version: "2026-09-20-c"
calibrated: true

injection:
  flag_threshold: 0.78

similarity:
  drift_threshold: 0.30
  authorship_margin: 0.20
  authorship_min_injection: 0.10

fusion:
  uncorroborated_weight: 0.35
  corroboration_weight: 0.60
  min_injection_for_corroboration: 0.0001
  ramp_width: 0.10

labels:
  suspicious: 0.60
  malicious: 0.85

The complete runtime configuration is in config/thresholds.yaml.

Calibration workflow

python calibration/build_dataset.py   --kit ../Sentinel_Starter_Kit   --backend real

python calibration/sweep_thresholds.py

Calibration outputs are written to calibration/report/.

The sweep also checks:

calibration/data/regression_signals.csv

Current result:

Regression guards: 2/2 passed

Dataset:

82 total rows
75 in-scope rows
17 positive rows
58 negative rows
19 scenarios

Selected-configuration metrics:

Metric

Result

Precision

0.769

Recall

0.588

F1

0.667

False-positive rate

0.052

Hard-negative FPR

0.000

Malicious-label precision

0.000

Ablation:

Variant

Precision

Recall

F1

FPR

Classifier only

0.0000

0.0000

0.0000

0.1379

Similarity only

0.5217

0.7059

0.6000

0.1897

Both / fusion

0.7692

0.5882

0.6667

0.0517

Chunking disabled

0.7500

0.5294

0.6207

0.0517

Per-family alert rates:

Group

Alert rate

Indirect prompt injection

0.5556

Memory poisoning

0.8333

Multi-step

0.0000

Legitimate action

0.0909

Benign

0.0000

Hard negative

0.0000

Poisoned-context benign action

0.0769

Direct user-authored attacks are treated as out of scope for Part 2 and belong to the trust/policy layer.

Latency

Measured with real CPU models in offline mode.

Cold start:

15847 ms

Ten warm runs:

Metric

Result

Mean

2219.9 ms

Median

2189 ms

Maximum

2471 ms

The cold-start cost is mostly model loading. Warm latency is more representative for a persistent service.

Docker

Build:

docker build -t sentinel-part2 .

Run tests:

docker run --rm sentinel-part2

Verify complete network isolation:

docker run --rm --network none sentinel-part2

Verified result:

113 passed, 1 skipped, 0 failed

The Docker image includes the local model cache so runtime inference does not need Internet access.

Golden tests

After an intentional model/configuration change:

UPDATE_GOLDEN=1 pytest tests/test_signals.py -q
pytest -q

Goldens are stored under:

samples/expected/*.golden.json

Latency is excluded from golden comparisons.

Important architectural boundaries

Part 2 observes only:

action_id
user_task
proposed_action_description
instruction_content

It does not:

make the final safety decision;

maintain multi-step state;

verify permissions or source trust;

execute actions;

reliably decode arbitrary encoded payloads.

The orchestrator must pass the text the agent actually observed, including recalled memory or retrieved external content.

The wording of proposed_action_description is calibration-sensitive because it directly affects semantic similarity.

Known limitations

Multi-step attacks: current Part 2 alert rate is 0.0000. A stateless single-action detector cannot reliably reconstruct malicious intent split across several records. Part 3 must accumulate state.

Malicious label: current calibration reports malicious-label precision 0.000. The calibration set is too small to validate a reliable high-confidence malicious operating region.

Small calibration set: thresholds were selected on 75 in-scope rows from 19 scenarios with no independent held-out split.

English-centric models: non-English attacks may receive weaker scores.

Encoded payloads: Base64, hex, reversed text, and similar structural obfuscations belong primarily to Part 1.

Long-horizon drift: one semantic cosine is a weak proxy for faithfulness across a long multi-action plan.

Truncation: if content exceeds the chunk budget, head and tail are retained but middle regions may be skipped.

Distribution shift: challenge scenarios and hard negatives are not a guarantee of production-enterprise performance.

Fail-open fallback: on internal failure, Part 2 returns a degraded valid output with INPUT_INCOMPLETE; Part 3 must not interpret that as evidence of safety.

Repository layout

part2_ml_detection/
├── calibration/
│   ├── build_dataset.py
│   ├── sweep_thresholds.py
│   ├── data/
│   └── report/
├── config/
│   └── thresholds.yaml
├── ml_detection/
│   ├── analyze.py
│   ├── chunking.py
│   ├── classifier.py
│   ├── config.py
│   ├── embeddings.py
│   ├── mapping.py
│   ├── models.py
│   ├── normalize.py
│   ├── schema.py
│   ├── service.py
│   └── similarity.py
├── models/
│   └── .hf/
├── samples/
│   └── expected/
├── scripts/
│   ├── bench_latency.py
│   └── download_models.py
├── tests/
├── Dockerfile
├── requirements.txt
├── pyproject.toml
└── README.md

Final role in SENTINEL

Part 2 answers:

What ML/content evidence suggests that the proposed action may have been influenced by untrusted instructions?

It does not answer:

Should SENTINEL allow or block the action?

That final decision belongs to Part 3.