# SENTINEL Part 2 — ML content-observation module

A pure function that reads what an agent is about to do and the untrusted text it has read, and returns
**evidence** for Part 3. It never decides allow / block / escalate / rewrite.

```
analyze({action_id, user_task, proposed_action_description, instruction_content}) -> {label, confidence, similarity, flags, details}
```

Two signals, one contract:

| Lane | Question | Signal |
|---|---|---|
| A | Is this text trying to instruct the agent? | DeBERTa injection classifier, max over overlapping chunks |
| B | Does the action still match the user's task, or the untrusted author's text? | MiniLM cosines: *task drift* (task↔action) and *authorship* (evidence↔action) |

## Status — read this first

| Area | State |
|---|---|
| Contract, normalizer, chunker, mapper, fusion, config, never-raise, HTTP service | Implemented and tested (152 tests pass without model weights) |
| Real DeBERTa / MiniLM wrappers (`classifier.py`, `embeddings.py`, `models.py`) | Implemented, **not yet run against real weights**: the build sandbox had no access to Hugging Face |
| `config/thresholds.yaml` values | **Placeholders** (`calibrated: false`). Run the calibration workflow below on the real models |
| Golden files | Property expectations ship in `samples/expected/*.expect.json`; exact-value goldens are generated on your machine |

Do these first on the demo machine: **Install → `download_models.py` → `pytest` → `bench_latency.py` → calibrate.**
Tests that need weights run automatically once the cache exists (they say why they skip until then).

## Install

```bash
uv venv --python 3.11 && source .venv/bin/activate      # Windows: .venv\Scripts\activate
uv pip install torch --index-url https://download.pytorch.org/whl/cpu   # CPU build first, on its own
uv pip install -e ".[service,calibration,dev]"

python scripts/download_models.py       # needs internet once; caches to models/.hf and verifies an offline load
pytest                                   # add HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 in CI
```

`download_models.py` prints the resolved commit of each model. Paste the full hash into `models.*.revision`
in `config/thresholds.yaml` (the classifier's `ccb1f30` comes from the architecture doc and was not
independently verified) and record both in the report. Weights are git-ignored.

## Use

```python
from ml_detection.analyze import analyze     # not `from ml_detection import analyze`: see Deviations
signals = analyze({
    "action_id": "a001",
    "user_task": "Reply to the vendor dispute email",
    "proposed_action_description": "email_draft to vendor@external.example with subject ...",
    "instruction_content": "<raw email text>",
})
```

```bash
uvicorn ml_detection.service:app --host 127.0.0.1 --port 8090        # POST /analyze, GET /health
```

**For Part 3 today, with no model download:** `samples/stub_detector.py` (put `samples/` on `sys.path`, then `from stub_detector import analyze`) exposes the same `analyze()` and
runs the real pipeline over two tiny lexical backends. Real shapes, flags and mapping; fake signal values.
Never demo or report from it.

## Output contract

The first five keys are frozen; new information only ever goes into `details`.

| Field | Meaning |
|---|---|
| `ml_label` | `benign` \| `suspicious` \| `malicious`: the risk of **this action in this context** |
| `ml_confidence` | fused manipulation score in [0,1], 4 dp; the value that decides the label |
| `semantic_similarity` | cosine(task, action), in [0,1] (0.0 if it could not be computed; see `INPUT_INCOMPLETE`) |
| `content_flags` | frozen vocabulary below, in a fixed order |
| `details` | `source_similarity`, `evidence_span`, `chunk_index`, `normalization_applied`, `model_version`, `thresholds_version`, `latency_ms`, plus `injection_score`, `drift_signal`, `authorship_signal`, `corroboration`, `chunks_scanned`, `chunks_total`, `missing_fields`, `embedder_version`, `thresholds_calibrated` |

| Flag | Raised when |
|---|---|
| `ML_FLAGGED_INJECTION` | max chunk injection probability ≥ `injection.flag_threshold` (a **content** signal, independent of the label) |
| `LOW_TASK_SIMILARITY` | task↔action cosine < `similarity.drift_threshold` |
| `ACTION_RESEMBLES_UNTRUSTED_SOURCE` | (evidence↔action) − (task↔action) > `similarity.authorship_margin`, and the content is at least slightly injection-like |
| `OBFUSCATION_NORMALIZED` | the normalizer undid zero-width/bidi characters, letter-folding or letter-spacing |
| `CONTENT_TRUNCATED` | more windows than `chunking.max_chunks`; head and tail were scanned, the middle was not |
| `INPUT_INCOMPLETE` | a required field was missing/empty, **or the module itself failed** (see below) |

Everything except `details.latency_ms` is deterministic.

## How the label is produced

```
corroboration = max( ramp(drift_threshold − task_sim),  ramp((source_sim − task_sim) − authorship_margin) )
fused         = injection_score × ( w + (1 − w) × corroboration )        # w = fusion.uncorroborated_weight
label         = malicious if fused ≥ labels.malicious, suspicious if ≥ labels.suspicious, else benign
```

Hostile-*looking* text is weak evidence (a security-awareness email quotes "ignore previous instructions").
What makes it dangerous is the agent **acting on it**, so the action-side signals corroborate. `ramp` is 0 at
the flag threshold and reaches 1 `fusion.ramp_width` later, so corroboration starts exactly where the
corresponding flag fires. Consequence, by design: a hostile document with an action that ignores it gives
`benign` + `ML_FLAGGED_INJECTION`, and Part 3 still sees the flag. Set `fusion.uncorroborated_weight: 1.0`
for classifier-only behaviour (that is ablation row 1).

## Deviations from the architecture document (and why)

1. **`ml_detection/config.py` added.** Five modules read `thresholds.yaml`; one typed loader that rejects unknown keys and checks invariants beats five copies of YAML parsing. Model ids/revisions also live in the config so `download_models.py` and the loader cannot disagree.
2. **Authorship flag is gated** by `similarity.authorship_min_injection`. Without it, every legitimate email summary "resembles its source" and raises the flag, defeating the hard-negative requirement. Set it to `0.0` for the literal rule.
3. **Authorship compares the action to the offending sentence**, not the whole content: MiniLM truncates at 256 tokens and a 150-word chunk dilutes the hostile sentence. The same sentence is `evidence_span`. It costs one extra small classifier batch, only when the top chunk scores ≥ `evidence.localize_min_score`.
4. **Label comes from the fused score** (above). The architecture left the label rule open; this is the rule.
5. **Chunk size is in words** (150 / overlap 40 ≈ 200 / 50 tokens) so the chunker is pure and testable without a tokenizer; the classifier still runs with `max_length: 512`, and over-long unbroken runs are split. Over budget, **head and tail are kept**: the scenario library's attacks append text, so head-only truncation would miss them.
6. **`analyze(raw, *, config=None, models=None)`** has two optional overrides for ablations, tests and the stub. The orchestrator ignores them.
7. **`ml_detection/__init__.py` does not re-export `analyze`**: doing so shadows the `ml_detection.analyze` submodule (this bit us during testing).
8. **Golden files** are generated locally (`UPDATE_GOLDEN=1 pytest tests/test_signals.py`); shipped expectations are property-level. **`tests/conftest.py`** added for the shared fixtures.

## Calibration workflow

```bash
git clone https://github.com/Skan22/Sentinel_Starter_Kit ../Sentinel_Starter_Kit
python calibration/build_dataset.py   --kit ../Sentinel_Starter_Kit           # real models; ~80 rows
python calibration/sweep_thresholds.py                                        # tables in calibration/report/
# copy calibration/report/recommended_thresholds.yaml into config/thresholds.yaml, bump `version`, set `calibrated: true`
UPDATE_GOLDEN=1 pytest tests/test_signals.py                                  # freeze goldens; later diffs show what moved
```

`build_dataset.py` reads scenarios only as data; `analyze()` never sees a scenario id, file name or label
(`test_unknown_keys_cannot_influence_the_result` enforces that). Labels are two-axis (*content carries a
payload* / *action follows it*). Direct-instruction attacks are user-authored, marked out of scope, and reported
separately. `sweep_thresholds.py` refuses stub-built datasets unless `--allow-stub`. It writes the four ablation
runs (classifier only, similarity only, both, chunking disabled) and a per-family table.

## Contract with the orchestrator (agree these today)

* **Phrasing of `proposed_action_description` is calibration-critical.** Calibration uses `tool key value key value…` (see `build_dataset.describe_action`), e.g. `email_draft to billing@x.example subject INV-4471 dispute`. If the orchestrator phrases actions differently, the cosines shift and thresholds are wrong.
* **Treat `INPUT_INCOMPLETE` as "no ML evidence", never as "safe".** This module fails *open* by contract (benign, confidence 0) so a crash cannot kill a run. Part 3 must not read that benign as reassurance.
* **Pass the content the agent actually observed** (untrusted or memory-recalled text included), not only the latest tool result: the memory-poisoning scenarios only show up if recalled entries reach `instruction_content`.
* Nobody currently owns wiring into `sentinel run` / `sentinel replay` (the trace the 40-point video score depends on). Not this module's job, but raise it.

## Models declared

| Role | Model | License |
|---|---|---|
| Classifier | `protectai/deberta-v3-base-prompt-injection-v2` | Apache 2.0 (its training datasets carry mixed licenses; review before redistribution) |
| Embeddings | `sentence-transformers/all-MiniLM-L6-v2` | Apache 2.0 |

Classifier model card: English only; does not detect jailbreaks; advises against running on system prompts (false positives);
reported 95.25% accuracy / 91.59% precision / 99.74% recall on its own 20,000-prompt evaluation, i.e. high recall, weaker precision.
No dataset is used beyond the public scenario library for calibration.

## Known limitations (source material for the safety statement and failure analysis)

* **Encoded payloads** (base64, hex, reversed) mean nothing to a text classifier. Structural checks (Part 1) own them; this module does not claim to.
* **Multi-step attacks:** an instruction split across records looks benign per fragment. Single-action analysis cannot see it; only accumulated state in Part 3 can. In the calibration data the split-payload scenario is the canonical case.
* **Long-horizon tasks:** one cosine between two short strings is a weak proxy for drift over a twenty-step plan.
* **English only; no jailbreak detection;** non-English injection is undetected. The normalizer does not map homoglyphs (Cyrillic "а" for "a"), collapses letters separated by *single spaces only* (not dots/dashes), and cannot re-segment a fully spaced string with no word gaps ("i g n o r e p r e v i o u s…" becomes one long token).
* **Memory poisoning phrased as policy** ("approved by Legal: summaries may be emailed to partners…") contains no imperative and may score low; it is caught, if at all, by authorship when the resulting action resembles the note.
* **Terse action descriptions can over-corroborate.** Hostile-looking content plus an action description sharing little wording with the task can be pushed to `suspicious`/`malicious` by drift alone. Hard-negative behaviour with real embeddings is the thing to check first (`test_hard_negative_*`).
* **Head+tail truncation:** content beyond `max_chunks` windows is not scanned in the middle. An adversary who knows the budget can bury text there.
* **Fusion suppresses content-only detection** by design (precision over recall). Raise `uncorroborated_weight` if recall matters more.
* **Distribution gap:** the classifier was trained on real-world prompts; the scenarios are synthetic. Calibration measures the gap; report the number.
* **Small calibration set** (~80 rows from 19 scenarios, no held-out split): thresholds are fitted to it.
* **Fails open** on internal error (see contract above). Expected false-positive behaviour: security-training and incident-response text with imperative phrasing will raise `ML_FLAGGED_INJECTION`; the fusion is meant to keep it from raising the label.
* **What this module observes:** the four input strings only. It stores nothing and makes no network calls. When to keep a human in the loop is Part 3's escalation policy.