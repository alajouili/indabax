# SENTINEL Part 3 — Decision Engine

Part 3 combines Part 1 structural/trust signals with Part 2 ML signals, computes an explainable risk score, applies deterministic policy overrides, optionally requests human approval, enforces the result as a hard execution gate, and appends the complete decision to a hash-chained JSONL trace.

## Flow

```text
Part 1 + Part 2
      ↓
signals.py
      ↓
state.py / classify.py
      ↓
scoring.py (0–100)
      ↓
overrides.py
      ↓
engine.py
      ↓
ALLOW | REWRITE | ESCALATE | BLOCK
      ↓
human.py when ESCALATE
      ↓
enforcement.py
      ↓
executor
      ↓
tracelog.py
```

The original action is never executed for `BLOCK`, `ESCALATE + DENIED`, or `REWRITE`. Rewritten actions must be submitted again through SENTINEL.

## Install

```bash
python -m venv .venv
source .venv/Scripts/activate   # Windows Git Bash
python -m pip install -e ".[dev]"
pytest
```

## Run a sample

```bash
python -m sentinel_decision.cli run samples/proposals/clean.json
python -m sentinel_decision.cli run samples/proposals/mixed.json --human cli
```

## Verify the trace log

```bash
python -m sentinel_decision.cli verify
```

All policy weights, thresholds, overrides, rewrite rules, action categories, state limits, human defaults and log paths live in `config/policy.yaml`.

## Part 2 integration

Part 3 can consume a hand-made Part 2-shaped object, or call the existing Part 2 module through `InProcessPart2Provider.from_default()` when `ml_detection` is importable.
