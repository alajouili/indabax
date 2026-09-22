# SENTINEL Part 1 — Structural Verifier

Part 1 is the deterministic, rule-based layer of SENTINEL. It inspects provenance, permissions, action shape, encoded/fragmented instructions, generic secret shapes, and source→sink data flow before Part 3 makes the final decision.

## Contract

```python
from sentinel_verifier import verify
result = verify(request_dict)  # always returns a dict; never raises to the caller
```

Stable output fields:

- `action_id`
- `trust_level`
- `trust_basis`
- `permission_ok` (`true`, `false`, or `null`)
- `structural_flags`
- `findings`
- `sensitivity`
- `details`

Part 1 is intentionally **not ML**. It produces deterministic evidence for Part 3.

## Modules

- `schema.py` — lenient request view + frozen output contract
- `config.py` — strict typed YAML loader; unknown config keys fail validation
- `digest.py` — deterministic action digest
- `textnorm.py` — NFKC, zero-width removal, separator/alnum folding
- `decode.py` — URL/base64/hex/ROT13/reversed variants, nested to depth 2
- `provenance.py` — source trust and influence set
- `permissions.py` — role/tool/prerequisite/confirmation checks
- `secrets.py` — generic secret-shape detection
- `dataflow.py` — source secret → external sink detection, including encoded values
- `mirroring.py` — instruction mirroring, encoded instructions, fragmented reassembly
- `action_shape.py` — consequential/control/memory/external-recipient/authority signals
- `verify.py` — aggregation + fail-closed boundary
- `service.py` — optional FastAPI `POST /verify`

## Rules

All tunable values live in `config/rules.yaml`. Do not add challenge scenario IDs, filenames, or expected outcomes to rules or runtime logic.

## Install

```bash
python -m pip install -e .
```

For tests:

```bash
python -m pip install -e '.[dev]'
pytest
```

For API service:

```bash
python -m pip install -e '.[service]'
python -m uvicorn sentinel_verifier.service:app --reload --port 8001
```

## Samples

```bash
python - <<'PY'
import json
from pathlib import Path
from sentinel_verifier import verify
p = Path('samples/requests/exfil_external.json')
print(json.dumps(verify(json.loads(p.read_text())), indent=2))
PY
```

## Latency benchmark

```bash
python scripts/bench_latency.py --repeat 100
```

## Starter-kit digest compatibility

`action_digest()` uses canonical JSON (`sort_keys=True`, compact separators, UTF-8) followed by SHA-256 and deliberately excludes `action_id` / scenario IDs.

If the official starter kit provides a fixed digest fixture or helper, add that fixture to `tests/test_kit_compat.py` (or set `STARTER_KIT_EXPECTED_DIGEST`) and compare it directly. This repository does not claim exact starter-kit compatibility without such an external reference vector.


## Validation status

Validated in the build environment:

```text
31 passed
1 skipped (official starter-kit digest vector not supplied)
```

Measured deterministic verifier latency on the included sample set (300 calls):

```text
mean: 4.47 ms
p50:  4.34 ms
p95:  5.65 ms
max:  7.36 ms
```

These latency figures are machine-specific and should be re-measured on the target machine.

## Security notes

- Part 1 is fail-closed on malformed internal state.
- `permission_ok=null` means the verifier could not determine permission from available facts; it is not equivalent to allow.
- Secret detection uses generic shapes only; it must never encode evaluator-specific canaries.
- The verifier never uses `action_id`, scenario names, filenames, or expected outcomes to decide flags.
