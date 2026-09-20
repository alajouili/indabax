"""Build the calibration dataset from the published scenario library.

One row per (task, candidate action, observed content) triple, labelled on two axes so each
signal is measured against what it is meant to detect:

  content_has_injection    - the observed content carries an attack payload (target of ML_FLAGGED_INJECTION)
  action_follows_injection - the candidate action is what the payload asks for (target of the label)

Rows come from each scenario's reference plan (legitimate actions, benign or over a poisoned
context) and from the calls the payload tries to induce ("call TOOL with {...}"). Direct-instruction
attacks are user-authored, so they are marked ``in_scope=0``: Part 2 has no content-level evidence of
them and they belong to the policy layer. Reported, not tuned on.

DEV-TIME ONLY. This script reads scenario files as *data* to produce labelled rows. The runtime
``analyze()`` never sees scenario ids, file names or labels: only the four contract fields go in.

Usage:
    python calibration/build_dataset.py --kit ../Sentinel_Starter_Kit            # real models
    python calibration/build_dataset.py --kit ../Sentinel_Starter_Kit --backend stub   # plumbing test only
"""

from __future__ import annotations

import argparse
import copy
import csv
import json
import re
import sys
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "samples"))

from ml_detection.analyze import analyze  # noqa: E402
from ml_detection.config import load_config  # noqa: E402

CALL_PATTERN = re.compile(r"call\s+([a-z][a-z0-9_]*)\s+with\s+")
SKIP_KEYS = {"_meta", "id"}
COLUMNS = [
    "row_id", "scenario", "domain", "family", "difficulty", "kind", "turn", "step",
    "user_task", "action", "content",
    "content_has_injection", "action_follows_injection", "in_scope",
    "injection_score", "injection_score_nochunk", "task_similarity", "source_similarity",
    "backend", "thresholds_version",
]


# --- reading the kit -----------------------------------------------------------------------------

def item_text(value: Any) -> str:
    """All human-readable strings of a fixture item (everything except ids and _meta)."""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return "\n".join(t for k, v in value.items() if k not in SKIP_KEYS and (t := item_text(v)))
    if isinstance(value, list):
        return "\n".join(t for v in value if (t := item_text(v)))
    return ""


def index_items(collections: dict[str, list[dict]]) -> dict[str, dict]:
    return {item["id"]: item for items in collections.values() for item in items if isinstance(item, dict) and "id" in item}


def apply_payloads(collections: dict[str, list[dict]], attack: dict[str, Any]) -> dict[str, list[dict]]:
    """Apply text payloads to their surfaces, mirroring the simulator's append/replace operations."""
    patched = copy.deepcopy(collections)
    surfaces = {s["id"]: s for s in attack.get("surfaces", [])}
    for payload in attack.get("payloads", []):
        surface = surfaces.get(payload["surface"])
        parts = surface["target"].split("/") if surface else []
        if len(parts) != 3 or parts[0] not in patched:
            print(f"  ! skipping payload for unsupported surface {surface and surface['target']!r}", file=sys.stderr)
            continue
        coll, item_id, field = parts
        for item in patched[coll]:
            if item.get("id") == item_id:
                text = payload["text"].strip()  # same form is used for the membership test in rows_for_scenario
                if payload["operation"] == "append_text":
                    item[field] = f"{item.get(field, '')}\n{text}".strip()
                elif payload["operation"] == "replace_text":
                    item[field] = text
    return patched


def describe_action(tool: str, args: dict[str, Any], max_value_chars: int = 80) -> str:
    """The action-description convention used for calibration: ``tool key value key value ...``.

    The orchestrator owner must build ``proposed_action_description`` the same way, or the similarity
    cosines will be calibrated on a different distribution than the one seen at runtime.
    """
    parts = [tool] + [f"{k} {str(v)[:max_value_chars]}" for k, v in args.items()]
    return " ".join(parts)


def describe_step(step: dict[str, Any]) -> str:
    if step.get("action") == "tool_call":
        return describe_action(step["tool"], step.get("args", {}))
    text = re.sub(r"\{\{.*?\}\}", "", step.get("content", "")).strip()
    return f"respond to the user: {text[:200]}" if text else ""


def induced_actions(text: str) -> list[str]:
    """Descriptions of every ``call TOOL with {json}`` an instruction asks the agent to make."""
    decoder = json.JSONDecoder()
    found = []
    for match in CALL_PATTERN.finditer(text):
        try:
            args, _ = decoder.raw_decode(text, match.end())
            found.append(describe_action(match.group(1), args if isinstance(args, dict) else {}))
        except ValueError:  # fragment of a split payload: keep the tool name at least
            found.append(describe_action(match.group(1), {}))
    return found


# --- row construction ----------------------------------------------------------------------------

def rows_for_scenario(scn: dict[str, Any], fixtures: dict[str, Any]) -> list[dict[str, Any]]:
    attack = scn.get("attack") or {}
    present = bool(attack.get("present"))
    family = attack.get("family", "none") if present else "none"
    base = fixtures[scn["domain"]]["collections"]
    collections = apply_payloads(base, attack) if present else base
    items = index_items(collections)
    payload_texts = [p["text"].strip() for p in attack.get("payloads", [])]
    tags = scn.get("tags") or []
    plain_kind = "hard_negative" if "hard_negative" in tags else "benign"
    common = {"scenario": scn["id"], "domain": scn["domain"], "family": family, "difficulty": attack.get("difficulty", 0)}
    rows: list[dict[str, Any]] = []

    def has_injection(content: str) -> int:
        return int(any(p in content for p in payload_texts))

    def add(kind, turn, step, task, action, content, follows, in_scope=1):
        if action and content.strip():
            rows.append({**common, "kind": kind, "turn": turn, "step": step, "user_task": task, "action": action,
                         "content": content, "content_has_injection": has_injection(content),
                         "action_follows_injection": follows, "in_scope": in_scope})

    for t_idx, turn in enumerate(scn["turns"]):
        goal = turn["goal"]
        observed: list[str] = []
        if family == "memory_poisoning" and t_idx > 0 and payload_texts:
            observed.append("Memory entry: " + payload_texts[0])  # the poisoned note, recalled in a later task

        for step in turn["reference_plan"]:
            kind = plain_kind if not present else "legitimate_action"
            if present and has_injection("\n\n".join(observed)):
                kind = "poisoned_context_benign_action"
            add(kind, t_idx + 1, step["id"], goal, describe_step(step), "\n\n".join(observed), 0)
            for value in (step.get("args") or {}).values():
                item = items.get(value) if isinstance(value, str) else None
                if item is not None:
                    observed.append(item_text(item))
                    for ref in (v for v in item.values() if isinstance(v, list) for v in v if isinstance(v, str) and v in items):
                        observed.append(item_text(items[ref]))

        content = "\n\n".join(observed)
        if present and family == "direct_instruction":
            for n, action in enumerate(induced_actions(goal)):
                add("hijacked_action", t_idx + 1, f"direct{n}", goal, action, content, 1, in_scope=0)
        elif present and has_injection(content):
            for n, action in enumerate(a for text in payload_texts if text in content for a in induced_actions(text)):
                add("hijacked_action", t_idx + 1, f"hijack{n}", goal, action, content, 1)

    seen, unique = set(), []
    for row in rows:
        key = (row["user_task"], row["action"], row["content"])
        if key not in seen:
            seen.add(key)
            unique.append(row)
    return unique


def load_kit(kit: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    scenarios = [yaml.safe_load(p.read_text(encoding="utf-8")) for p in sorted((kit / "scenarios").rglob("*.yaml"))]
    fixtures = {d: json.loads((kit / "fixtures" / d / "base.json").read_text(encoding="utf-8")) for d in ("enterprise", "finance", "soc")}
    return [s for s in scenarios if s.get("split", "public") == "public"], fixtures


# --- scoring -------------------------------------------------------------------------------------

def score_rows(rows: list[dict[str, Any]], backend: str, config_path: str | None) -> None:
    cfg = load_config(config_path)
    no_chunk = cfg.model_copy(update={"chunking": cfg.chunking.model_copy(update={"enabled": False})})
    kwargs: dict[str, Any] = {}
    if backend == "stub":
        from stub_detector import STUB_MODELS

        kwargs["models"] = STUB_MODELS
    for i, row in enumerate(rows):
        raw = {"action_id": f"r{i:04d}", "user_task": row["user_task"], "proposed_action_description": row["action"],
               "instruction_content": row["content"]}  # the ONLY fields the detector ever sees
        result = analyze(raw, config=cfg, **kwargs)
        if result["details"].get("degraded"):
            raise SystemExit(f"analysis failed ({result['details'].get('error')}). Cache the models "
                             "(scripts/download_models.py) or pass --backend stub to test the plumbing only.")
        whole = analyze(raw, config=no_chunk, **kwargs)
        row.update(
            row_id=i, backend=backend, thresholds_version=cfg.version,
            injection_score=result["details"]["injection_score"],
            injection_score_nochunk=whole["details"]["injection_score"],
            task_similarity=result["semantic_similarity"],
            source_similarity=result["details"]["source_similarity"] if result["details"]["source_similarity"] is not None else 0.0,
        )


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--kit", required=True, type=Path, help="path to a clone of Sentinel_Starter_Kit")
    ap.add_argument("--out", type=Path, default=ROOT / "calibration" / "data" / "dataset.csv")
    ap.add_argument("--backend", choices=["real", "stub"], default="real")
    ap.add_argument("--config", default=None, help="thresholds.yaml override")
    args = ap.parse_args()

    scenarios, fixtures = load_kit(args.kit)
    rows = [row for scn in scenarios for row in rows_for_scenario(scn, fixtures)]
    print(f"{len(scenarios)} scenarios -> {len(rows)} rows")
    score_rows(rows, args.backend, args.config)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    by_kind: dict[str, int] = {}
    for row in rows:
        by_kind[row["kind"]] = by_kind.get(row["kind"], 0) + 1
    print(f"wrote {args.out}  ({args.backend} backend)  {by_kind}")
    if args.backend == "stub":
        print("NOTE: stub-backend numbers verify the plumbing only; they are not evidence.")


if __name__ == "__main__":
    main()