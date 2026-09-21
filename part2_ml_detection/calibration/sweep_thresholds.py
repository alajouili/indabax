"""Choose thresholds from data, not intuition, and produce the report tables.

Reads the CSV from build_dataset.py (raw injection score + both cosines per row) and re-applies
``ml_detection.mapping`` under many configurations. No models are loaded, so a sweep takes seconds.

Outputs in calibration/report/:
  sweep_content_flag.csv       ML_FLAGGED_INJECTION threshold vs "content carries a payload"
  sweep_fusion.csv             every fusion/label configuration tried, with its metrics
  ablation.csv / .md           classifier only | similarity only | both | chunking disabled
  families.md                  detection / false-positive rate per attack family and row kind
  summary.md                   the above plus the selected configuration and honest caveats
  recommended_thresholds.yaml  values to copy into config/thresholds.yaml

Selection rule:
  1. A configuration must pass every regression case in regression_signals.csv.
  2. Among those configurations, prefer ones whose hard-negative FPR <= --max-hn-fpr
     and overall benign-action FPR <= --max-fpr.
  3. Pick the highest F1 for "alert on actions that follow the injection".
  4. If several configurations share the best F1, choose one REAL evaluated configuration
     closest to the centre of that best plateau.
  5. If no regression-passing configuration satisfies the FPR constraints, keep the
     regression constraint and fall back to the best-F1 regression-passing configuration,
     while emitting a warning.
"""

from __future__ import annotations

import argparse
import itertools
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ml_detection.config import Config, load_config  # noqa: E402
from ml_detection.mapping import RawSignals, map_signals  # noqa: E402
from ml_detection.schema import Label  # noqa: E402


BENIGN_KINDS = (
    "legitimate_action",
    "benign",
    "hard_negative",
    "poisoned_context_benign_action",
)

GRID = {
    "drift_threshold": [0.20, 0.25, 0.30, 0.35, 0.40, 0.45, 0.50],
    "authorship_margin": [0.0, 0.05, 0.10, 0.15, 0.20, 0.25],
    "uncorroborated_weight": [0.2, 0.35, 0.45, 0.6, 0.8, 1.0],
    "suspicious": [0.3, 0.4, 0.5, 0.6, 0.7],
    "ramp_width": [0.1, 0.2, 0.3],
}

REGRESSION_COLUMNS = {
    "name",
    "expected_alert",
    "injection_score",
    "task_similarity",
    "source_similarity",
}


def with_params(cfg: Config, **p: float) -> Config:
    """Return a config copy with only the requested calibration fields changed."""
    return cfg.model_copy(
        update={
            "similarity": cfg.similarity.model_copy(
                update={
                    k: p[k]
                    for k in (
                        "drift_threshold",
                        "authorship_margin",
                        "authorship_min_injection",
                    )
                    if k in p
                }
            ),
            "fusion": cfg.fusion.model_copy(
                update={
                    k: p[k]
                    for k in (
                        "uncorroborated_weight",
                        "corroboration_weight",
                        "min_injection_for_corroboration",
                        "ramp_width",
                    )
                    if k in p
                }
            ),
            "labels": cfg.labels.model_copy(
                update={
                    k: p[k]
                    for k in ("suspicious", "malicious")
                    if k in p
                }
            ),
            "injection": cfg.injection.model_copy(
                update={
                    k: p[k]
                    for k in ("flag_threshold",)
                    if k in p
                }
            ),
        }
    )


def prf(truth: np.ndarray, pred: np.ndarray) -> dict[str, float]:
    tp = int((truth & pred).sum())
    fp = int((~truth & pred).sum())
    fn = int((truth & ~pred).sum())
    tn = int((~truth & ~pred).sum())

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall
        else 0.0
    )
    fpr = fp / (fp + tn) if fp + tn else 0.0

    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": fpr,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
    }


def mapped_rows(
    df: pd.DataFrame,
    cfg: Config,
    inj_col: str = "injection_score",
):
    renamed = df.rename(columns={inj_col: "inj"})
    return [
        map_signals(
            RawSignals(
                injection_score=float(r.inj),
                task_similarity=float(r.task_similarity),
                source_similarity=float(r.source_similarity),
            ),
            cfg,
        )
        for r in renamed.itertuples()
    ]


def alerts(
    df: pd.DataFrame,
    cfg: Config,
    inj_col: str = "injection_score",
) -> np.ndarray:
    return np.array(
        [
            mapped.label is not Label.BENIGN
            for mapped in mapped_rows(df, cfg, inj_col)
        ],
        dtype=bool,
    )


def evaluate(
    df: pd.DataFrame,
    cfg: Config,
    inj_col: str = "injection_score",
) -> dict[str, float]:
    mapped = mapped_rows(df, cfg, inj_col)
    pred = np.array(
        [m.label is not Label.BENIGN for m in mapped],
        dtype=bool,
    )
    truth = df["action_follows_injection"].to_numpy(bool)

    out = prf(truth, pred)

    hn = (df["kind"] == "hard_negative").to_numpy()
    out["hn_fpr"] = float(pred[hn].mean()) if hn.any() else 0.0

    malicious = np.array(
        [m.label is Label.MALICIOUS for m in mapped],
        dtype=bool,
    )
    out["malicious_precision"] = (
        float(truth[malicious].mean())
        if malicious.any()
        else 0.0
    )

    return out


def sweep_content_flag(
    df: pd.DataFrame,
) -> tuple[pd.DataFrame, float]:
    truth = df["content_has_injection"].to_numpy(bool)

    rows = [
        {
            "flag_threshold": round(float(t), 2),
            **prf(
                truth,
                df["injection_score"].to_numpy() >= t,
            ),
        }
        for t in np.arange(0.05, 1.0, 0.05)
    ]

    table = pd.DataFrame(rows)
    best = table["f1"].max()
    plateau = table.loc[
        np.isclose(table["f1"], best),
        "flag_threshold",
    ]

    return table, float(plateau.median())


def validate_regressions(df: pd.DataFrame) -> None:
    missing = REGRESSION_COLUMNS - set(df.columns)
    if missing:
        raise SystemExit(
            "regression_signals.csv is missing columns: "
            + ", ".join(sorted(missing))
        )

    if df.empty:
        raise SystemExit(
            "regression_signals.csv is empty; refusing to calibrate "
            "without regression guards."
        )


def regressions_pass(
    df: pd.DataFrame,
    cfg: Config,
) -> bool:
    for r in df.itertuples():
        mapped = map_signals(
            RawSignals(
                injection_score=float(r.injection_score),
                task_similarity=float(r.task_similarity),
                source_similarity=float(r.source_similarity),
            ),
            cfg,
        )

        predicted_alert = mapped.label is not Label.BENIGN
        expected_alert = bool(int(r.expected_alert))

        if predicted_alert != expected_alert:
            return False

    return True


def sweep_fusion(
    df: pd.DataFrame,
    base: Config,
    max_fpr: float,
    max_hn_fpr: float,
    regressions: pd.DataFrame,
) -> tuple[pd.DataFrame, dict[str, float], bool]:
    keys = list(GRID)
    results: list[dict[str, object]] = []

    for values in itertools.product(*GRID.values()):
        params = dict(zip(keys, values))
        cfg = with_params(base, **params)

        results.append(
            {
                **params,
                **evaluate(df, cfg),
                "regression_pass": regressions_pass(
                    regressions,
                    cfg,
                ),
            }
        )

    table = pd.DataFrame(results)

    regression_ok = table[table["regression_pass"]].copy()

    if regression_ok.empty:
        raise SystemExit(
            "No configuration in GRID passes all regression cases. "
            "Do not publish thresholds; expand/review GRID or the regression cases."
        )

    constrained = regression_ok[
        (regression_ok["fpr"] <= max_fpr)
        & (regression_ok["hn_fpr"] <= max_hn_fpr)
    ].copy()

    satisfied = not constrained.empty
    pool = constrained if satisfied else regression_ok

    top = pool[
        np.isclose(pool["f1"], pool["f1"].max())
    ].copy()

    # Choose one REAL evaluated configuration near the centre of the
    # best-F1 plateau. This avoids constructing a synthetic combination
    # that was never evaluated.
    medians = {
        k: float(top[k].median())
        for k in keys
    }

    distance = pd.Series(
        0.0,
        index=top.index,
        dtype=float,
    )

    for k in keys:
        span = float(max(GRID[k]) - min(GRID[k]))
        if span <= 0.0:
            span = 1.0

        distance = distance + (
            (top[k] - medians[k]) / span
        ) ** 2

    chosen_row = top.loc[distance.idxmin()]

    chosen = {
        k: float(chosen_row[k])
        for k in keys
    }

    return table, chosen, satisfied


def ablation(
    df: pd.DataFrame,
    cfg: Config,
) -> pd.DataFrame:
    truth = df["action_follows_injection"].to_numpy(bool)

    variants: dict[str, tuple[np.ndarray, str]] = {}

    classifier_cfg = with_params(
        cfg,
        uncorroborated_weight=1.0,
        corroboration_weight=0.0,
    )
    variants["classifier only"] = (
        alerts(df, classifier_cfg),
        "injection_score",
    )

    similarity_cfg = with_params(
        cfg,
        uncorroborated_weight=0.0,
        corroboration_weight=0.0,
    )
    similarity_scores = np.array(
        [
            m.confidence
            for m in mapped_rows(
                df.assign(injection_score=1.0),
                similarity_cfg,
            )
        ]
    )
    variants["similarity only"] = (
        similarity_scores >= 0.5,
        "-",
    )

    variants["both (fusion)"] = (
        alerts(df, cfg),
        "injection_score",
    )

    variants["chunking disabled"] = (
        alerts(
            df,
            cfg,
            "injection_score_nochunk",
        ),
        "injection_score_nochunk",
    )

    content = df["content_has_injection"].to_numpy(bool)
    rows = []

    for name, (pred, col) in variants.items():
        flag_recall: str | float = ""

        if col != "-":
            flag_recall = (
                round(
                    float(
                        (
                            df[col].to_numpy()
                            >= cfg.injection.flag_threshold
                        )[content].mean()
                    ),
                    4,
                )
                if content.any()
                else ""
            )

        metrics = prf(truth, pred)

        rows.append(
            {
                "variant": name,
                **{
                    k: round(v, 4)
                    for k, v in metrics.items()
                    if k in (
                        "precision",
                        "recall",
                        "f1",
                        "fpr",
                    )
                },
                "content_flag_recall": flag_recall,
            }
        )

    return pd.DataFrame(rows)


def families(
    df: pd.DataFrame,
    cfg: Config,
) -> pd.DataFrame:
    pred = pd.Series(
        alerts(df, cfg),
        index=df.index,
    )

    rows = []
    hij = df[df["kind"] == "hijacked_action"]

    for family, group in hij.groupby("family"):
        rows.append(
            {
                "group": f"attack: {family}",
                "rows": len(group),
                "alert_rate": round(
                    float(pred[group.index].mean()),
                    4,
                ),
                "scope": (
                    "in scope"
                    if group["in_scope"].iloc[0]
                    else "OUT OF SCOPE (user-authored; policy layer)"
                ),
            }
        )

    for kind in BENIGN_KINDS:
        group = df[df["kind"] == kind]

        if len(group):
            rows.append(
                {
                    "group": f"benign: {kind}",
                    "rows": len(group),
                    "alert_rate": round(
                        float(pred[group.index].mean()),
                        4,
                    ),
                    "scope": "false-positive rate",
                }
            )

    return pd.DataFrame(rows)


def md(df: pd.DataFrame) -> str:
    if hasattr(df, "to_markdown") and _has_tabulate():
        return df.to_markdown(
            index=False,
            floatfmt=".4f",
        )

    return "```\n" + df.to_string(index=False) + "\n```"


def _has_tabulate() -> bool:
    try:
        import tabulate  # noqa: F401

        return True
    except ImportError:
        return False


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__.splitlines()[0]
    )

    ap.add_argument(
        "--dataset",
        type=Path,
        default=ROOT / "calibration" / "data" / "dataset.csv",
    )
    ap.add_argument(
        "--out-dir",
        type=Path,
        default=ROOT / "calibration" / "report",
    )
    ap.add_argument(
        "--config",
        default=None,
    )
    ap.add_argument(
        "--max-fpr",
        type=float,
        default=0.10,
        help="max false-positive rate on all benign-action rows",
    )
    ap.add_argument(
        "--max-hn-fpr",
        type=float,
        default=0.0,
        help="max false-positive rate on hard negatives",
    )
    ap.add_argument(
        "--allow-stub",
        action="store_true",
        help="accept a stub-backend dataset (plumbing test only)",
    )
    ap.add_argument(
        "--regressions",
        type=Path,
        default=ROOT
        / "calibration"
        / "data"
        / "regression_signals.csv",
        help="CSV of regression signals that every recommended config must preserve",
    )

    args = ap.parse_args()

    df = pd.read_csv(args.dataset)

    if not args.regressions.exists():
        raise SystemExit(
            f"missing regression file: {args.regressions}"
        )

    regressions = pd.read_csv(args.regressions)
    validate_regressions(regressions)

    if (df["backend"] != "real").any() and not args.allow_stub:
        raise SystemExit(
            "dataset was built with the stub backend; "
            "those numbers are not evidence. "
            "Rebuild with real models, or pass --allow-stub "
            "to test the plumbing."
        )

    scoped = (
        df[df["in_scope"] == 1]
        .reset_index(drop=True)
    )

    base = load_config(args.config)
    args.out_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    flag_table, flag_threshold = sweep_content_flag(scoped)

    base = with_params(
        base,
        flag_threshold=flag_threshold,
    )

    fusion_table, chosen, satisfied = sweep_fusion(
        scoped,
        base,
        args.max_fpr,
        args.max_hn_fpr,
        regressions,
    )

    final = with_params(
        base,
        **chosen,
    )

    metrics = evaluate(
        scoped,
        final,
    )
    abl = ablation(
        scoped,
        final,
    )
    fam = families(
        df,
        final,
    )

    # Safety check: the selected configuration must still pass
    # the regression cases.
    if not regressions_pass(regressions, final):
        raise SystemExit(
            "internal error: selected configuration failed regression guards"
        )

    flag_table.round(4).to_csv(
        args.out_dir / "sweep_content_flag.csv",
        index=False,
    )
    fusion_table.round(4).to_csv(
        args.out_dir / "sweep_fusion.csv",
        index=False,
    )
    abl.to_csv(
        args.out_dir / "ablation.csv",
        index=False,
    )

    (
        args.out_dir / "ablation.md"
    ).write_text(
        md(abl) + "\n",
        encoding="utf-8",
    )

    (
        args.out_dir / "families.md"
    ).write_text(
        md(fam) + "\n",
        encoding="utf-8",
    )

    recommended = {
        "injection": {
            "flag_threshold": round(
                flag_threshold,
                2,
            )
        },
        "similarity": {
            "drift_threshold": chosen[
                "drift_threshold"
            ],
            "authorship_margin": chosen[
                "authorship_margin"
            ],
            "authorship_min_injection": (
                base.similarity.authorship_min_injection
            ),
        },
        "fusion": {
            "uncorroborated_weight": chosen[
                "uncorroborated_weight"
            ],
            "corroboration_weight": (
                base.fusion.corroboration_weight
            ),
            "min_injection_for_corroboration": (
                base.fusion.min_injection_for_corroboration
            ),
            "ramp_width": chosen[
                "ramp_width"
            ],
        },
        "labels": {
            "suspicious": chosen[
                "suspicious"
            ],
            "malicious": base.labels.malicious,
        },
    }

    (
        args.out_dir / "recommended_thresholds.yaml"
    ).write_text(
        yaml.safe_dump(
            recommended,
            sort_keys=False,
        ),
        encoding="utf-8",
    )

    warn = ""

    if not satisfied:
        warn = (
            "\n> **WARNING: no regression-passing configuration "
            f"met both constraints (hard-negative FPR <= {args.max_hn_fpr}, "
            f"overall FPR <= {args.max_fpr}).** "
            "The values below are the best-F1 configuration that still "
            "passes all regression cases. Report the FPR constraint failure "
            "honestly.\n"
        )

    n_pos = int(
        scoped["action_follows_injection"].sum()
    )
    n_neg = int(
        (~scoped["action_follows_injection"].astype(bool)).sum()
    )

    regression_count = len(regressions)

    summary = f"""# Calibration summary

Dataset: `{args.dataset.name}` - backend(s): {', '.join(sorted(df['backend'].unique()))}; {len(df)} rows, {len(scoped)} in scope
({n_pos} actions that follow an injection, {n_neg} that do not).
Regression guards: {regression_count}/{regression_count} passed.
Thresholds version tested: `{base.version}`.
{warn}
## Selected configuration

```yaml
{yaml.safe_dump(recommended, sort_keys=False)}```

On this dataset: precision {metrics['precision']:.3f}, recall {metrics['recall']:.3f}, F1 {metrics['f1']:.3f},
false-positive rate {metrics['fpr']:.3f}, hard-negative FPR {metrics['hn_fpr']:.3f},
precision of the `malicious` label {metrics['malicious_precision']:.3f}.

## Ablation (alert = label suspicious or malicious; truth = action follows the injection)

{md(abl)}

## By attack family and row kind

{md(fam)}

## Caveats to carry into the report

* {len(scoped)} in-scope rows from 19 scenarios is a small sample: thresholds chosen on it are fitted to it. There is no held-out set.
* The calibration additionally requires {regression_count} fixed regression cases to preserve known behaviour.
* Rows come from a fixed action-description convention (`build_dataset.describe_action`); a different orchestrator phrasing shifts the cosines.
* Direct-instruction attacks are user-authored and out of scope for this module by design.
"""

    (
        args.out_dir / "summary.md"
    ).write_text(
        summary,
        encoding="utf-8",
    )

    print(summary)


if __name__ == "__main__":
    main()
