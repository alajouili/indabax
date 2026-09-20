# Calibration summary

Dataset: `dataset.csv` - backend(s): real; 82 rows, 75 in scope
(17 actions that follow an injection, 58 that do not).
Regression guards: 2/2 passed.
Thresholds version tested: `2026-09-20-b`.

## Selected configuration

```yaml
injection:
  flag_threshold: 0.78
similarity:
  drift_threshold: 0.3
  authorship_margin: 0.2
  authorship_min_injection: 0.1
fusion:
  uncorroborated_weight: 0.35
  corroboration_weight: 0.6
  min_injection_for_corroboration: 0.0001
  ramp_width: 0.1
labels:
  suspicious: 0.6
  malicious: 0.85
```

On this dataset: precision 0.769, recall 0.588, F1 0.667,
false-positive rate 0.052, hard-negative FPR 0.000,
precision of the `malicious` label 0.000.

## Ablation (alert = label suspicious or malicious; truth = action follows the injection)

| variant           |   precision |   recall |     f1 |    fpr |   content_flag_recall |
|:------------------|------------:|---------:|-------:|-------:|----------------------:|
| classifier only   |      0.0000 |   0.0000 | 0.0000 | 0.1379 |                0.0233 |
| similarity only   |      0.5217 |   0.7059 | 0.6000 | 0.1897 |                       |
| both (fusion)     |      0.7692 |   0.5882 | 0.6667 | 0.0517 |                0.0233 |
| chunking disabled |      0.7500 |   0.5294 | 0.6207 | 0.0517 |                0.0233 |

## By attack family and row kind

| group                                  |   rows |   alert_rate | scope                                      |
|:---------------------------------------|-------:|-------------:|:-------------------------------------------|
| attack: direct_instruction             |      7 |       0.0000 | OUT OF SCOPE (user-authored; policy layer) |
| attack: indirect_prompt_injection      |      9 |       0.5556 | in scope                                   |
| attack: memory_poisoning               |      6 |       0.8333 | in scope                                   |
| attack: multi_step                     |      2 |       0.0000 | in scope                                   |
| benign: legitimate_action              |     11 |       0.0909 | false-positive rate                        |
| benign: benign                         |     12 |       0.0000 | false-positive rate                        |
| benign: hard_negative                  |      9 |       0.0000 | false-positive rate                        |
| benign: poisoned_context_benign_action |     26 |       0.0769 | false-positive rate                        |

## Caveats to carry into the report

* 75 in-scope rows from 19 scenarios is a small sample: thresholds chosen on it are fitted to it. There is no held-out set.
* The calibration additionally requires 2 fixed regression cases to preserve known behaviour.
* Rows come from a fixed action-description convention (`build_dataset.describe_action`); a different orchestrator phrasing shifts the cosines.
* Direct-instruction attacks are user-authored and out of scope for this module by design.
