| group                                  |   rows |   alert_rate | scope                                      |
|:---------------------------------------|-------:|-------------:|:-------------------------------------------|
| attack: direct_instruction             |      7 |       0.0000 | OUT OF SCOPE (user-authored; policy layer) |
| attack: indirect_prompt_injection      |      9 |       0.5556 | in scope                                   |
| attack: memory_poisoning               |      6 |       1.0000 | in scope                                   |
| attack: multi_step                     |      2 |       0.0000 | in scope                                   |
| benign: legitimate_action              |     11 |       0.0909 | false-positive rate                        |
| benign: benign                         |     12 |       0.0000 | false-positive rate                        |
| benign: hard_negative                  |      9 |       0.0000 | false-positive rate                        |
| benign: poisoned_context_benign_action |     26 |       0.1154 | false-positive rate                        |
