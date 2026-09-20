"""C6 - the two cosines.

* task drift  = cos(user task, proposed action): is the agent still doing what was asked?
* authorship  = cos(untrusted evidence, proposed action): is the plan written in the
  voice of the untrusted text instead of the user's?

The pair is what separates "the vendor dispute asks for a token" (drift stays high,
authorship is high too) from a genuine reply. Negative cosines are clipped to 0 because
the output contract is a 0-1 float and a negative value carries no extra meaning here.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np


def cosine(a: np.ndarray, b: np.ndarray) -> float:
    """Cosine similarity clipped to [0, 1]; zero vectors give 0.0."""
    norm = float(np.linalg.norm(a) * np.linalg.norm(b))
    if norm == 0.0 or not np.isfinite(norm):
        return 0.0
    value = float(np.dot(a, b)) / norm
    return min(1.0, max(0.0, value))


@dataclass(frozen=True)
class Similarities:
    task_action: float | None  # None when the task or the action text is missing
    source_action: float | None  # None when there is no untrusted content to compare


def compute_similarities(
    task_vec: np.ndarray | None,
    action_vec: np.ndarray | None,
    source_vec: np.ndarray | None,
) -> Similarities:
    task_action = cosine(task_vec, action_vec) if task_vec is not None and action_vec is not None else None
    source_action = cosine(source_vec, action_vec) if source_vec is not None and action_vec is not None else None
    return Similarities(task_action=task_action, source_action=source_action)