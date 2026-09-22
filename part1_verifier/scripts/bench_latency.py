from __future__ import annotations

import argparse
import json
import statistics
import time
from pathlib import Path

from sentinel_verifier.verify import verify


def percentile(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, max(0, round((len(ordered) - 1) * p)))
    return ordered[idx]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--samples", default="samples/requests")
    parser.add_argument("--repeat", type=int, default=50)
    args = parser.parse_args()

    samples = []
    for path in sorted(Path(args.samples).glob("*.json")):
        samples.append((path.name, json.loads(path.read_text(encoding="utf-8"))))

    if not samples:
        raise SystemExit("No samples found")

    times_ms: list[float] = []
    for _ in range(args.repeat):
        for _, sample in samples:
            start = time.perf_counter()
            verify(sample)
            times_ms.append((time.perf_counter() - start) * 1000)

    print(f"calls={len(times_ms)}")
    print(f"mean_ms={statistics.mean(times_ms):.3f}")
    print(f"p50_ms={percentile(times_ms, 0.50):.3f}")
    print(f"p95_ms={percentile(times_ms, 0.95):.3f}")
    print(f"max_ms={max(times_ms):.3f}")


if __name__ == "__main__":
    main()
