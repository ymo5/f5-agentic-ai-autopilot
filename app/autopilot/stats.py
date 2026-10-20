"""Latency statistics used everywhere a percentile is displayed (ingest edges, validation perf, comparisons).

One definition only — nearest-rank percentiles — so p50 <= p95 <= max always holds. The sample count is reported
with every summary because a p95 over a handful of samples is not meaningful (the UI says so).
"""
from __future__ import annotations

import math

MIN_SAMPLES_FOR_P95 = 20


def percentile(values, q: float) -> float | None:
    """Nearest-rank percentile (q in 0..100). Monotonic in q; returns an observed sample, never an interpolation."""
    s = sorted(v for v in values if v is not None)
    if not s:
        return None
    rank = max(1, math.ceil(q / 100 * len(s)))
    return s[min(rank, len(s)) - 1]


def latency_summary(values_ms, digits: int = 1) -> dict | None:
    s = [v for v in values_ms if v is not None]
    if not s:
        return None
    return {"n": len(s), "p50": round(percentile(s, 50), digits), "p95": round(percentile(s, 95), digits),
            "max": round(max(s), digits), "p95_reliable": len(s) >= MIN_SAMPLES_FOR_P95}
