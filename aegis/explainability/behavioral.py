"""Behavioral (black-box) explainability.

Turns an :class:`~aegis.core.types.Observation` plus its underlying probe/result
pairs into a human-readable explanation grounded in evidence:

* **transform attribution** — which transforms/families most changed the answer,
* **recall-vs-distance** — the long-context degradation curve,
* **contrastive token diff** — tokens present in the baseline answer but dropped
  (or newly introduced) in the most-divergent variant.

No model internals required; works identically on the mock and on a real target.
"""

from __future__ import annotations

import re

from ..core.types import Observation
from ..evaluation import metrics
from ..evaluation.behavioral import ProbePair
from .base import Explanation

_WORD = re.compile(r"[a-zA-Z0-9]{3,}")


def _tokens(s: str) -> list[str]:
    return _WORD.findall((s or "").lower())


def _transform_attribution(baseline_text: str, pairs: list[ProbePair]) -> list[dict]:
    contrib: dict[str, list[float]] = {}
    for p in pairs:
        if p.probe.provenance == ["identity"]:
            continue
        sim = metrics.cosine_similarity(baseline_text, p.result.text)
        div = 1 - sim
        for t in p.probe.provenance:
            contrib.setdefault(t, []).append(div)
    ranked = [
        {"transform": t, "mean_divergence": round(sum(v) / len(v), 4), "n": len(v)}
        for t, v in contrib.items()
    ]
    ranked.sort(key=lambda x: x["mean_divergence"], reverse=True)
    return ranked


def _contrastive_diff(baseline_text: str, pairs: list[ProbePair]) -> dict:
    worst, worst_div = None, -1.0
    for p in pairs:
        if p.probe.provenance == ["identity"]:
            continue
        div = 1 - metrics.cosine_similarity(baseline_text, p.result.text)
        if div > worst_div:
            worst_div, worst = div, p
    if worst is None:
        return {}
    base_t, var_t = set(_tokens(baseline_text)), set(_tokens(worst.result.text))
    return {
        "most_divergent_transform": "+".join(worst.probe.provenance),
        "divergence": round(worst_div, 4),
        "dropped_tokens": sorted(base_t - var_t)[:15],
        "introduced_tokens": sorted(var_t - base_t)[:15],
    }


def explain_observation(obs: Observation, pairs: list[ProbePair]) -> Explanation:
    baseline = next((p for p in pairs if p.probe.provenance == ["identity"]), None)
    base_text = baseline.result.text if baseline else ""

    if obs.dimension == "long_context_retention":
        curve = obs.context.get("recall_by_distance", [])
        # Aggregate recall by distance bucket.
        buckets: dict[int, list[int]] = {}
        for dist, ok in curve:
            buckets.setdefault(dist, []).append(1 if ok else 0)
        agg = [{"distance": d, "recall": round(sum(v) / len(v), 3), "n": len(v)}
               for d, v in sorted(buckets.items())]
        trend = ("recall declines as distance grows"
                 if len(agg) >= 2 and agg[0]["recall"] > agg[-1]["recall"]
                 else "recall roughly flat across tested distances")
        return Explanation(
            method="behavioral.long_context_curve",
            summary=f"Anchor recall {obs.value:.0%}; {trend}.",
            artifacts={"recall_by_distance": agg},
            notes="Distances are filler-paragraph counts between anchor and query.")

    if obs.dimension == "confidence_calibration":
        return Explanation(
            method="behavioral.calibration",
            summary=f"ECE {obs.value:.2f} (Brier "
                    f"{obs.context.get('brier','?')}): stated confidence is "
                    f"{'poorly' if obs.value > 0.15 else 'reasonably'} aligned with "
                    "actual recall.",
            notes="Confidence parsed from responses; correctness = anchor recalled.")

    # Default: transform attribution + contrastive diff.
    attributions = _transform_attribution(base_text, pairs)
    diff = _contrastive_diff(base_text, pairs)
    top = attributions[0]["transform"] if attributions else "n/a"
    return Explanation(
        method="behavioral.transform_attribution",
        summary=f"'{obs.dimension}' driven most by transform '{top}'. "
                f"{'Answer content shifts materially under it.' if attributions and attributions[0]['mean_divergence'] > 0.25 else 'Effect is modest.'}",
        attributions=attributions[:8],
        artifacts={"contrastive_diff": diff},
    )
