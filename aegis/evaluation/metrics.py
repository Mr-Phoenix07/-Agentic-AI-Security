"""Evaluation metrics — the quantitative backbone.

Pure functions over text/values so they are trivially unit-testable and stable.
Each metric returns a plain float (or small dict) and documents its direction so
observations can be interpreted consistently.
"""

from __future__ import annotations

import math
import re
from collections import Counter

_WORD = re.compile(r"[a-z0-9]{2,}")


def _bag(text: str) -> Counter:
    return Counter(_WORD.findall((text or "").lower()))


def cosine_similarity(a: str, b: str) -> float:
    """Cosine similarity over word-frequency bags. 1.0 == identical vocab/freq."""
    ba, bb = _bag(a), _bag(b)
    if not ba or not bb:
        return 1.0 if ba == bb else 0.0
    common = set(ba) & set(bb)
    dot = sum(ba[w] * bb[w] for w in common)
    na = math.sqrt(sum(v * v for v in ba.values()))
    nb = math.sqrt(sum(v * v for v in bb.values()))
    return dot / (na * nb) if na and nb else 0.0


def jaccard(a: str, b: str) -> float:
    sa, sb = set(_WORD.findall((a or "").lower())), set(_WORD.findall((b or "").lower()))
    if not sa and not sb:
        return 1.0
    return len(sa & sb) / len(sa | sb) if (sa | sb) else 0.0


def consistency_score(texts: list[str]) -> float:
    """Mean pairwise cosine similarity across responses. Higher == more stable.

    This is the core robustness signal: semantically-equivalent prompt variants
    should yield semantically-similar answers.
    """
    n = len(texts)
    if n < 2:
        return 1.0
    total, pairs = 0.0, 0
    for i in range(n):
        for j in range(i + 1, n):
            total += cosine_similarity(texts[i], texts[j])
            pairs += 1
    return total / pairs if pairs else 1.0


def rate(successes: int, n: int) -> float:
    return successes / n if n else 0.0


def expected_calibration_error(pairs: list[tuple[float, bool]], bins: int = 10) -> float:
    """ECE over (stated_confidence, was_correct) pairs. Lower == better calibrated.

    Partitions confidences into ``bins`` buckets and averages |accuracy - mean
    confidence| weighted by bucket population.
    """
    if not pairs:
        return 0.0
    buckets: list[list[tuple[float, bool]]] = [[] for _ in range(bins)]
    for conf, correct in pairs:
        idx = min(bins - 1, max(0, int(conf * bins)))
        buckets[idx].append((conf, correct))
    n = len(pairs)
    ece = 0.0
    for bucket in buckets:
        if not bucket:
            continue
        acc = sum(1 for _, c in bucket if c) / len(bucket)
        conf = sum(cf for cf, _ in bucket) / len(bucket)
        ece += (len(bucket) / n) * abs(acc - conf)
    return ece


def brier_score(pairs: list[tuple[float, bool]]) -> float:
    """Mean squared error between confidence and outcome. Lower == better."""
    if not pairs:
        return 0.0
    return sum((conf - (1.0 if correct else 0.0)) ** 2 for conf, correct in pairs) / len(pairs)


def coverage_fraction(covered: set[str], universe: set[str]) -> float:
    if not universe:
        return 1.0
    return len(covered & universe) / len(universe)


def contains_anchor(text: str, anchor: str) -> bool:
    return bool(anchor) and anchor in (text or "")


def grounding_rate(traces: list[dict]) -> float:
    """Fraction of RAG responses whose citations are all supported by retrieval."""
    if not traces:
        return 1.0
    ok = 0
    for t in traces:
        cited = set(t.get("cited_ids", []))
        retrieved = set(t.get("retrieved_ids", []))
        if not cited:
            continue
        if cited <= retrieved:
            ok += 1
    denom = sum(1 for t in traces if t.get("cited_ids"))
    return ok / denom if denom else 1.0
