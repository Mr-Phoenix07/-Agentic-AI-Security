"""Confidence estimation utilities.

Confidence in AEGIS is evidence-driven, not vibes-driven. These helpers convert
raw observation counts and effect sizes into calibrated :class:`Confidence`
objects with an explicit rationale, so every certainty claim is auditable.
"""

from __future__ import annotations

import math

from .types import Confidence, clamp01


def wilson_interval(successes: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score confidence interval (lo, hi) for a proportion."""
    if n == 0:
        return (0.0, 1.0)
    phat = successes / n
    denom = 1 + z * z / n
    centre = (phat + z * z / (2 * n)) / denom
    margin = (z * math.sqrt((phat * (1 - phat) + z * z / (4 * n)) / n)) / denom
    return (clamp01(centre - margin), clamp01(centre + margin))


def wilson_lower_bound(successes: int, n: int, z: float = 1.96) -> float:
    """Wilson score lower bound of a proportion (conservative on small samples)."""
    return wilson_interval(successes, n, z)[0]


def measurement_confidence(value: float, n: int, *, dimension: str = "") -> Confidence:
    """Confidence in the *reliability* of a measurement — driven by sample size
    and interval width, **not** by whether the measured value is good or bad.

    A poorly-performing dimension measured over many trials is a *high-confidence*
    finding (we are sure it is poor); a single trial is low-confidence whatever
    the value. Implemented as ``1 - width(Wilson 95% CI)`` treating a continuous
    [0,1] metric as a pseudo-proportion for precision accounting.
    """
    value = clamp01(value)
    successes = round(value * n)
    lo, hi = wilson_interval(successes, max(n, 1))
    width = hi - lo
    conf = clamp01(1.0 - width)
    return Confidence(
        value=conf,
        rationale=f"n={n}, 95% CI width {width:.2f} for {dimension or 'metric'} "
                  f"(value {value:.2f})",
        sample_size=n,
    )


def from_effect(rate: float, n: int, *, dimension: str = "") -> Confidence:
    """Confidence that an effect is *real and reproducible* given a hit-rate.

    Combines the observed rate with a sample-size discount so that a strong
    effect seen across many trials scores high, while the same rate on n=1 does
    not. This is intentionally conservative — false positives are costly in
    security reporting.
    """
    rate = clamp01(rate)
    successes = round(rate * n)
    lb = wilson_lower_bound(successes, max(n, 1))
    # Blend point estimate with its lower bound; weight toward LB for small n.
    w = 1.0 / (1.0 + math.exp(-(n - 5) / 3.0))   # sigmoid on sample size
    value = clamp01(w * rate + (1 - w) * lb)
    rationale = (
        f"observed rate {rate:.2f} over n={n} "
        f"(Wilson LB {lb:.2f}); {dimension or 'effect'} "
        f"{'stable' if n >= 5 else 'preliminary'}"
    )
    return Confidence(value=value, rationale=rationale, sample_size=n)


def agree(confidences: list[Confidence]) -> Confidence:
    """Aggregate multiple independent confidences (noisy-OR style).

    Independent corroboration should *raise* confidence, so we combine via
    ``1 - prod(1 - c)`` while keeping the weakest rationale visible.
    """
    if not confidences:
        return Confidence(0.0, "no supporting confidences", 0)
    prod = 1.0
    n = 0
    for c in confidences:
        prod *= (1 - c.value)
        n += c.sample_size
    value = clamp01(1 - prod)
    return Confidence(
        value=value,
        rationale=f"aggregated from {len(confidences)} sources (noisy-OR)",
        sample_size=n,
    )
