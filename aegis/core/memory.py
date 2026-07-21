"""Structured memory & learning.

Memory in AEGIS spans three tiers, all backed by the SQLite store so they persist
across runs and keep every assessment reproducible:

* **Working memory** — the live blackboard for the current assessment (held on the
  graph state; not here).
* **Episodic memory** — the durable record of what happened: observations,
  findings, and which prompt variants produced signal.
* **Semantic / regression memory** — accepted baselines per (target, dimension,
  metric) used to detect drift and to *bias future strategy* toward transforms
  that have historically been informative for a given target family.

This is how the platform "learns" without sacrificing reproducibility: priors
change *which* probes are prioritised, never *how* a given probe is scored.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Optional

from ..storage.db import Database
from .types import Observation


@dataclass
class RegressionResult:
    dimension: str
    metric: str
    baseline: float
    current: float
    tolerance: float
    regressed: bool
    delta: float


class Memory:
    def __init__(self, db: Database, target_key: str = "default") -> None:
        self.db = db
        self.target_key = target_key

    # -- episodic ----------------------------------------------------------- #
    def note(self, key: str, value: dict) -> None:
        self.db.mem_put("episodic", key, value)

    def recall(self, key: str) -> list[dict]:
        return self.db.mem_get("episodic", key)

    def record_variant_signal(self, transform: str, informative: bool) -> None:
        """Track whether a transform lineage produced a notable observation.

        Used to prioritise historically-informative transforms in later rounds
        and future assessments (a bandit-style prior).
        """
        self.db.mem_put("variant_signal",
                        f"{self.target_key}:{transform}",
                        {"informative": bool(informative)})

    def transform_priors(self, transforms: list[str]) -> dict[str, float]:
        """Return a 0..1 prior weight per transform from historical signal."""
        priors: dict[str, float] = {}
        for t in transforms:
            hist = self.db.mem_get("variant_signal", f"{self.target_key}:{t}")
            if not hist:
                priors[t] = 0.5
                continue
            hits = sum(1 for h in hist if h.get("informative"))
            # Laplace-smoothed hit rate.
            priors[t] = (hits + 1) / (len(hist) + 2)
        return priors

    # -- semantic / regression --------------------------------------------- #
    def set_baseline(self, dimension: str, metric: str, value: float,
                     tolerance: float = 0.1) -> None:
        self.db.set_baseline(self.target_key, dimension, metric, value, tolerance)

    def check_regression(self, dimension: str, metric: str,
                         current: float) -> Optional[RegressionResult]:
        base = self.db.get_baseline(self.target_key, dimension, metric)
        if not base:
            return None
        delta = current - base["value"]
        # For higher-is-better metrics a drop beyond tolerance is a regression.
        regressed = (base["value"] - current) > base["tolerance"]
        return RegressionResult(dimension, metric, base["value"], current,
                                base["tolerance"], regressed, delta)

    def learn_baselines(self, observations: list[Observation]) -> None:
        """Persist current observations as accepted baselines (first-run seeding)."""
        for o in observations:
            self.set_baseline(o.dimension, o.metric, o.value)

    # -- summaries ---------------------------------------------------------- #
    def dimension_histogram(self) -> dict[str, int]:
        rows = self.db.mem_get("episodic", "dimension_touch")
        return dict(Counter(r.get("dimension", "?") for r in rows))
