"""Modular prompt-transformation framework for robustness testing.

Transforms are semantically-preserving re-encodings of benign requests, used to
measure a target's parser resilience, consistency, calibration, and long-context
behaviour — not to bypass safeguards.
"""

from __future__ import annotations

from .engine import MutationEngine, Seed, Variant
from .transforms import REGISTRY, Transform, default_transforms

__all__ = ["MutationEngine", "Seed", "Variant", "Transform",
           "default_transforms", "REGISTRY"]
