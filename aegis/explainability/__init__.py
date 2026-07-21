"""Explainability layer.

Two tiers, matching evaluation visibility:

* **Behavioral** (always available, black-box): explains *why* an observation was
  made from evidence alone — which transform families drove a divergence, the
  recall-vs-distance curve behind a long-context score, a contrastive token diff
  between the baseline and the most-divergent variant.
* **Internals** (white-box, optional): token attribution / attention / residual
  analysis via TransformerLens, SHAP, Captum, BertViz when the target's weights
  are available. Absent those libraries or access, the platform degrades
  gracefully to behavioral-only and says so explicitly.
"""

from __future__ import annotations

from .base import Explanation
from .behavioral import explain_observation
from .internals import explain_with_internals, internals_available

__all__ = ["Explanation", "explain_observation", "internals_available",
           "explain_with_internals"]
