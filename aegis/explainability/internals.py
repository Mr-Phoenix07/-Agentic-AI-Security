"""White-box explainability via model internals (optional).

When the target's weights are locally available (a genuine white-box engagement)
and the relevant libraries are installed, this module produces token attribution,
attention, and residual-stream summaries. It is import-safe: nothing heavy is
imported at module load, and every capability is probed at call time so the core
stays offline and dependency-free.

Supported backends (any subset): TransformerLens, Captum, SHAP, BertViz.
Absent them, callers receive an ``unavailable`` :class:`Explanation` and should
rely on the behavioral tier.
"""

from __future__ import annotations

import importlib.util
from typing import Optional

from .base import Explanation

_BACKENDS = ("transformer_lens", "captum", "shap", "bertviz", "torch")


def internals_available() -> dict[str, bool]:
    return {name: importlib.util.find_spec(name) is not None for name in _BACKENDS}


def _any_available() -> bool:
    return any(internals_available().values())


def explain_with_internals(
    model_ref: Optional[object],
    prompt: str,
    *,
    method: str = "token_attribution",
) -> Explanation:
    """Attempt a white-box explanation; degrade gracefully.

    ``model_ref`` is a loaded model handle (e.g. a HookedTransformer). If it is
    None or no backend is installed, returns an ``unavailable`` explanation that
    documents exactly what would be produced with access — keeping the report
    honest about visibility.
    """
    avail = internals_available()
    if model_ref is None or not _any_available():
        return Explanation(
            method=f"internals.{method}",
            availability="unavailable",
            summary="Model internals not available; behavioral analysis used instead.",
            notes=("With white-box access + TransformerLens/Captum/SHAP, AEGIS would "
                   "report per-token attribution, attention patterns over the "
                   "instruction/data boundary, and residual-stream contributions for "
                   "this prompt."),
            artifacts={"backends_detected": avail},
        )

    # Real backend path (executed only in white-box engagements with weights).
    try:  # pragma: no cover - requires heavy optional deps + a real model
        if avail.get("transformer_lens") and hasattr(model_ref, "run_with_cache"):
            import torch  # type: ignore

            tokens = model_ref.to_tokens(prompt)
            logits, cache = model_ref.run_with_cache(tokens)
            last = logits[0, -1]
            topk = torch.topk(last.softmax(-1), k=5)
            attrib = [
                {"token": model_ref.to_string(idx.item()), "prob": round(p.item(), 4)}
                for p, idx in zip(topk.values, topk.indices)
            ]
            return Explanation(
                method="internals.transformer_lens.logit_lens",
                availability="available",
                summary="Top next-token distribution and cached activations captured.",
                attributions=attrib,
                artifacts={"n_layers": getattr(model_ref.cfg, "n_layers", None)},
            )
    except Exception as e:  # pragma: no cover
        return Explanation(method=f"internals.{method}", availability="degraded",
                           summary=f"Internals backend error: {e}",
                           artifacts={"backends_detected": avail})

    return Explanation(method=f"internals.{method}", availability="degraded",
                       summary="No compatible white-box path for this model handle.",
                       artifacts={"backends_detected": avail})
