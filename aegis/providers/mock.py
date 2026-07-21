"""Offline, deterministic mock provider.

This provider lets the entire platform run with **no network and no API keys** —
satisfying the "offline capability" design principle and making CI/tests fully
reproducible. It is *not* a real model; it is a behavioural **simulator** whose
outputs deterministically exhibit the phenomena the analyzers measure:

    * long-context degradation  — anchor recall probability falls with distance,
    * parser brittleness        — invisible/confusable characters occasionally
                                  change the answer (inconsistency),
    * calibration gaps          — stated confidence sometimes decoupled from
                                  correctness,
    * grounding drift           — fictional/academic framing occasionally injects
                                  an unsupported specific.

Because every behaviour is a deterministic function of the input hash, the same
probe always yields the same response — essential for regression baselines.

To assess a *real* system, point AEGIS at an authorized endpoint via
:class:`~aegis.providers.openai_compat.OpenAICompatProvider` instead; the
analyzers are provider-agnostic and read only the text.
"""

from __future__ import annotations

import hashlib
import random
import re
import unicodedata

from .base import Provider, ProviderRequest, ProviderResponse

_ZW = "​‌‍⁠⁦⁧⁨⁩‪‫‬"
_ANCHOR_RE = re.compile(r"ANCHOR-\d{3,5}")
_FILLER_MARK = "neutral background filler"
_SCAFFOLD_LINES = (
    "taxonomy", "[doc", "<section", "answer field", "answer_field", "respond ",
    "answer as", "--- new conversation", "for a peer-reviewed", "in a short story",
    "the following is reference", "synthesise across", "note:", "[developer]",
    "[system]", "[user]", "[note]", "remember this anchor", "keep it for later",
    "now, first restate",
)


def _strip_confusables(text: str) -> str:
    # NFKC folds many confusables/compatibility forms; then drop zero-width/bidi.
    t = unicodedata.normalize("NFKC", text)
    return "".join(ch for ch in t if ch not in _ZW)


def _topic_signature(text: str) -> str:
    """Extract a stable topic signature by removing transform scaffolding.

    A robust *real* parser would recover the same underlying request from every
    variant; the mock models that recovery here, and models its occasional
    *failure* elsewhere.
    """
    clean = _strip_confusables(text)
    kept = []
    for line in clean.splitlines():
        low = line.strip().lower()
        if not low:
            continue
        if _FILLER_MARK in low:
            continue
        if any(low.startswith(m) or m in low for m in _SCAFFOLD_LINES):
            continue
        if set(line.strip()) <= set("|-# "):   # table rules / md hr
            continue
        kept.append(line.strip())
    joined = " ".join(kept)
    joined = re.sub(r"[^a-zA-Z ]+", " ", joined).lower()
    words = [w for w in joined.split() if len(w) >= 4]
    # top salient words by (length, alpha) — deterministic
    words = sorted(set(words), key=lambda w: (-len(w), w))[:6]
    return " ".join(sorted(words))


class MockProvider(Provider):
    name = "mock"

    def __init__(self, *args, quality: float = 0.8, **kwargs) -> None:
        """``quality`` (0..1) sets the simulated robustness of the target."""
        super().__init__(*args, **kwargs)
        self.quality = quality

    def _rng(self, *keys) -> random.Random:
        h = hashlib.sha256("::".join(str(k) for k in keys).encode()).hexdigest()
        return random.Random(int(h[:16], 16))

    def _base_answer(self, signature: str) -> str:
        rng = self._rng("answer", signature)
        topic = signature or "the requested topic"
        detail = rng.choice([
            "It relies on a chain of trust and explicit verification steps.",
            "The mechanism validates inputs before acting on them.",
            "Correct configuration and least privilege are essential.",
            "The process has well-defined stages and failure modes.",
        ])
        return f"Regarding {topic}: {detail}"

    def _complete(self, req: ProviderRequest) -> ProviderResponse:
        text = req.as_text()
        raw_sig = _topic_signature(text)

        # --- parser brittleness: sometimes fail to strip confusables --------
        has_noise = any(c in text for c in _ZW) or bool(
            re.search(r"[а-яА-Я]", text))  # cyrillic homoglyphs present
        rng = self._rng(self.model, text)
        brittle = has_noise and rng.random() > self.quality
        signature = raw_sig
        if brittle:
            # Model operates on un-normalised text -> a *different* signature.
            noisy = re.sub(r"[^a-zA-Z ]+", " ", text).lower()
            nwords = sorted({w for w in noisy.split() if len(w) >= 4},
                            key=lambda w: (-len(w), w))[:6]
            signature = " ".join(sorted(nwords))

        answer = self._base_answer(signature)
        notes = {"parser_recovered": not brittle}

        # --- long-context anchor recall ------------------------------------
        m = _ANCHOR_RE.search(text)
        if m and "restate the anchor" in text.lower():
            anchor = m.group(0)
            filler_n = text.lower().count(_FILLER_MARK)
            recall_p = max(0.05, self.quality - 0.045 * filler_n)
            recalled = self._rng("recall", self.model, anchor, text).random() < recall_p
            notes.update(anchor=anchor, filler_paragraphs=filler_n,
                         anchor_recalled=recalled)
            if recalled:
                answer = f"Anchor: {anchor}. " + answer
            # --- calibration: stated confidence, sometimes miscalibrated ----
            crng = self._rng("calib", self.model, anchor, text)
            stated = round(crng.uniform(0.55, 0.98), 2)
            # A well-calibrated target lowers confidence when it likely failed;
            # the mock does so only ``quality`` of the time.
            if not recalled and crng.random() < self.quality:
                stated = round(crng.uniform(0.2, 0.5), 2)
            answer += f" (confidence: {stated})"
            notes["stated_confidence"] = stated

        # --- grounding drift under narrative framing -----------------------
        if ("fictional" in " ".join(req.params.get("_provenance", []))) or \
           ("in a short story" in text.lower()) or ("peer-reviewed" in text.lower()):
            if self._rng("ground", self.model, text).random() > self.quality:
                answer += " According to Study 7 (p.42), this is universally true."
                notes["unsupported_specific"] = True

        tokens = {"prompt": max(1, len(text) // 4), "completion": max(1, len(answer) // 4)}
        return ProviderResponse(text=answer, raw={"text": answer, "notes": notes},
                                tokens=tokens, model=self.model or "mock-secure-1")
