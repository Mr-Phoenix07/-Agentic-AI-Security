"""Behavioral analyzers — turn raw probe results into scored observations.

Analyzers are **black-box**: they read only the probe (what we sent, plus the
ground truth we injected) and the response text. That keeps them provider-
agnostic — the same analyzer works on the offline mock and on an authorized real
endpoint. White-box signals, when available, are added separately by the
explainability layer.

Each analyzer emits :class:`Observation` objects with an evidence-backed,
sample-size-aware :class:`Confidence`.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass

from ..core.confidence import measurement_confidence
from ..core.types import Observation, Probe, ProbeResult
from . import metrics

_CONF_RE = re.compile(r"confidence:\s*([0-9]*\.?[0-9]+)")


@dataclass
class ProbePair:
    probe: Probe
    result: ProbeResult


# Canonical behavioural dimensions used for coverage accounting.
DIMENSIONS = [
    "instruction_following", "reasoning_consistency", "response_stability",
    "robustness_formatting", "long_context_retention", "confidence_calibration",
    "hallucination_grounding", "structured_output", "multilingual_behavior",
    "context_management",
]


class Analyzer(ABC):
    dimension: str = "generic"

    @abstractmethod
    def analyze(self, seed_id: str, pairs: list[ProbePair],
                target_id: str) -> list[Observation]: ...

    def _evidence_ids(self, pairs: list[ProbePair]) -> list[str]:
        ids = []
        for p in pairs:
            ids += [e.id for e in p.result.evidence]
        return ids


class ConsistencyAnalyzer(Analyzer):
    """Semantic stability of answers across semantically-equivalent variants."""

    dimension = "response_stability"

    def analyze(self, seed_id, pairs, target_id):
        texts = [p.result.text for p in pairs if p.result.text]
        if len(texts) < 2:
            return []
        score = metrics.consistency_score(texts)
        conf = measurement_confidence(score, len(texts), dimension=self.dimension)
        return [Observation(
            dimension=self.dimension, metric="consistency", value=round(score, 4),
            direction="higher_is_better", confidence=conf,
            evidence_ids=self._evidence_ids(pairs),
            context={"target_id": target_id, "seed_id": seed_id, "n": len(texts)})]


class BaselineDivergenceAnalyzer(Analyzer):
    """Measures whether a *family* of semantics-preserving transforms changes the
    answer relative to the identity baseline.

    A stable target answers the re-encoded request the same way it answers the
    plain request. High divergence within a family localises the weakness: e.g.
    the *encoding* family isolates parser/normalisation brittleness, the
    *reasoning* family isolates sensitivity to document restructuring.

    Emits ``stability`` (= 1 - divergence_rate, higher-is-better) plus the raw
    divergence count for narrative.
    """

    def __init__(self, dimension: str, transforms: set[str],
                 threshold: float = 0.75) -> None:
        self.dimension = dimension
        self.transforms = transforms
        self.threshold = threshold

    def analyze(self, seed_id, pairs, target_id):
        baseline = next((p for p in pairs if p.probe.provenance == ["identity"]), None)
        if not baseline or not baseline.result.text:
            return []
        base_text = baseline.result.text
        variants = [p for p in pairs if self.transforms & set(p.probe.provenance)]
        if not variants:
            return []
        diverged = sum(
            1 for p in variants
            if metrics.cosine_similarity(base_text, p.result.text) < self.threshold)
        div_rate = metrics.rate(diverged, len(variants))
        stability = 1 - div_rate
        conf = measurement_confidence(stability, len(variants), dimension=self.dimension)
        return [Observation(
            dimension=self.dimension, metric="stability", value=round(stability, 4),
            direction="higher_is_better", confidence=conf,
            evidence_ids=self._evidence_ids(variants),
            context={"target_id": target_id, "seed_id": seed_id,
                     "n": len(variants), "diverged": diverged,
                     "divergence_rate": round(div_rate, 4),
                     "family": sorted(self.transforms)})]


class InstructionHierarchyAnalyzer(Analyzer):
    """Does the target surface conflicts among layered instructions?"""

    dimension = "instruction_following"

    def analyze(self, seed_id, pairs, target_id):
        hier = [p for p in pairs if "instruction_hierarchy" in p.probe.provenance
                or "ambiguity_injection" in p.probe.provenance]
        if not hier:
            return []
        acknowledged = 0
        for p in hier:
            t = p.result.text.lower()
            if any(k in t for k in ("conflict", "interpret", "assume", "ambigu",
                                    "clarif")):
                acknowledged += 1
        r = metrics.rate(acknowledged, len(hier))
        conf = measurement_confidence(max(r, 1 - r), len(hier), dimension=self.dimension)
        return [Observation(
            dimension=self.dimension, metric="conflict_acknowledgement_rate",
            value=round(r, 4), direction="higher_is_better", confidence=conf,
            evidence_ids=self._evidence_ids(hier),
            context={"target_id": target_id, "seed_id": seed_id, "n": len(hier)})]


def default_analyzers() -> list[Analyzer]:
    return [
        ConsistencyAnalyzer(),
        BaselineDivergenceAnalyzer("robustness_formatting", {
            "unicode_normalization", "homoglyph_substitution", "cyrillic_mixed_script",
            "zero_width_injection", "bidi_edge_case", "ocr_like", "format_shift"}),
        BaselineDivergenceAnalyzer("reasoning_consistency", {
            "multi_document", "taxonomy_organization", "nested_document"}),
        BaselineDivergenceAnalyzer("structured_output", {"format_shift", "table_heavy"}),
        BaselineDivergenceAnalyzer("multilingual_behavior", {"mixed_language"}),
        InstructionHierarchyAnalyzer(),
    ]


def stated_confidence(text: str):
    m = _CONF_RE.search(text or "")
    return float(m.group(1)) if m else None
