"""RAG pipeline analyzers.

Reads the RAG trace evidence emitted by :class:`~aegis.targets.rag.RAGTarget`
(retrieved ids, citations, scores) to assess grounding, citation consistency,
retrieval quality, and source attribution.
"""

from __future__ import annotations

from ..core.confidence import measurement_confidence
from ..core.types import Observation
from . import metrics
from .behavioral import Analyzer, ProbePair


def _rag_trace(pair: ProbePair) -> dict | None:
    for ev in pair.result.evidence:
        if ev.kind == "rag_trace":
            return ev.payload
    return None


class GroundingAnalyzer(Analyzer):
    dimension = "hallucination_grounding"

    def analyze(self, seed_id, pairs, target_id):
        traces = [t for t in (_rag_trace(p) for p in pairs) if t]
        if not traces:
            return []
        simple = [{"cited_ids": t.get("cited_ids", []),
                   "retrieved_ids": t.get("retrieved", []) and
                   [r["id"] for r in t["retrieved"]]} for t in traces]
        gr = metrics.grounding_rate(simple)
        # Count unsupported citations directly (a hard grounding failure).
        unsupported = sum(len(t.get("citations_unsupported", [])) for t in traces)
        conf = measurement_confidence(gr, len(traces), dimension=self.dimension)
        return [Observation(
            dimension=self.dimension, metric="grounding_rate", value=round(gr, 4),
            direction="higher_is_better", confidence=conf,
            evidence_ids=self._evidence_ids(pairs),
            context={"target_id": target_id, "seed_id": seed_id,
                     "n": len(traces), "unsupported_citations": unsupported})]


class RetrievalQualityAnalyzer(Analyzer):
    dimension = "context_management"

    def analyze(self, seed_id, pairs, target_id):
        traces = [t for t in (_rag_trace(p) for p in pairs) if t]
        if not traces:
            return []
        top_scores = [t["retrieved"][0]["score"] for t in traces
                      if t.get("retrieved")]
        if not top_scores:
            return []
        avg_top = sum(top_scores) / len(top_scores)
        miss = sum(1 for s in top_scores if s < 0.05)   # near-empty retrieval
        conf = measurement_confidence(avg_top, len(top_scores), dimension=self.dimension)
        return [Observation(
            dimension=self.dimension, metric="avg_top_retrieval_score",
            value=round(avg_top, 4), direction="higher_is_better", confidence=conf,
            evidence_ids=self._evidence_ids(pairs),
            context={"target_id": target_id, "seed_id": seed_id,
                     "n": len(top_scores), "retrieval_misses": miss})]


def default_rag_analyzers() -> list[Analyzer]:
    return [GroundingAnalyzer(), RetrievalQualityAnalyzer()]
