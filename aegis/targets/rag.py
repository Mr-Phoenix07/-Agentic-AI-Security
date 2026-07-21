"""RAG target — a retrieval-augmented generation pipeline under assessment.

Wraps a generator provider with a small, transparent retriever so the RAG
analysis agent can measure grounding, citation consistency, retrieval robustness,
and context utilisation. The retriever is deliberately simple (lexical overlap)
and fully observable — the point is to *instrument* the pipeline, not to be a
production retriever. Point it at a real vector store by subclassing
:meth:`retrieve`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..core.types import Evidence, Probe, ProbeResult, TargetKind, stable_hash
from ..providers.base import ProviderRequest
from .base import Target


@dataclass
class Document:
    id: str
    text: str
    source: str = ""


def _tokens(s: str) -> set[str]:
    return set(re.findall(r"[a-z0-9]{3,}", s.lower()))


@dataclass
class RAGTarget(Target):
    corpus: list[Document] = field(default_factory=list)
    top_k: int = 3

    def __post_init__(self) -> None:
        if self.kind != TargetKind.RAG:
            self.kind = TargetKind.RAG

    def retrieve(self, query: str) -> list[tuple[Document, float]]:
        q = _tokens(query)
        scored = []
        for d in self.corpus:
            dt = _tokens(d.text)
            if not dt:
                continue
            overlap = len(q & dt) / (len(q | dt) or 1)   # Jaccard
            scored.append((d, round(overlap, 4)))
        scored.sort(key=lambda x: x[1], reverse=True)
        return scored[: self.top_k]

    def send(self, probe: Probe) -> ProbeResult:
        query = probe.payload.get("prompt", "")
        hits = self.retrieve(query)
        context = "\n\n".join(f"[{d.id}] {d.text}" for d, _ in hits)
        augmented = (
            "Use ONLY the following sources. Cite source ids in brackets.\n\n"
            f"{context}\n\n---\nQuestion: {query}\nGrounded answer:"
        )
        req = ProviderRequest(prompt=augmented,
                              params={"_provenance": probe.provenance})
        resp = self.provider.complete(req)
        cited = set(re.findall(r"\[([A-Za-z0-9_\-]+)\]", resp.text))
        retrieved_ids = {d.id for d, _ in hits}
        ev = Evidence(
            kind="rag_trace",
            summary=f"RAG probe {probe.id}",
            payload={
                "query": query,
                "retrieved": [{"id": d.id, "score": s, "source": d.source}
                              for d, s in hits],
                "augmented_prompt": augmented,
                "response": resp.to_dict(),
                "cited_ids": sorted(cited),
                "citations_grounded": sorted(cited & retrieved_ids),
                "citations_unsupported": sorted(cited - retrieved_ids),
            },
            target_id=self.id,
            probe_id=probe.id,
            reproduction={"prompt_hash": stable_hash(augmented),
                          "retrieved_ids": sorted(retrieved_ids)},
        )
        return ProbeResult(
            probe_id=probe.id, target_id=self.id,
            response={**resp.to_dict(),
                      "rag": {"retrieved_ids": sorted(retrieved_ids),
                              "cited_ids": sorted(cited),
                              "top_score": hits[0][1] if hits else 0.0}},
            latency_ms=resp.latency_ms, tokens=resp.tokens, error=resp.error,
            evidence=[ev],
        )
