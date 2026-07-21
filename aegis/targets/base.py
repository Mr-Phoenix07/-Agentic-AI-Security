"""Target abstraction — the thing under assessment.

A :class:`Target` binds a provider to an evaluation *mode* (black/grey/white box)
and metadata, exposes a uniform :meth:`send` that turns a :class:`Probe` into a
:class:`ProbeResult` (with reproducible evidence attached), and is the object all
agents reason about.

Subtypes specialise behaviour for retrieval pipelines, web/API surfaces, and MCP
servers while sharing the same interface.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from ..core.types import (
    EvaluationMode,
    Evidence,
    Probe,
    ProbeResult,
    ProbeStatus,
    TargetKind,
    stable_hash,
)
from ..providers.base import Provider, ProviderRequest


@dataclass
class Target:
    id: str
    kind: TargetKind
    provider: Provider
    mode: EvaluationMode = EvaluationMode.BLACK_BOX
    metadata: dict = field(default_factory=dict)

    def send(self, probe: Probe) -> ProbeResult:
        req = ProviderRequest(
            prompt=probe.payload.get("prompt"),
            messages=probe.payload.get("messages"),
            params={"_provenance": probe.provenance, **probe.payload.get("params", {})},
            model=self.metadata.get("model"),
            endpoint=self.metadata.get("endpoint"),
        )
        resp = self.provider.complete(req)
        status = ProbeStatus.ERRORED if resp.error else ProbeStatus.COMPLETED
        ev = Evidence(
            kind="transcript",
            summary=f"probe {probe.id} -> {self.id}",
            payload={"request": {"prompt": probe.payload.get("prompt"),
                                 "messages": probe.payload.get("messages")},
                     "response": resp.to_dict()},
            target_id=self.id,
            probe_id=probe.id,
            reproduction={
                "provider": self.provider.name,
                "model": resp.model,
                "prompt_hash": stable_hash(probe.payload),
                "provenance": probe.provenance,
                "params": req.params,
            },
        )
        return ProbeResult(
            probe_id=probe.id,
            target_id=self.id,
            status=status,
            response=resp.to_dict(),
            latency_ms=resp.latency_ms,
            tokens=resp.tokens,
            error=resp.error,
            evidence=[ev],
        )

    # Capability hints used by the capability-mapping agent.
    def declared_capabilities(self) -> dict:
        return self.metadata.get("capabilities", {})

    def attack_surface(self) -> dict:
        """Declared surface inventory (endpoints, tools, integrations)."""
        return self.metadata.get("surface", {})
