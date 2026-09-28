"""Active reconnaissance agent.

Runs the safe, authorized :class:`~aegis.active.http_probe.SafeHTTPProbe` against
web targets that (a) declare a real ``endpoint`` and (b) explicitly opt in via
``metadata.active_probe: true``. It is **off by default**: a normal assessment of
a declared-inventory or mock target never sends live traffic. When it does run,
every request is authorized against the engagement scope first (fail-closed), so
an out-of-scope endpoint is refused and recorded, never probed.

Findings are appended to the candidate pipeline so they flow through controlled
validation, risk analysis, and reporting like any other finding.
"""

from __future__ import annotations

from ..core.types import TargetKind
from .base import BaseAgent

_WEB_KINDS = {TargetKind.WEB_APP, TargetKind.REST_API, TargetKind.GRAPHQL_API,
              TargetKind.AI_GATEWAY}


def _probe_targets(state):
    for t in state.targets:
        if t.kind not in _WEB_KINDS:
            continue
        endpoint = t.metadata.get("endpoint")
        if endpoint and t.metadata.get("active_probe"):
            yield t, endpoint


class ActiveReconAgent(BaseAgent):
    name = "active_recon"
    responsibilities = ("Safe, authorized live HTTP reconnaissance (headers, TLS, "
                        "cookies, CORS, exposed paths) for opted-in web targets; "
                        "non-destructive, scope-gated, no exploitation.")
    inputs = ["targets"]
    outputs = ["candidates", "recon"]

    def should_run(self, state):
        return any(True for _ in _probe_targets(state))

    def _run(self, state):
        from ..active import SafeHTTPProbe

        log = state.logger.bind(agent=self.name)
        for t, endpoint in _probe_targets(state):
            probe = SafeHTTPProbe(
                state.config.scope, target_id=t.id,
                max_requests=int(t.metadata.get("max_probe_requests", 20)),
                delay=float(t.metadata.get("probe_delay", 0.0)))
            outcome = probe.probe(endpoint)
            state.candidates.extend(outcome.findings)
            state.recon.setdefault(t.id, {})
            state.recon[t.id]["active"] = {
                "endpoint": endpoint,
                "requests_made": outcome.requests_made,
                "findings": len(outcome.findings),
                "denied": outcome.denied,
                "errors": outcome.errors,
                "checks": [c.__dict__ for c in outcome.checks],
            }
            log.info("active_recon.done", "active recon complete",
                     target=t.id, requests=outcome.requests_made,
                     findings=len(outcome.findings), denied=len(outcome.denied))
        return state
