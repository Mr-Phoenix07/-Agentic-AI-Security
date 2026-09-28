"""Tool runner — the thin layer that turns *selection* into *scoped, parsed runs*.

Both the recursive scanner (:mod:`aegis.tools.pipeline`) and the approval-gated
validator (:mod:`aegis.tools.validation`) need the same primitive: "given a
target (or a specific tool), run what's applicable through the controlled
executor and hand back structured observations plus the audit records." That
primitive lives here so the two higher-level engines share one code path — and
so tests can substitute a deterministic fake that never touches a real binary.

Nothing here relaxes a guarantee: every run still goes through
:class:`~aegis.tools.execution.ToolExecutor` (scope, offline, approval, dry-run,
audit). The runner only *chooses* and *parses*; the executor decides.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from ..core.authorization import AuthorizationScope
from .execution import ToolExecutor, ToolResult, ToolRunRecord
from .registry import TargetProfile, ToolRegistry
from .spec import ParsedObservation, RiskLevel


@dataclass
class RunOutput:
    """Everything produced by running one target (or one tool) once."""

    observations: list[ParsedObservation] = field(default_factory=list)
    results: list[ToolResult] = field(default_factory=list)
    records: list[ToolRunRecord] = field(default_factory=list)

    def extend(self, other: RunOutput) -> None:
        self.observations.extend(other.observations)
        self.results.extend(other.results)
        self.records.extend(other.records)


@runtime_checkable
class ToolRunnerLike(Protocol):
    """The surface the pipeline and validator depend on (duck-typed for tests)."""

    scope: AuthorizationScope

    def run_selected(self, profile: TargetProfile) -> RunOutput: ...

    def run_tool(self, tool_name: str, target: str,
                 params: dict | None = None, reason: str = "") -> RunOutput: ...


class ToolRunner:
    """Default runner backed by a :class:`ToolRegistry` + :class:`ToolExecutor`.

    Parameters
    ----------
    registry / executor: the catalog and the controlled execution choke point.
    tool_params:         per-tool default params (e.g. an operator wordlist for
                         ffuf/gobuster), applied to every invocation of that tool.
    credential_testing / exploitation / max_risk:
                         forwarded to selection so the runner never even *tries*
                         a tool the engagement hasn't authorized.
    engagement:          audit attribution.
    """

    def __init__(
        self,
        registry: ToolRegistry,
        executor: ToolExecutor,
        *,
        tool_params: dict[str, dict] | None = None,
        credential_testing: bool = False,
        exploitation: bool = False,
        max_risk: RiskLevel = RiskLevel.ACTIVE,
        engagement: str = "",
    ) -> None:
        self.registry = registry
        self.executor = executor
        self.tool_params = tool_params or {}
        self.credential_testing = credential_testing
        self.exploitation = exploitation
        self.max_risk = max_risk
        self.engagement = engagement

    @property
    def scope(self) -> AuthorizationScope:
        return self.executor.scope

    # -- run everything applicable to a target ------------------------------ #
    def run_selected(self, profile: TargetProfile) -> RunOutput:
        from .spec import ToolInvocation

        out = RunOutput()
        plan = self.registry.select(
            profile, credential_testing=self.credential_testing,
            exploitation=self.exploitation, max_risk=self.max_risk)
        for spec in plan.runnable_specs():
            inv = ToolInvocation(
                tool=spec.name, target=profile.target,
                params=dict(self.tool_params.get(spec.name, {})),
                engagement=self.engagement, requested_by="scanner",
                reason=f"selected for {profile.kind.value} target")
            res = self.executor.run(inv, spec)
            out.results.append(res)
            if self.executor.audit_log:
                out.records.append(self.executor.audit_log[-1])
            out.observations.extend(self.executor.parse(spec, res))
        return out

    # -- run one specific tool (used by validation) ------------------------- #
    def run_tool(self, tool_name: str, target: str,
                 params: dict | None = None, reason: str = "") -> RunOutput:
        from .spec import ToolInvocation

        out = RunOutput()
        spec = self.registry.get(tool_name)
        if spec is None:
            return out
        inv = ToolInvocation(tool=tool_name, target=target,
                             params=dict(params or {}), engagement=self.engagement,
                             requested_by="validator", reason=reason)
        res = self.executor.run(inv, spec)
        out.results.append(res)
        if self.executor.audit_log:
            out.records.append(self.executor.audit_log[-1])
        out.observations.extend(self.executor.parse(spec, res))
        return out
