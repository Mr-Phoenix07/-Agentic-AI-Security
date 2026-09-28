"""Approval-gated, evidence-first vulnerability validation.

A scan produces *observations* (a matched template, an open port, a discovered
endpoint). An observation is a lead, not a confirmed vulnerability. This module
turns a lead into an adjudicated result **only when a controlled re-run produces
evidence** — honoring the platform's trust hierarchy:

    raw tool output → parsed observation → validation attempt → validated finding

Two validation strategies, and the boundary between them is the whole point:

* **Non-destructive re-observation** (default). Re-run the *same class* of safe
  detection (nuclei by template id, nmap on the specific port, httpx on the URL)
  and confirm the signal reproduces. This runs through the controlled executor,
  so it is still scope- and approval-gated, but it changes no state.

* **Intrusive validation** (sqlmap / hydra / metasploit class). These are
  *documentation-only contracts* — AEGIS ships no auto-runnable adapter. A
  request that needs one is never executed autonomously: it resolves to
  ``MANUAL_REQUIRED`` with proposed steps for a human, or ``REFUSED`` if the
  engagement hasn't enabled that class. The validator never fabricates a result
  and never confirms without evidence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from ..core.types import (
    Confidence,
    Evidence,
    Finding,
    FindingCategory,
    Severity,
)
from .runner import RunOutput, ToolRunnerLike
from .spec import ParsedObservation

_SEVERITY = {"info": Severity.INFO, "low": Severity.LOW, "medium": Severity.MEDIUM,
             "high": Severity.HIGH, "critical": Severity.CRITICAL}

# Observation kinds that would require an intrusive / gated tool to validate,
# mapped to the documentation-only contract that would (with a human adapter)
# perform it. These never auto-run.
_MANUAL_CONTRACTS = {
    "injection_candidate": "sqlmap",
    "sqli": "sqlmap",
    "sql_injection": "sqlmap",
    "credential_weakness": "hydra",
    "weak_auth": "hydra",
}


class ValidationStatus(str, Enum):
    CONFIRMED = "confirmed"            # reproduced with evidence
    NOT_REPRODUCED = "not_reproduced"  # ran, signal did not recur
    INCONCLUSIVE = "inconclusive"      # could not run meaningfully (e.g. dry-run)
    REFUSED = "refused"                # scope/approval/policy blocked the attempt
    MANUAL_REQUIRED = "manual_required"  # needs a human-driven gated adapter


@dataclass
class ValidationRequest:
    observation: ParsedObservation
    target: str = ""                  # defaults to the observation's own locus
    note: str = ""

    def locus(self) -> str:
        if self.target:
            return self.target
        d = self.observation.detail or {}
        for k in ("matched-at", "url", "host"):
            v = d.get(k)
            if isinstance(v, str) and v:
                return v
        return self.observation.value


@dataclass
class ValidationResult:
    status: ValidationStatus
    method: str
    rationale: str
    evidence: list[Evidence] = field(default_factory=list)
    records: list[dict] = field(default_factory=list)     # ToolRunRecord dicts
    requires_human: bool = False
    proposed_manual_steps: str = ""

    def to_dict(self) -> dict:
        return {
            "status": self.status.value,
            "method": self.method,
            "rationale": self.rationale,
            "evidence": [e.to_dict() for e in self.evidence],
            "records": self.records,
            "requires_human": self.requires_human,
            "proposed_manual_steps": self.proposed_manual_steps,
        }


def _snippet(text: str, limit: int = 2000) -> str:
    text = text or ""
    return text if len(text) <= limit else text[:limit] + "…[truncated]"


class Validator:
    """Adjudicates observations into validation results via controlled re-runs."""

    def __init__(self, runner: ToolRunnerLike) -> None:
        self.runner = runner

    # -- public entry point ------------------------------------------------- #
    def validate(self, request: ValidationRequest) -> ValidationResult:
        kind = request.observation.kind
        locus = request.locus()

        # 1) intrusive/gated class → never auto-run; hand back to a human.
        if kind in _MANUAL_CONTRACTS:
            return self._manual(request, _MANUAL_CONTRACTS[kind])

        # 2) non-destructive re-observation.
        plan = self._reobserve_plan(request)
        if plan is None:
            return ValidationResult(
                status=ValidationStatus.INCONCLUSIVE,
                method="none",
                rationale=f"no non-destructive validation defined for '{kind}'")

        tool, params, confirm = plan
        out = self.runner.run_tool(tool, locus, params=params,
                                   reason=f"validate {kind} at {locus}")
        records = [r.to_dict() for r in out.records]
        res0 = out.results[0] if out.results else None

        # No result at all → the validation tool isn't available.
        if res0 is None:
            return ValidationResult(
                status=ValidationStatus.INCONCLUSIVE, method=f"re-observe:{tool}",
                rationale=f"validation tool '{tool}' unavailable", records=records)

        # Refused by the control layer (scope / approval / offline / policy).
        # A refused ToolResult is not ok and carries a reason; it never executed.
        if not res0.ok and res0.refused_reason is not None:
            return ValidationResult(
                status=ValidationStatus.REFUSED, method=f"re-observe:{tool}",
                rationale=f"validation run refused: {res0.refused_reason}",
                records=records)

        # Ran in dry-run (validated, not executed) with no output → can't adjudicate.
        if res0.dry_run and not out.observations:
            return ValidationResult(
                status=ValidationStatus.INCONCLUSIVE, method=f"re-observe:{tool}",
                rationale="validation ran in dry-run; execute against the "
                          "authorized target to adjudicate", records=records)

        if confirm(out):
            ev = self._evidence(request, tool, locus, out)
            return ValidationResult(
                status=ValidationStatus.CONFIRMED, method=f"re-observe:{tool}",
                rationale=f"signal reproduced by {tool} at {locus}",
                evidence=[ev], records=records)

        return ValidationResult(
            status=ValidationStatus.NOT_REPRODUCED, method=f"re-observe:{tool}",
            rationale=f"{tool} did not reproduce the signal at {locus}",
            records=records)

    # -- promote a confirmed result to a finding (severity stays provisional) #
    def to_finding(self, request: ValidationRequest,
                   result: ValidationResult) -> Finding | None:
        """Build a Finding from a CONFIRMED validation.

        Severity is taken *provisionally* from the tool's advisory hint; final
        severity is the risk engine's call plus human review, per the platform's
        rule that a model alone never sets final severity.
        """
        if result.status != ValidationStatus.CONFIRMED:
            return None
        obs = request.observation
        sev = _SEVERITY.get((obs.severity_hint or "info").lower(), Severity.INFO)
        return Finding(
            title=f"Validated: {obs.kind} ({obs.value})",
            category=FindingCategory.OTHER,
            severity=sev,
            confidence=Confidence(
                value=0.8, sample_size=1,
                rationale="reproduced by controlled re-observation; severity "
                          "provisional pending risk-engine/human review"),
            summary=result.rationale,
            evidence_ids=[e.id for e in result.evidence],
        )

    # -- internals ---------------------------------------------------------- #
    def _reobserve_plan(self, request: ValidationRequest):
        """Return (tool, params, confirm_predicate) or None."""
        obs = request.observation
        kind = obs.kind

        if kind == "template_match":
            tid = (obs.detail or {}).get("template-id") or obs.value

            def confirm(out: RunOutput) -> bool:
                return any(
                    o.kind == "template_match"
                    and (str((o.detail or {}).get("template-id") or o.value) == str(tid))
                    for o in out.observations) or any(
                    o.kind == "template_match" for o in out.observations)

            return ("nuclei", {"template_id": tid} if tid else {}, confirm)

        if kind == "open_port":
            port = str((obs.detail or {}).get("portid") or "")

            def confirm(out: RunOutput) -> bool:
                return any(o.kind == "open_port"
                           and str((o.detail or {}).get("portid")) == port
                           for o in out.observations)

            return ("nmap", {"ports": port} if port else {}, confirm)

        if kind in ("http_service", "path"):
            def confirm(out: RunOutput) -> bool:
                return any(o.kind == "http_service" for o in out.observations)

            return ("httpx", {}, confirm)

        return None

    def _manual(self, request: ValidationRequest, contract_tool: str) -> ValidationResult:
        return ValidationResult(
            status=ValidationStatus.MANUAL_REQUIRED,
            method=f"gated:{contract_tool}",
            rationale=(
                f"validating '{request.observation.kind}' requires the gated "
                f"'{contract_tool}' class, which ships as a documentation-only "
                f"contract and is never auto-run"),
            requires_human=True,
            proposed_manual_steps=(
                f"Under explicit written authorization, a human operator may "
                f"implement a scoped '{contract_tool}' adapter and validate "
                f"'{request.locus()}' with minimal, non-destructive confirmation, "
                f"capturing evidence. AEGIS will not perform this autonomously."),
        )

    def _evidence(self, request: ValidationRequest, tool: str, locus: str,
                  out: RunOutput) -> Evidence:
        res = out.results[0] if out.results else None
        matches = [o.to_dict() for o in out.observations][:20]
        return Evidence(
            kind="tool_validation",
            summary=f"{tool} reproduced '{request.observation.kind}' at {locus}",
            payload={
                "tool": tool,
                "argv": res.argv if res else [],
                "exit_code": res.exit_code if res else None,
                "matches": matches,
                "stdout_snippet": _snippet(res.stdout if res else ""),
            },
            reproduction={"tool": tool, "target": locus,
                          "observation_kind": request.observation.kind},
        )
