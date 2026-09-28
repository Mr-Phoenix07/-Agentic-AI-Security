"""Recursive, scope-bounded scanning pipeline.

This is the "recursive scanning" capability: a breadth-first orchestration loop
that chains tools so that what one tool *discovers* becomes the input to the
next — subdomains → live HTTP services → discovered endpoints → deeper scans —
without a human hand-feeding each step.

Two properties make recursion safe rather than a runaway:

* **Every derived target is re-validated against the authorization scope before
  it can enter the frontier.** A subdomain or endpoint that a tool surfaces but
  that scope does not cover is dropped and audited — it is never scanned. This
  is the whole reason recursion is dangerous without a scope engine and safe
  with one.
* **Hard budgets.** Depth, total targets, and total tool invocations are all
  capped; a visited-set dedupes normalized targets so a cycle can't loop. When a
  budget is hit the pipeline stops and records *why*.

The pipeline never executes anything itself — it drives a
:class:`~aegis.tools.runner.ToolRunner`, so every tool run still passes through
the controlled executor (scope, offline, approval, dry-run, audit).
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

from ..core.types import TargetKind
from .registry import TargetProfile
from .runner import RunOutput, ToolRunnerLike
from .spec import ParsedObservation

_HTTP_PORTS = {"80": "http", "8080": "http", "8000": "http",
               "443": "https", "8443": "https"}


@dataclass
class PipelineBudget:
    """Ceilings that bound a recursive scan. All are fail-safe (small defaults)."""

    max_depth: int = 2            # how many expansion hops from the seed
    max_targets: int = 50         # total distinct targets ever scanned
    max_invocations: int = 200    # total tool runs attempted
    max_expansion_per_node: int = 25  # cap fan-out from a single node


@dataclass
class ScanNode:
    """A target in the frontier, with provenance back to what produced it."""

    profile: TargetProfile
    depth: int = 0
    parent: str | None = None
    reason: str = "seed"


@dataclass
class PipelineResult:
    scanned: list[dict] = field(default_factory=list)          # {target, kind, depth, reason}
    observations: list[ParsedObservation] = field(default_factory=list)
    edges: list[dict] = field(default_factory=list)            # {parent, child, reason}
    dropped_out_of_scope: list[dict] = field(default_factory=list)  # {target, reason}
    invocations: int = 0
    stop_reason: str = "frontier exhausted"

    def to_dict(self) -> dict:
        return {
            "scanned": self.scanned,
            "observations": [o.to_dict() for o in self.observations],
            "edges": self.edges,
            "dropped_out_of_scope": self.dropped_out_of_scope,
            "counts": {
                "targets": len(self.scanned),
                "observations": len(self.observations),
                "invocations": self.invocations,
                "dropped": len(self.dropped_out_of_scope),
            },
            "stop_reason": self.stop_reason,
        }


def _normalize(target: str) -> str:
    """Stable identity for dedup: lowercased, no trailing slash, no fragment."""
    t = (target or "").strip().lower()
    if "://" in t:
        p = urlparse(t)
        path = p.path.rstrip("/") or "/"
        netloc = p.netloc
        return f"{p.scheme}://{netloc}{path}"
    return t.rstrip("/")


def _host_of(target: str) -> str:
    if "://" in target:
        return (urlparse(target).hostname or "").lower()
    return target.split("/")[0].split(":")[0].lower()


class TargetExpander:
    """Derive new candidate targets from a node's observations.

    Deliberately conservative: only a handful of well-understood observation
    kinds expand, and each expansion is a *plausible next scan target*, never an
    assumption of vulnerability. Returns ``(profile, reason)`` pairs; the
    pipeline is responsible for scope-checking and budgeting them.
    """

    def expand(self, node: ScanNode,
               observations: list[ParsedObservation]) -> list[tuple[TargetProfile, str]]:
        out: list[tuple[TargetProfile, str]] = []
        base = node.profile.target
        host = _host_of(base)
        for obs in observations:
            if obs.kind == "subdomain":
                sub = obs.detail.get("host") or obs.value
                prof = TargetProfile(f"https://{sub}", TargetKind.WEB_APP)
                prof.add("http", "https", "web", "domain", "host")
                out.append((prof, f"subdomain of {host}"))
            elif obs.kind == "open_port":
                port = str(obs.detail.get("portid") or "")
                scheme = _HTTP_PORTS.get(port)
                if not scheme or not host:
                    continue
                url = f"{scheme}://{host}:{port}"
                prof = TargetProfile(url, TargetKind.WEB_APP).add(scheme, "web")
                out.append((prof, f"open {port}/tcp on {host}"))
            elif obs.kind == "http_service":
                url = obs.detail.get("url") or obs.value
                if not url:
                    continue
                techs = obs.detail.get("tech") or obs.detail.get("technologies") or []
                techs = [str(t).lower() for t in techs] if isinstance(techs, list) else []
                prof = TargetProfile(str(url), TargetKind.WEB_APP)
                prof.add("http", "https", "web", *techs)
                out.append((prof, "live HTTP service"))
            elif obs.kind == "path":
                url = obs.detail.get("url")
                if not url:
                    path = obs.detail.get("path") or obs.value
                    url = urljoin(base if base.endswith("/") else base + "/",
                                  str(path).lstrip("/"))
                prof = TargetProfile(str(url), TargetKind.WEB_APP)
                prof.add("http", "https", "web", "endpoint")
                out.append((prof, "discovered endpoint"))
            # template_match is a *finding candidate* for validation, not a
            # recursion target — intentionally not expanded here.
        return out


class RecursiveScanner:
    """Breadth-first, scope-bounded recursive scan driver."""

    def __init__(self, runner: ToolRunnerLike, *,
                 budget: PipelineBudget | None = None,
                 expander: TargetExpander | None = None) -> None:
        self.runner = runner
        self.budget = budget or PipelineBudget()
        self.expander = expander or TargetExpander()

    def run(self, seeds: list[TargetProfile]) -> PipelineResult:
        result = PipelineResult()
        frontier: deque[ScanNode] = deque(ScanNode(profile=s) for s in seeds)
        visited: set[str] = set()

        while frontier:
            node = frontier.popleft()
            key = _normalize(node.profile.target)
            if key in visited:
                continue

            if len(result.scanned) >= self.budget.max_targets:
                result.stop_reason = f"max_targets ({self.budget.max_targets}) reached"
                break
            if result.invocations >= self.budget.max_invocations:
                result.stop_reason = (
                    f"max_invocations ({self.budget.max_invocations}) reached")
                break

            visited.add(key)

            # Scope-gate the node itself before touching it (non-mutating check,
            # so it doesn't consume rate budget). Derived targets are also checked
            # before enqueue; this covers seeds too. The executor is still the
            # authority — it re-checks (and counts) on every real run.
            if not self.runner.scope.allows_url(node.profile.target):
                result.dropped_out_of_scope.append(
                    {"target": node.profile.target,
                     "reason": "not covered by any active scope rule",
                     "parent": node.parent})
                continue

            out: RunOutput = self.runner.run_selected(node.profile)
            result.invocations += len(out.results)
            result.observations.extend(out.observations)
            result.scanned.append({
                "target": node.profile.target, "kind": node.profile.kind.value,
                "depth": node.depth, "reason": node.reason,
                "signals": sorted(node.profile.signals),
                "observations": len(out.observations),
            })

            # Expand only while we have depth budget left.
            if node.depth >= self.budget.max_depth:
                continue
            derived = self.expander.expand(node, out.observations)
            for prof, reason in derived[: self.budget.max_expansion_per_node]:
                child_key = _normalize(prof.target)
                if child_key in visited:
                    continue
                # *** the safety gate: never enqueue an out-of-scope target ***
                # (non-mutating check — no request is sent here)
                if not self.runner.scope.allows_url(prof.target):
                    result.dropped_out_of_scope.append(
                        {"target": prof.target,
                         "reason": "not covered by any active scope rule",
                         "parent": node.profile.target})
                    continue
                result.edges.append({"parent": node.profile.target,
                                     "child": prof.target, "reason": reason})
                frontier.append(ScanNode(profile=prof, depth=node.depth + 1,
                                         parent=node.profile.target, reason=reason))

        return result
