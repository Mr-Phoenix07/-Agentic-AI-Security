"""Tests for the recursive scanning pipeline and the approval-gated validator.

A deterministic ``FakeRunner`` stands in for the executor-backed runner so these
exercise the *orchestration and safety logic* — recursion, the scope gate on
derived targets, budgets, and every validation outcome — without touching a real
binary. Two tests also drive the real executor (dry-run) to prove the
REFUSED / INCONCLUSIVE paths behave with the genuine control layer.
"""

from __future__ import annotations

from aegis.core.authorization import AuthorizationScope, ScopeRule
from aegis.core.types import TargetKind
from aegis.tools import (
    PipelineBudget,
    RecursiveScanner,
    TargetProfile,
    ToolExecutor,
    ToolRegistry,
    ToolRunner,
    ValidationRequest,
    ValidationStatus,
    Validator,
)
from aegis.tools.execution import ToolResult, ToolRunRecord
from aegis.tools.runner import RunOutput
from aegis.tools.spec import ParsedObservation


def _scope():
    return AuthorizationScope([
        ScopeRule(label="e", hosts=["*.authorized.example", "authorized.example"],
                  url_globs=["http://authorized.example/*",
                             "https://authorized.example/*",
                             "http://*.authorized.example/*",
                             "https://*.authorized.example/*"],
                  authorization_ref="SoW")
    ])


def _norm(t: str) -> str:
    from aegis.tools.pipeline import _normalize
    return _normalize(t)


class FakeRunner:
    """Implements the ToolRunnerLike surface with canned outputs."""

    def __init__(self, scope, selected_map=None, tool_output=None):
        self.scope = scope
        self.selected_map = selected_map or {}
        self.tool_output = tool_output or RunOutput()
        self.calls: list[str] = []

    def run_selected(self, profile: TargetProfile) -> RunOutput:
        self.calls.append(profile.target)
        return self.selected_map.get(_norm(profile.target), RunOutput())

    def run_tool(self, tool_name, target, params=None, reason="") -> RunOutput:
        self.calls.append(f"{tool_name}:{target}")
        return self.tool_output


def _obs(kind, value, **detail):
    return ParsedObservation(kind=kind, value=value, detail=detail)


def _out(obs=None, results=None, records=None):
    return RunOutput(observations=obs or [], results=results or [],
                     records=records or [])


# --------------------------------------------------------------------------- #
# Recursive scanning
# --------------------------------------------------------------------------- #
def test_recursion_chains_discovered_targets():
    scope = _scope()
    seed = "https://authorized.example"
    selected = {
        _norm(seed): _out(
            obs=[_obs("subdomain", "api.authorized.example", host="api.authorized.example"),
                 _obs("http_service", "https://authorized.example/app",
                      url="https://authorized.example/app", tech=["nginx"])],
            results=[ToolResult(True, "httpx", seed, ["httpx"])]),
        _norm("https://api.authorized.example"): _out(
            obs=[_obs("path", "/admin", url="https://api.authorized.example/admin")],
            results=[ToolResult(True, "httpx", "x", ["httpx"])]),
    }
    runner = FakeRunner(scope, selected_map=selected)
    scanner = RecursiveScanner(runner, budget=PipelineBudget(max_depth=3))
    res = scanner.run([TargetProfile(seed, TargetKind.WEB_APP).add("web", "domain")])

    scanned = {s["target"] for s in res.scanned}
    # seed + the derived subdomain + the derived live service + the deep endpoint
    assert "https://authorized.example" in scanned
    assert "https://api.authorized.example" in scanned
    assert "https://authorized.example/app" in scanned
    assert "https://api.authorized.example/admin" in scanned
    assert res.stop_reason == "frontier exhausted"
    # provenance edges recorded
    assert any(e["child"] == "https://api.authorized.example" for e in res.edges)


def test_derived_out_of_scope_target_is_dropped_not_scanned():
    scope = _scope()
    seed = "https://authorized.example"
    selected = {
        _norm(seed): _out(
            obs=[_obs("http_service", "https://evil.example",
                      url="https://evil.example")],
            results=[ToolResult(True, "httpx", seed, ["httpx"])]),
    }
    runner = FakeRunner(scope, selected_map=selected)
    res = RecursiveScanner(runner, budget=PipelineBudget(max_depth=3)).run(
        [TargetProfile(seed, TargetKind.WEB_APP).add("web")])

    scanned = {s["target"] for s in res.scanned}
    assert "https://evil.example" not in scanned          # never scanned
    assert "evil.example" not in "".join(runner.calls)     # never even attempted
    assert any(d["target"] == "https://evil.example"
               for d in res.dropped_out_of_scope)          # audited as dropped


def test_max_depth_budget_stops_expansion():
    scope = _scope()
    seed = "https://authorized.example"
    selected = {
        _norm(seed): _out(
            obs=[_obs("path", "/a", url="https://authorized.example/a")],
            results=[ToolResult(True, "x", seed, ["x"])]),
        _norm("https://authorized.example/a"): _out(
            obs=[_obs("path", "/b", url="https://authorized.example/a/b")],
            results=[ToolResult(True, "x", "y", ["x"])]),
    }
    runner = FakeRunner(scope, selected_map=selected)
    res = RecursiveScanner(runner, budget=PipelineBudget(max_depth=1)).run(
        [TargetProfile(seed, TargetKind.WEB_APP).add("web")])
    scanned = {s["target"] for s in res.scanned}
    # depth 0 (seed) and depth 1 (/a) scanned; depth 2 (/a/b) must NOT be
    assert "https://authorized.example/a" in scanned
    assert "https://authorized.example/a/b" not in scanned


def test_max_targets_budget_halts():
    scope = _scope()
    seed = "https://authorized.example"
    # every target yields two fresh endpoints → unbounded without a cap
    selected = {}
    runner = FakeRunner(scope, selected_map=selected)

    def run_selected(profile):
        runner.calls.append(profile.target)
        base = profile.target.rstrip("/")
        return _out(obs=[_obs("path", "/x", url=base + "/x"),
                         _obs("path", "/y", url=base + "/y")],
                    results=[ToolResult(True, "x", profile.target, ["x"])])
    runner.run_selected = run_selected  # type: ignore

    res = RecursiveScanner(runner, budget=PipelineBudget(
        max_depth=10, max_targets=5)).run(
        [TargetProfile(seed, TargetKind.WEB_APP).add("web")])
    assert len(res.scanned) <= 5
    assert "max_targets" in res.stop_reason


def test_visited_dedup_prevents_recscan():
    scope = _scope()
    seed = "https://authorized.example"
    selected = {
        _norm(seed): _out(
            obs=[_obs("http_service", seed + "/", url=seed + "/")],  # points back at itself
            results=[ToolResult(True, "x", seed, ["x"])]),
    }
    runner = FakeRunner(scope, selected_map=selected)
    res = RecursiveScanner(runner, budget=PipelineBudget(max_depth=5)).run(
        [TargetProfile(seed, TargetKind.WEB_APP).add("web")])
    # the self-referential target is normalized to the seed and not re-scanned
    assert len(res.scanned) == 1


# --------------------------------------------------------------------------- #
# Approval-gated validation
# --------------------------------------------------------------------------- #
def test_validation_confirmed_with_evidence():
    scope = _scope()
    reproduced = _out(
        obs=[_obs("template_match", "cve-2021-1234")],
        results=[ToolResult(True, "nuclei", "https://authorized.example",
                            ["nuclei"], exit_code=0, stdout='{"template-id":"x"}')],
        records=[ToolRunRecord(tool="nuclei", executed=True, dry_run=False,
                               outcome="executed")])
    # make the confirming observation carry the right template-id
    reproduced.observations[0].detail = {"template-id": "cve-2021-1234"}
    runner = FakeRunner(scope, tool_output=reproduced)
    v = Validator(runner)
    req = ValidationRequest(
        observation=_obs("template_match", "cve-2021-1234",
                         **{"template-id": "cve-2021-1234",
                            "matched-at": "https://authorized.example"}),
        )
    res = v.validate(req)
    assert res.status == ValidationStatus.CONFIRMED
    assert res.evidence and res.evidence[0].kind == "tool_validation"
    # a confirmed result can be promoted to a finding (severity provisional)
    finding = v.to_finding(req, res)
    assert finding is not None and finding.evidence_ids


def test_validation_not_reproduced():
    scope = _scope()
    empty = _out(
        obs=[],  # nuclei ran but matched nothing
        results=[ToolResult(True, "nuclei", "https://authorized.example",
                            ["nuclei"], exit_code=0, stdout="")],
        records=[ToolRunRecord(tool="nuclei", executed=True, dry_run=False,
                               outcome="executed")])
    runner = FakeRunner(scope, tool_output=empty)
    res = Validator(runner).validate(ValidationRequest(
        observation=_obs("template_match", "cve-x",
                         **{"template-id": "cve-x",
                            "matched-at": "https://authorized.example"})))
    assert res.status == ValidationStatus.NOT_REPRODUCED
    assert not res.evidence


def test_validation_manual_required_for_gated_class():
    runner = FakeRunner(_scope(), tool_output=_out())
    res = Validator(runner).validate(ValidationRequest(
        observation=_obs("injection_candidate", "?id=1",
                         url="https://authorized.example/item"),
        target="https://authorized.example/item"))
    assert res.status == ValidationStatus.MANUAL_REQUIRED
    assert res.requires_human and "sqlmap" in res.proposed_manual_steps
    # never auto-runs a gated tool
    assert runner.calls == []


def test_validation_refused_out_of_scope_via_real_executor():
    scope = _scope()
    ex = ToolExecutor(scope, dry_run=True, approval=lambda *a: True)
    runner = ToolRunner(ToolRegistry(), ex)
    res = Validator(runner).validate(ValidationRequest(
        observation=_obs("http_service", "https://evil.example",
                         url="https://evil.example"),
        target="https://evil.example"))
    assert res.status == ValidationStatus.REFUSED


def test_validation_inconclusive_on_dry_run_via_real_executor():
    scope = _scope()
    ex = ToolExecutor(scope, dry_run=True, approval=lambda *a: True)
    runner = ToolRunner(ToolRegistry(), ex)
    res = Validator(runner).validate(ValidationRequest(
        observation=_obs("http_service", "https://authorized.example",
                         url="https://authorized.example"),
        target="https://authorized.example"))
    assert res.status == ValidationStatus.INCONCLUSIVE


def test_to_finding_none_unless_confirmed():
    runner = FakeRunner(_scope(), tool_output=_out())
    v = Validator(runner)
    req = ValidationRequest(observation=_obs("injection_candidate", "x"))
    res = v.validate(req)
    assert v.to_finding(req, res) is None


# --------------------------------------------------------------------------- #
# Scope safety of the pipeline
# --------------------------------------------------------------------------- #
def test_out_of_scope_seed_dropped_without_running():
    scope = _scope()
    runner = FakeRunner(scope, selected_map={})
    res = RecursiveScanner(runner).run(
        [TargetProfile("https://evil.example", TargetKind.WEB_APP).add("web")])
    assert res.scanned == []                 # nothing scanned
    assert runner.calls == []                # runner never invoked
    assert res.dropped_out_of_scope and res.invocations == 0


def test_allows_url_is_non_mutating():
    # frontier scope checks must not consume rate/volume budget
    scope = AuthorizationScope([
        ScopeRule(label="capped", hosts=["authorized.example"],
                  url_globs=["https://authorized.example/*"], max_requests=1)])
    for _ in range(10):
        assert scope.allows_url("https://authorized.example/x") is True
    # the single real request still succeeds — budget was untouched by allows_url
    assert scope.check_url("https://authorized.example/x").allowed
    # and the next real request trips the ceiling
    assert not scope.check_url("https://authorized.example/x").allowed
