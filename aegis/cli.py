"""AEGIS command-line interface.

Subcommands:
    run          run an assessment from a config file
    demo         run a self-contained offline demo (mock target, no keys/network)
    mutate       show reproducible prompt variants for a piece of text
    scope-check  test whether a URL/model is inside a config's authorization scope
    agents       list the agent collective and the workflow order
    version      print version

Pure stdlib (argparse); no third-party dependency required to run.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__


def _print(msg: str = "") -> None:
    print(msg, file=sys.stdout, flush=True)


def _host_of(url: str) -> str:
    from urllib.parse import urlsplit
    return urlsplit(url).hostname or url


def _progress_printer():
    def cb(kind, data):
        if kind == "phase":
            _print(f"  ▸ phase: {data['phase']}")
        elif kind == "agent":
            _print(f"      · {data['agent']}")
    return cb


def cmd_run(args) -> int:
    from .core.config import Config
    from .graph import run_assessment

    cfg = Config.load(args.config)
    if args.workdir:
        cfg.workdir = Path(args.workdir)
    if cfg.scope.is_empty:
        _print("ERROR: authorization scope is empty (fail-closed). Add rules for "
               "systems you own or are authorized to assess.")
        return 2
    _print(f"AEGIS {__version__} — engagement '{cfg.engagement}' "
           f"({len(cfg.targets)} target(s))")
    state = run_assessment(cfg, progress=_progress_printer() if not args.quiet else None)
    _print("")
    _print(f"Findings: {len(state.findings)} | coverage: "
           f"{state.coverage.get('mean', 0):.0%} | errors: {len(state.errors)}")
    counts: dict[str, int] = {}
    for f in state.findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
    if counts:
        _print("Severity: " + ", ".join(f"{v} {k}" for k, v in counts.items()))
    _print(f"Report:   {state.report_paths.get('markdown')}")
    _print(f"Dashboard:{state.report_paths.get('html')}")
    if args.fail_on:
        from .core.types import Severity
        thresh = Severity(args.fail_on).rank
        worst = max((f.severity.rank for f in state.findings), default=-1)
        if worst >= thresh:
            _print(f"Gate: findings at/above '{args.fail_on}' present -> exit 1")
            return 1
    return 0


def cmd_demo(args) -> int:
    from .core.config import default_config
    from .graph import run_assessment

    cfg = default_config("aegis-offline-demo")
    if args.workdir:
        cfg.workdir = Path(args.workdir)
    cfg.loop.max_rounds = args.rounds
    _print(f"AEGIS {__version__} offline demo (mock target, no network/keys)")
    state = run_assessment(cfg, progress=_progress_printer())
    _print("")
    _print(f"Findings: {len(state.findings)}  coverage: {state.coverage.get('mean',0):.0%}")
    for f in sorted(state.findings, key=lambda x: -x.severity.rank):
        _print(f"  [{f.severity.value:8s}] {f.title} ({f.confidence.band})")
    _print(f"\nReport written to: {state.report_paths.get('dir')}")
    return 0


def cmd_mutate(args) -> int:
    from .core.types import FindingCategory
    from .mutation import MutationEngine, Seed

    text = args.text or sys.stdin.read()
    eng = MutationEngine(seed=args.seed)
    seed = Seed(text=text, category=FindingCategory.ROBUSTNESS)
    probes = eng.generate([seed], per_seed=args.count)
    for p in probes:
        _print(f"--- {'+'.join(p.provenance)} [{p.content_hash}]")
        _print(p.payload["prompt"])
        _print("")
    _print(f"({len(probes)} reproducible variants; seed={args.seed})")
    return 0


def cmd_scope_check(args) -> int:
    from .core.config import Config

    cfg = Config.load(args.config)
    if args.url:
        d = cfg.scope.check_url(args.url)
        _print(f"URL   {args.url}: {'ALLOWED' if d.allowed else 'DENIED'} — {d.reason}")
    if args.model:
        d = cfg.scope.check_model(args.model)
        _print(f"MODEL {args.model}: {'ALLOWED' if d.allowed else 'DENIED'} — {d.reason}")
    if not args.url and not args.model:
        _print(json.dumps(cfg.scope.summary(), indent=2))
    return 0


def cmd_methodology(args) -> int:
    from . import methodology as M

    if args.export:
        _print(json.dumps(M.to_dict(), indent=2))
        return 0

    if not args.name or args.name == "list":
        _print("AEGIS assessment methodologies:\n")
        for m in M.list_methodologies():
            _print(f"  {m.id:18s} {m.title}")
            _print(f"  {'':18s} {m.phase_count if hasattr(m,'phase_count') else len(m.phases)} phases · "
                   f"{m.technique_count()} techniques · domain={m.domain}")
            _print("")
        _print("Show one with:  aegis methodology <id>   (e.g. webapp | active-directory | ai-redteam)")
        _print("Export JSON:    aegis methodology --export")
        return 0

    meth = M.get_methodology(args.name)
    if meth is None:
        _print(f"Unknown methodology '{args.name}'. Known: "
               + ", ".join(m.id for m in M.list_methodologies()))
        return 2

    if args.json:
        _print(json.dumps(meth.to_dict(), indent=2))
        return 0

    _print(f"# {meth.title}  [{meth.id}]")
    _print(f"{meth.summary}\n")
    _print(f"⚖️  {meth.authorization_note}\n")
    _print(f"{len(meth.phases)} phases · {meth.technique_count()} techniques\n")
    for i, ph in enumerate(meth.phases, 1):
        _print(f"{i}. {ph.name}  ({ph.id})")
        _print(f"   goal: {ph.goal}")
        for t in ph.techniques:
            fw = "; ".join(f"{k}:{','.join(v)}" for k, v in t.frameworks.items())
            _print(f"     - [{t.id}] {t.name}  (sev-hint={t.severity_hint.value})")
            _print(f"         objective: {t.objective}")
            if fw:
                _print(f"         frameworks: {fw}")
        _print("")
    _print("References: " + ", ".join(f"{k} ({v})" for k, v in meth.references.items()))
    return 0


def cmd_probe(args) -> int:
    from .active import SafeHTTPProbe
    from .core.config import Config

    # Resolve the authorization scope. A scope is REQUIRED and fail-closed: an
    # out-of-scope URL is refused and never contacted.
    if args.config:
        scope = Config.load(args.config).scope
    elif args.i_am_authorized:
        from .core.authorization import AuthorizationScope, ScopeRule
        host = _host_of(args.url)
        scope = AuthorizationScope([ScopeRule(
            label="cli-authorized", hosts=[host],
            url_globs=[f"http://{host}*", f"https://{host}*"],
            authorization_ref=args.i_am_authorized)])
    else:
        _print("ERROR: authorization required. Pass --config <engagement.yaml> "
               "(recommended) or --i-am-authorized '<SoW/ticket ref>' to attest "
               "you are authorized to actively probe this host.")
        return 2

    if scope.is_empty:
        _print("ERROR: authorization scope is empty (fail-closed).")
        return 2

    probe = SafeHTTPProbe(scope, target_id=args.url, max_requests=args.max_requests)
    _print(f"AEGIS active recon (non-destructive, GET/HEAD only) -> {args.url}")
    outcome = probe.probe(args.url)

    if args.json:
        _print(json.dumps({
            "target": outcome.target,
            "requests_made": outcome.requests_made,
            "denied": outcome.denied,
            "errors": outcome.errors,
            "checks": [c.__dict__ for c in outcome.checks],
            "findings": [f.to_dict() for f in outcome.findings],
        }, indent=2, default=str))
        return 0

    if outcome.denied:
        for d in outcome.denied:
            _print(f"  DENIED (out of scope): {d}")
    _print(f"  requests: {outcome.requests_made}  checks: {len(outcome.checks)}  "
           f"findings: {len(outcome.findings)}")
    for c in outcome.checks:
        mark = {"pass": "·", "finding": "!", "info": "i", "error": "x"}.get(c.status, "?")
        _print(f"    [{mark}] {c.check:22s} {c.detail}")
    if outcome.findings:
        _print("")
        for f in sorted(outcome.findings, key=lambda x: -x.severity.rank):
            _print(f"  [{f.severity.value:8s}] {f.title}")
    if outcome.errors:
        _print("")
        for e in outcome.errors:
            _print(f"  note: {e}")
    return 1 if any(f.severity.rank >= 3 for f in outcome.findings) else 0


def cmd_benchmark(args) -> int:
    from .benchmark import run_suite

    _print(f"AEGIS {__version__} accuracy benchmark (offline, mock provider)")
    workdir = Path(args.workdir) if args.workdir else None
    report = run_suite(seed=args.seed, workdir=workdir)
    d = report.to_dict()
    if args.json:
        _print(json.dumps(d, indent=2))
        return 0

    t = d["totals"]
    _print("")
    _print(f"Implemented-detection accuracy over {t['graded_cases']} cases:")
    _print(f"  precision={t['precision']:.3f}  recall={t['recall']:.3f}  "
           f"f1={t['f1']:.3f}   (tp={t['tp']} fp={t['fp']} fn={t['fn']})")
    _print("")
    _print(f"  {'case':30s} {'kind':17s}  P     R     F1    tp fp fn")
    for c in d["cases"]:
        _print(f"  {c['case_id']:30s} {c['kind']:17s} "
               f"{c['precision']:.2f}  {c['recall']:.2f}  {c['f1']:.2f}  "
               f"{c['tp']:2d} {c['fp']:2d} {c['fn']:2d}")
        for m in c["missed"]:
            _print(f"      MISSED   {m}")
        for s in c["spurious"]:
            _print(f"      SPURIOUS {s}")
    if d["coverage_gaps"]:
        _print("")
        _print("Documented coverage gaps (reported separately, not in headline):")
        for c in d["coverage_gaps"]:
            _print(f"  {c['case_id']:30s} recall={c['recall']:.2f}  "
                   f"(needs live testing; see docs/METHODOLOGY_WEBAPP.md)")
    return 0


def cmd_agents(args) -> int:
    from .agents import WORKFLOW_ORDER
    from .graph.workflow import AGENT_PHASE

    _print(f"AEGIS agent collective ({len(WORKFLOW_ORDER)} agents):\n")
    for i, cls in enumerate(WORKFLOW_ORDER, 1):
        phase = AGENT_PHASE.get(cls.name, "?")
        phase = phase.value if hasattr(phase, "value") else phase
        _print(f"{i:2d}. [{phase:9s}] {cls.name}")
        _print(f"       {cls.responsibilities}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="aegis",
        description="AEGIS — Autonomous Agentic AI Security Assessment & "
                    "Adversarial Evaluation Platform")
    p.add_argument("--version", action="version", version=f"aegis {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    r = sub.add_parser("run", help="run an assessment from a config file")
    r.add_argument("config", help="path to engagement config (.yaml/.json)")
    r.add_argument("--workdir", help="override output directory")
    r.add_argument("--quiet", action="store_true")
    r.add_argument("--fail-on", choices=["low", "medium", "high", "critical"],
                   help="exit 1 if any finding at/above this severity (CI gate)")
    r.set_defaults(func=cmd_run)

    d = sub.add_parser("demo", help="offline demo against the mock target")
    d.add_argument("--workdir")
    d.add_argument("--rounds", type=int, default=4)
    d.set_defaults(func=cmd_demo)

    m = sub.add_parser("mutate", help="print reproducible prompt variants")
    m.add_argument("text", nargs="?", help="text to mutate (or read stdin)")
    m.add_argument("--count", type=int, default=10)
    m.add_argument("--seed", type=int, default=1337)
    m.set_defaults(func=cmd_mutate)

    s = sub.add_parser("scope-check", help="test a URL/model against a config's scope")
    s.add_argument("config")
    s.add_argument("--url")
    s.add_argument("--model")
    s.set_defaults(func=cmd_scope_check)

    a = sub.add_parser("agents", help="list the agent collective and workflow order")
    a.set_defaults(func=cmd_agents)

    pr = sub.add_parser("probe",
                        help="safe active HTTP recon of an AUTHORIZED web target "
                             "(non-destructive; GET/HEAD only)")
    pr.add_argument("url", help="base URL of the authorized target")
    pr.add_argument("--config", help="engagement config providing the authz scope")
    pr.add_argument("--i-am-authorized", metavar="REF",
                    help="attest authorization (SoW/ticket ref) to scope this host "
                         "when no --config is given")
    pr.add_argument("--max-requests", type=int, default=20)
    pr.add_argument("--json", action="store_true")
    pr.set_defaults(func=cmd_probe)

    b = sub.add_parser("benchmark",
                       help="measure detection accuracy (precision/recall/F1) on "
                            "offline ground-truth fixtures")
    b.add_argument("--seed", type=int, default=1337)
    b.add_argument("--workdir", help="output directory for per-case runs")
    b.add_argument("--json", action="store_true", help="emit the full report as JSON")
    b.set_defaults(func=cmd_benchmark)

    me = sub.add_parser("methodology",
                        help="show the web-app / Active Directory / AI red-team methodologies")
    me.add_argument("name", nargs="?",
                    help="methodology id/alias: webapp | active-directory | ai-redteam "
                         "(omit or 'list' to list all)")
    me.add_argument("--json", action="store_true", help="emit the selected methodology as JSON")
    me.add_argument("--export", action="store_true", help="emit the entire knowledge base as JSON")
    me.set_defaults(func=cmd_methodology)

    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        _print("\ninterrupted")
        return 130


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
