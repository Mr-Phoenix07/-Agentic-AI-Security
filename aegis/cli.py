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
