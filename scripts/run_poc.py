#!/usr/bin/env python3
"""Proof-of-Concept runner for AEGIS.

Runs the platform end-to-end **against its built-in, offline, deterministic mock
target** — the authorized, safe-by-construction path the framework is designed
for — and captures timestamped evidence:

  * the offline assessment (findings, coverage, generated report paths),
  * the new `aegis methodology` knowledge base (web-app / AD / AI red-team),
  * the rendered HTML dashboard (for screenshotting).

No real, external, or unauthorized systems are touched; the authorization scope
is fail-closed and the mock provider requires no network or keys.
"""

from __future__ import annotations

import json
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
OUT = ROOT / "docs" / "proof-of-concept"
OUT.mkdir(parents=True, exist_ok=True)


def ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def log(fh, msg: str = "") -> None:
    line = f"[{ts()}] {msg}" if msg else ""
    print(line)
    fh.write(line + "\n")
    fh.flush()


def run_cmd(fh, argv: list[str]) -> str:
    log(fh, f"$ {' '.join(argv)}")
    proc = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True)
    out = (proc.stdout or "") + (proc.stderr or "")
    for ln in out.rstrip("\n").splitlines():
        print("    " + ln)
        fh.write("    " + ln + "\n")
    fh.write(f"    (exit={proc.returncode})\n")
    fh.flush()
    return out


def main() -> int:
    console = OUT / "console_output.txt"
    with console.open("w") as fh:
        log(fh, "AEGIS Proof-of-Concept run — offline mock target, no network/keys")
        log(fh, f"Host: {platform.platform()}  Python: {platform.python_version()}")
        log(fh, f"Repo: {ROOT}")
        log(fh)

        # 1) Environment / version
        log(fh, "== [1/6] Version & environment ==")
        run_cmd(fh, [sys.executable, "-m", "aegis.cli", "--version"])
        log(fh)

        # 2) Methodology knowledge base (the new integration)
        log(fh, "== [2/6] Methodology knowledge base (aegis methodology) ==")
        run_cmd(fh, [sys.executable, "-m", "aegis.cli", "methodology"])
        for name in ("webapp", "active-directory", "ai-redteam"):
            run_cmd(fh, [sys.executable, "-m", "aegis.cli", "methodology", name])
        export = run_cmd(fh, [sys.executable, "-m", "aegis.cli", "methodology", "--export"])
        try:
            kb = json.loads(export)
            (OUT / "methodology_export.json").write_text(json.dumps(kb, indent=2))
            log(fh, f"methodology KB exported: {kb['methodology_count']} methodologies, "
                    f"{kb['technique_count']} techniques -> methodology_export.json")
        except Exception as e:  # pragma: no cover
            log(fh, f"could not parse methodology export: {e}")
        log(fh)

        # 3) Agent collective
        log(fh, "== [3/6] Agent collective & workflow order ==")
        run_cmd(fh, [sys.executable, "-m", "aegis.cli", "agents"])
        log(fh)

        # 4) End-to-end offline assessment against the mock target
        log(fh, "== [4/6] Offline assessment against built-in mock target ==")
        from aegis.core.config import default_config
        from aegis.graph import run_assessment

        cfg = default_config("aegis-poc-demo")
        cfg.workdir = OUT / "aegis_run"
        cfg.loop.max_rounds = 4

        started = ts()
        log(fh, f"assessment started: {started}")

        def progress(kind, data):
            if kind == "phase":
                log(fh, f"  phase -> {data['phase']}")

        state = run_assessment(cfg, progress=progress)
        finished = ts()
        log(fh, f"assessment finished: {finished}")
        log(fh, f"engagement={cfg.engagement}  findings={len(state.findings)}  "
                f"coverage={state.coverage.get('mean',0):.0%}  errors={len(state.errors)}")
        for f in sorted(state.findings, key=lambda x: -x.severity.rank):
            fw = ", ".join(sorted(f.frameworks)) or "-"
            log(fh, f"  [{f.severity.value:8s}] {f.title} ({f.confidence.band}; {fw})")
        report_dir = state.report_paths.get("dir")
        log(fh, f"reports written to: {report_dir}")
        for k, v in state.report_paths.items():
            log(fh, f"  {k}: {v}")
        log(fh)

        # 5) Test suite
        log(fh, "== [5/6] Test suite (offline) ==")
        run_cmd(fh, [sys.executable, "-m", "pytest", "-q", "--no-header"])
        log(fh)

        # 6) Summary manifest
        log(fh, "== [6/6] Evidence manifest ==")
        manifest = {
            "run_at": ts(),
            "assessment_started": started,
            "assessment_finished": finished,
            "host": platform.platform(),
            "python": platform.python_version(),
            "engagement": cfg.engagement,
            "findings": len(state.findings),
            "coverage_mean": state.coverage.get("mean", 0),
            "report_paths": {k: str(v) for k, v in state.report_paths.items()},
            "methodologies": [
                {"id": m.get("id"), "phases": m.get("phase_count"),
                 "techniques": m.get("technique_count")}
                for m in kb.get("methodologies", [])
            ] if 'kb' in dir() else [],
        }
        (OUT / "run_manifest.json").write_text(json.dumps(manifest, indent=2))
        log(fh, "wrote run_manifest.json")
        log(fh, "PoC run complete.")

    print(f"\nConsole log: {console}")
    print(f"HTML dashboard: {OUT / 'aegis_run'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
