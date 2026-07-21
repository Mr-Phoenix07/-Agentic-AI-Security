#!/usr/bin/env python3
"""Minimal end-to-end AEGIS demo — offline, no API keys, no network.

Runs a full autonomous assessment against the built-in mock target and prints
where the report was written. Equivalent to ``aegis demo``.

    python examples/run_demo.py
"""

from __future__ import annotations

import sys
from pathlib import Path

# Allow running directly from a source checkout without installing.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aegis.core.config import default_config  # noqa: E402
from aegis.graph import run_assessment  # noqa: E402


def main() -> None:
    cfg = default_config("aegis-readme-demo")
    cfg.loop.max_rounds = 4

    def progress(kind, data):
        if kind == "phase":
            print(f"▸ {data['phase']}")

    state = run_assessment(cfg, progress=progress)

    print(f"\nEngagement: {cfg.engagement}")
    print(f"Coverage:   {state.coverage.get('mean', 0):.0%} of measurable dimensions")
    print(f"Findings:   {len(state.findings)}")
    for f in sorted(state.findings, key=lambda x: -x.severity.rank):
        fw = ", ".join(sorted(f.frameworks)) or "-"
        print(f"  [{f.severity.value:8s}] {f.title}  ({f.confidence.band}; {fw})")
    print(f"\nReports in: {state.report_paths.get('dir')}")
    print("  - report.md / report.html / report.json / dashboard.json")


if __name__ == "__main__":
    main()
