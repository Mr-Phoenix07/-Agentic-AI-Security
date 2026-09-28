"""Run benchmark cases and score AEGIS's detection accuracy.

Fully offline: each case is turned into a normal AEGIS engagement (localhost
scope, mock provider), assessed end-to-end, and the reported findings are matched
against the case's ground truth to produce per-case and aggregate
precision / recall / F1.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from ..core.authorization import localhost_scope
from ..core.config import Config, LoopConfig, TargetConfig
from ..core.types import Severity, now_ts
from ..graph import run_assessment
from .fixtures import default_suite
from .models import BenchmarkCase, BenchmarkReport, CaseResult

_SEV_RANK = {s.value: s.rank for s in Severity}


def _config_for_case(case: BenchmarkCase, *, seed: int, workdir: Path) -> Config:
    cfg = Config(
        engagement=f"benchmark-{case.id}",
        workdir=workdir,
        scope=localhost_scope(f"benchmark-{case.id}"),
        loop=LoopConfig(max_rounds=3, min_rounds=1, probes_per_round=12, seed=seed),
    )
    cfg.targets = [TargetConfig(**t) for t in case.targets]
    return cfg


def _score_case(case: BenchmarkCase, findings: list[dict]) -> CaseResult:
    graded_values = case.graded_values()
    min_rank = case.min_severity.rank

    graded = [
        f for f in findings
        if f.get("category") in graded_values
        and _SEV_RANK.get(f.get("severity", "info"), 0) >= min_rank
    ]

    res = CaseResult(case_id=case.id, kind=case.kind)
    res.reported = [
        {"target_id": f.get("target_id"), "category": f.get("category"),
         "severity": f.get("severity"), "title": f.get("title")}
        for f in graded
    ]

    consumed: set[int] = set()
    for exp in case.expected:
        hit_idx = next(
            (i for i, f in enumerate(graded)
             if i not in consumed and exp.matches(f)),
            None,
        )
        if hit_idx is None:
            res.fn += 1
            res.missed.append(f"{exp.target_id}:{exp.category.value}"
                              + (f" ~ '{exp.title_contains}'" if exp.title_contains else ""))
        else:
            consumed.add(hit_idx)
            res.tp += 1
            f = graded[hit_idx]
            res.matched.append(f"{f['target_id']}:{f['category']} -> {f['title']}")

    if case.count_false_positives:
        for i, f in enumerate(graded):
            if i not in consumed:
                res.fp += 1
                res.spurious.append(f"{f['target_id']}:{f['category']} -> {f['title']}")
    return res


def run_case(case: BenchmarkCase, *, seed: int = 1337,
             workdir: Path | None = None) -> CaseResult:
    """Assess a single case and score it against ground truth."""
    if workdir is None:
        tmp = tempfile.mkdtemp(prefix=f"aegis_bench_{case.id}_")
        workdir = Path(tmp)
    cfg = _config_for_case(case, seed=seed, workdir=Path(workdir))
    state = run_assessment(cfg)
    findings = [f.to_dict() for f in state.findings]
    return _score_case(case, findings)


def run_suite(cases: list[BenchmarkCase] | None = None, *, seed: int = 1337,
              workdir: Path | None = None) -> BenchmarkReport:
    """Assess every case and aggregate accuracy metrics."""
    cases = cases if cases is not None else default_suite()
    report = BenchmarkReport(seed=seed, generated_at=now_ts())
    for i, case in enumerate(cases):
        case_workdir = None
        if workdir is not None:
            case_workdir = Path(workdir) / case.id
        report.cases.append(run_case(case, seed=seed + i, workdir=case_workdir))
    return report


def run_default_benchmark(*, seed: int = 1337) -> BenchmarkReport:
    return run_suite(default_suite(), seed=seed)
