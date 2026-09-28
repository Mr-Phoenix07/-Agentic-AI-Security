"""Offline accuracy benchmark for AEGIS.

Measures the platform's detection accuracy (precision / recall / F1) against
self-contained fixtures whose weaknesses are known in advance — the security-tool
equivalent of a labelled test set. Everything runs offline on the mock provider;
no network, no keys, no external or unauthorized targets.

    from aegis.benchmark import run_default_benchmark
    report = run_default_benchmark()
    print(report.to_dict()["totals"])
"""

from __future__ import annotations

from .fixtures import default_suite
from .harness import run_case, run_default_benchmark, run_suite
from .models import (
    BenchmarkCase,
    BenchmarkReport,
    CaseResult,
    ExpectedFinding,
)

__all__ = [
    "BenchmarkCase", "BenchmarkReport", "CaseResult", "ExpectedFinding",
    "default_suite", "run_case", "run_suite", "run_default_benchmark",
]
