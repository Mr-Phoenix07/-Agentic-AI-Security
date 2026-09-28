"""Tests for the offline accuracy benchmark."""

from __future__ import annotations

from aegis.benchmark import (
    BenchmarkReport,
    default_suite,
    run_case,
    run_suite,
)
from aegis.benchmark.models import CaseResult, ExpectedFinding
from aegis.core.types import FindingCategory, Severity


def test_suite_is_non_empty_and_has_controls():
    suite = default_suite()
    kinds = {c.kind for c in suite}
    assert "vulnerable" in kinds
    assert "hardened-control" in kinds  # needed for a real precision measurement
    assert "coverage-gap" in kinds      # honest known limitation


def test_expected_finding_matcher():
    exp = ExpectedFinding("t1", FindingCategory.AUTHZ, "unauthenticated ai")
    assert exp.matches({"target_id": "t1", "category": "authorization",
                        "title": "Unauthenticated AI endpoint"})
    assert not exp.matches({"target_id": "t2", "category": "authorization",
                           "title": "Unauthenticated AI endpoint"})
    assert not exp.matches({"target_id": "t1", "category": "api_security",
                           "title": "Unauthenticated AI endpoint"})
    # Empty substring matches any finding of the right target+category.
    assert ExpectedFinding("t1", FindingCategory.AUTHZ).matches(
        {"target_id": "t1", "category": "authorization", "title": "anything"})


def test_vulnerable_surface_cases_are_fully_detected():
    """Deterministic surface detections must score perfectly (regression guard)."""
    for case in default_suite():
        if case.kind != "vulnerable" or "llm" in case.id:
            continue
        res = run_case(case, seed=7)
        assert res.fn == 0, f"{case.id} missed: {res.missed}"
        assert res.tp == len(case.expected)


def test_hardened_controls_produce_no_false_positives():
    for case in default_suite():
        if case.kind != "hardened-control":
            continue
        res = run_case(case, seed=7)
        assert res.fp == 0, f"{case.id} false positives: {res.spurious}"
        assert res.tp == 0 and res.fn == 0


def test_coverage_gap_is_reported_but_excluded_from_headline():
    report = run_suite(seed=11)
    assert isinstance(report, BenchmarkReport)
    # A documented gap exists and is not counted in the headline precision/recall.
    assert report.gap_cases, "expected at least one coverage-gap case"
    d = report.to_dict()
    assert d["coverage_gaps"], "gaps must be reported separately"
    assert d["totals"]["graded_cases"] == len(report.graded_cases)


def test_headline_accuracy_is_high_on_implemented_detections():
    report = run_suite(seed=13)
    # The implemented-detection suite should have no false positives and catch
    # every planted, deterministically-detectable weakness.
    assert report.fp == 0
    assert report.recall == 1.0
    assert report.precision == 1.0
    assert report.f1 == 1.0


def test_case_result_metric_math():
    r = CaseResult(case_id="x", kind="vulnerable", tp=3, fp=1, fn=1)
    assert abs(r.precision - 0.75) < 1e-9
    assert abs(r.recall - 0.75) < 1e-9
    assert abs(r.f1 - 0.75) < 1e-9


def test_min_severity_filter_is_respected():
    # Sanity: severity ranking used by the harness is monotone.
    assert Severity.HIGH.rank > Severity.MEDIUM.rank > Severity.LOW.rank
