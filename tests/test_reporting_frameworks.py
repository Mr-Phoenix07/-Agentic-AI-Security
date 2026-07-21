from __future__ import annotations

import json

from aegis.core.types import (
    Confidence,
    EvaluationMode,
    Finding,
    FindingCategory,
    Severity,
)
from aegis.reporting import (
    ReportBuilder,
    frameworks_for,
    mitigations_for,
    regression_tests_for,
    render_html,
    render_json,
    render_markdown,
)


def _finding():
    return Finding(
        title="Parser brittleness", category=FindingCategory.ROBUSTNESS,
        severity=Severity.MEDIUM, mode=EvaluationMode.GREY_BOX,
        confidence=Confidence(0.72, "n=28", 28),
        summary="s", root_cause="rc", target_id="m",
        frameworks=frameworks_for(FindingCategory.ROBUSTNESS),
        mitigations=mitigations_for(FindingCategory.ROBUSTNESS),
        regression_tests=regression_tests_for(FindingCategory.ROBUSTNESS))


def test_framework_mapping_present():
    fw = frameworks_for(FindingCategory.MCP_EXPOSURE)
    assert "owasp_llm" in fw
    assert mitigations_for(FindingCategory.AUTHZ)
    assert regression_tests_for(FindingCategory.LONG_CONTEXT)


def test_report_builder_partitions_ai_and_web():
    web = Finding(title="Unauth endpoint", category=FindingCategory.AUTHZ,
                  severity=Severity.HIGH)
    rep = ReportBuilder().build(
        "eng", targets=[{"id": "m", "kind": "local_llm", "mode": "grey_box"}],
        findings=[_finding().to_dict(), web.to_dict()], observations=[],
        metrics={"robustness_formatting.stability": 0.64},
        coverage={"mean": 1.0}, scope={"rules": []})
    assert len(rep.ai_findings) == 1
    assert len(rep.web_findings) == 1
    assert rep.risk_ratings["counts_by_severity"]["high"] == 1


def test_renderers_produce_output():
    rep = ReportBuilder().build(
        "eng", targets=[{"id": "m", "kind": "local_llm", "mode": "grey_box"}],
        findings=[_finding().to_dict()], observations=[],
        metrics={"m.v": 0.5}, coverage={"mean": 1.0},
        scope={"rules": [{"label": "lab", "hosts": ["localhost"],
                          "model_ids": ["mock-*"], "authorization_ref": "x"}]})
    md = render_markdown(rep)
    assert "Executive Summary" in md and "Mitigation Roadmap" in md
    assert "Regression Test Plan" in md
    html = render_html(rep)
    assert "<!doctype html>" in html.lower() and "AEGIS" in html
    data = json.loads(render_json(rep))
    assert data["engagement"] == "eng"


def test_severity_ordering():
    assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW
    assert max([Severity.LOW, Severity.CRITICAL, Severity.MEDIUM]) == Severity.CRITICAL
