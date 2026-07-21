"""Explainability, mitigation, reporting, and dashboard agents (pipeline tail)."""

from __future__ import annotations

import json
from pathlib import Path

from ..core.types import EvaluationMode
from ..explainability.behavioral import explain_observation
from ..explainability.internals import explain_with_internals
from ..reporting.frameworks import (
    frameworks_for,
    mitigations_for,
    regression_tests_for,
)
from ..reporting.models import ReportBuilder
from ..reporting.renderer import render_html, render_json, render_markdown
from .base import BaseAgent


class ExplainabilityAgent(BaseAgent):
    name = "explainability"
    responsibilities = ("Attach behavioral (always) and white-box (when available) "
                        "explanations to key findings.")
    inputs = ["findings", "verified_observations", "pairs"]
    outputs = ["explanations"]

    def _run(self, state):
        obs_by_id = {o.id: o for o in state.verified_observations}
        for f in state.findings:
            tid = f.target_id or ""
            pairs = state.pairs.get(tid, [])
            expl = state.explanations.setdefault(tid, {})
            for oid in f.observation_ids:
                obs = obs_by_id.get(oid)
                if obs and pairs:
                    e = explain_observation(obs, pairs)
                    expl[f.id] = e.to_dict()
            # White-box path (degrades gracefully to a documented note).
            target = state.target(tid)
            if target and target.mode == EvaluationMode.WHITE_BOX:
                wb = explain_with_internals(
                    target.metadata.get("model_handle"),
                    (pairs[0].probe.payload.get("prompt", "") if pairs else ""))
                expl.setdefault("_internals", wb.to_dict())
        return state


class MitigationRecommendationAgent(BaseAgent):
    name = "mitigation_recommendation"
    responsibilities = ("Attach standards-aligned framework references, defensive "
                        "mitigations, and regression tests to every finding.")
    inputs = ["findings"]
    outputs = ["findings"]

    def _run(self, state):
        for f in state.findings:
            f.frameworks = frameworks_for(f.category)
            f.mitigations = mitigations_for(f.category)
            f.regression_tests = regression_tests_for(f.category)
        return state


class ReportingAgent(BaseAgent):
    name = "reporting"
    responsibilities = ("Assemble and render the assessment report (Markdown, HTML, "
                        "JSON); persist findings; finish the assessment record.")
    inputs = ["findings", "verified_observations", "metrics", "coverage"]
    outputs = ["report_paths"]

    def _run(self, state):
        for f in state.findings:
            state.db.save_finding(state.assessment_id, f)
        state.db.commit()

        targets = [{
            "id": t.id, "kind": t.kind.value, "mode": t.mode.value,
            "model": t.metadata.get("model"),
            "surface": t.attack_surface() if hasattr(t, "attack_surface") else {},
        } for t in state.targets]

        builder = ReportBuilder()
        report = builder.build(
            state.config.engagement,
            targets=targets,
            findings=[f.to_dict() for f in state.findings],
            observations=[o.to_dict() for o in state.verified_observations],
            metrics=state.metrics,
            coverage=state.coverage,
            scope=state.config.scope.summary(),
            timeline=state.tracer.timeline(),
        )
        # attach explanations + per-round coverage into appendices
        report.appendices["explanations"] = state.explanations
        report.appendices["errors"] = state.errors
        report.appendices["agent_trail"] = state.trail

        outdir = Path(state.config.workdir) / state.assessment_id
        outdir.mkdir(parents=True, exist_ok=True)
        md, html, js = render_markdown(report), render_html(report), render_json(report)
        (outdir / "report.md").write_text(md, encoding="utf-8")
        (outdir / "report.html").write_text(html, encoding="utf-8")
        (outdir / "report.json").write_text(js, encoding="utf-8")
        state.report_paths = {
            "markdown": str(outdir / "report.md"),
            "html": str(outdir / "report.html"),
            "json": str(outdir / "report.json"),
            "dir": str(outdir),
        }
        state.db.finish_assessment(state.assessment_id, "completed")
        state.logger.bind(agent=self.name).info(
            "report.written", "report rendered", dir=str(outdir),
            findings=len(state.findings))
        return state


class DashboardAgent(BaseAgent):
    name = "dashboard"
    responsibilities = ("Emit machine-readable dashboard data: coverage/confidence "
                        "time-series and metric snapshot for external dashboards.")
    inputs = ["evaluations", "metrics", "coverage"]
    outputs = ["report_paths"]

    def _run(self, state):
        series = {}
        for tid, rep in state.evaluations.items():
            series[tid] = [
                {"round": r.index, "coverage": r.coverage,
                 "mean_confidence": r.mean_confidence, "probes": r.probes,
                 "gaps": r.gaps}
                for r in rep.rounds
            ]
        dashboard = {
            "engagement": state.config.engagement,
            "assessment_id": state.assessment_id,
            "coverage": state.coverage,
            "metrics": state.metrics,
            "rounds": series,
            "finding_counts": self._counts(state),
        }
        if state.report_paths.get("dir"):
            p = Path(state.report_paths["dir"]) / "dashboard.json"
            p.write_text(json.dumps(dashboard, indent=2, default=str), encoding="utf-8")
            state.report_paths["dashboard"] = str(p)
        return state

    def _counts(self, state):
        counts: dict[str, int] = {}
        for f in state.findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        return counts
