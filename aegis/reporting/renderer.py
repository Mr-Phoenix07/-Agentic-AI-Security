"""Render a :class:`~aegis.reporting.models.Report` to Markdown / JSON / HTML.

Markdown and JSON have no dependencies. HTML uses Jinja2 when available and
falls back to a self-contained string template otherwise, so a shareable
dashboard is always producible offline.
"""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone

from .models import Report

_SEV_ORDER = ["critical", "high", "medium", "low", "info"]
_SEV_EMOJI = {"critical": "🟥", "high": "🟧", "medium": "🟨", "low": "🟦", "info": "⬜"}


def _ts(t: float) -> str:
    return datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def render_json(report: Report) -> str:
    return json.dumps(report.to_dict(), indent=2, default=str, ensure_ascii=False)


def _finding_md(f: dict) -> str:
    conf = f.get("confidence_json")
    if isinstance(conf, str):
        try:
            conf = json.loads(conf)
        except Exception:
            conf = {}
    conf = conf or {}
    fw = f.get("frameworks_json") or f.get("frameworks") or {}
    if isinstance(fw, str):
        try:
            fw = json.loads(fw)
        except Exception:
            fw = {}
    mit = f.get("mitigations_json") or f.get("mitigations") or []
    if isinstance(mit, str):
        try:
            mit = json.loads(mit)
        except Exception:
            mit = []
    lines = [
        f"#### {_SEV_EMOJI.get(f.get('severity','info'),'')} {f.get('title','(untitled)')}",
        "",
        f"- **Severity:** {f.get('severity','info')}  |  "
        f"**Category:** {f.get('category','other')}  |  "
        f"**Mode:** {f.get('mode','black_box')}  |  "
        f"**Confidence:** {conf.get('band','?')} ({conf.get('value','?')})",
        f"- **Summary:** {f.get('summary','')}",
    ]
    if f.get("root_cause"):
        lines.append(f"- **Root cause:** {f['root_cause']}")
    if f.get("impact"):
        lines.append(f"- **Impact:** {f['impact']}")
    if fw:
        refs = "; ".join(f"{k}: {', '.join(v)}" for k, v in fw.items())
        lines.append(f"- **Framework mapping:** {refs}")
    if mit:
        lines.append("- **Mitigations:**")
        lines += [f"    - {m}" for m in mit]
    lines.append("")
    return "\n".join(lines)


def render_markdown(report: Report) -> str:
    r = report
    out: list[str] = []
    A = out.append
    A(f"# AEGIS Security Assessment — {r.engagement}\n")
    A(f"_Generated {_ts(r.generated_at)} · AEGIS autonomous evaluation platform_\n")

    A("## 1. Executive Summary\n")
    A(r.executive_summary + "\n")

    rr = r.risk_ratings
    A("### Risk at a glance\n")
    A("| Severity | Count |")
    A("|----------|-------|")
    for s in _SEV_ORDER:
        A(f"| {_SEV_EMOJI[s]} {s.capitalize()} | {rr.get('counts_by_severity',{}).get(s,0)} |")
    A("")

    A("## 2. Scope & Authorization\n")
    rules = r.scope.get("rules", [])
    if rules:
        A("Assessment was constrained to the following authorized scope (fail-closed):\n")
        for rule in rules:
            A(f"- **{rule.get('label')}** — hosts={rule.get('hosts')} "
              f"models={rule.get('model_ids')} ref=`{rule.get('authorization_ref','')}`")
    else:
        A("_No scope rules recorded._")
    A("")

    A("## 3. Architecture Overview\n")
    for t in r.architecture.get("targets", []):
        A(f"- `{t['id']}` — kind={t['kind']}, mode={t.get('mode')}, "
          f"provider/model={t.get('model')}")
    A("")

    A("## 4. Attack Surface Inventory\n")
    any_surface = False
    for a in r.attack_surface:
        surface = a.get("surface") or {}
        if not surface:
            continue
        any_surface = True
        A(f"### {a['target']} ({a['kind']})")
        A("```json")
        A(json.dumps(surface, indent=2)[:2000])
        A("```")
    if not any_surface:
        A("_No declared web/API/MCP surface inventory for this assessment._")
    A("")

    A("## 5. AI Security Findings\n")
    if r.ai_findings:
        for f in r.ai_findings:
            A(_finding_md(f))
    else:
        A("_No AI-domain findings above threshold._\n")

    A("## 6. Web / API / MCP Security Findings\n")
    if r.web_findings:
        for f in r.web_findings:
            A(_finding_md(f))
    else:
        A("_No application-domain findings above threshold._\n")

    A("## 7. Security Metrics\n")
    if r.metrics:
        A("| Metric | Value |")
        A("|--------|-------|")
        for k, v in sorted(r.metrics.items()):
            A(f"| `{k}` | {v} |")
    else:
        A("_No metrics recorded._")
    A("")

    A("## 8. Coverage Report\n")
    A(f"- Behavioural dimension coverage: **{r.coverage.get('mean', 0):.0%}** of "
      f"measurable dimensions.")
    for dim, conf in (r.coverage.get("dimension_confidence") or {}).items():
        A(f"    - {dim}: confidence {conf}")
    A("")

    A("## 9. Mitigation Roadmap\n")
    if r.mitigation_roadmap:
        for item in r.mitigation_roadmap:
            A(f"- **[{item['priority']}] {item['finding']}** ({item['severity']})")
            for m in item["mitigations"]:
                A(f"    - {m}")
    else:
        A("_No prioritized mitigations._")
    A("")

    A("## 10. Regression Test Plan\n")
    if r.regression_plan:
        for t in r.regression_plan:
            A(f"- [ ] {t}")
    else:
        A("_No regression tests defined._")
    A("")

    A("## 11. Assessment Methodology Reference\n")
    meths = r.appendices.get("methodologies") or []
    if meths:
        A("Findings are produced against AEGIS's phased, standards-mapped "
          "methodologies (queryable via `aegis methodology`):\n")
        A("| Methodology | Domain | Phases | Techniques | Key frameworks |")
        A("|-------------|--------|--------|------------|----------------|")
        for m in meths:
            fw = ", ".join(sorted(m.get("references", {}).keys()))
            A(f"| {m.get('title')} | {m.get('domain')} | {m.get('phases')} | "
              f"{m.get('techniques')} | {fw} |")
    else:
        A("_Methodology knowledge base unavailable._")
    A("")

    A("## 12. Appendices\n")
    A(f"- Observations recorded: {r.appendices.get('observation_count', 0)}")
    A("- Full machine-readable artifacts available in the JSON report and the "
      "SQLite assessment store (probes, responses, evidence, reproduction seeds).")
    A("")
    A("---")
    A("_This report is an evidence-based evaluation of authorized systems. "
      "Findings include reproduction metadata for independent verification._")
    return "\n".join(out)


def render_html(report: Report) -> str:
    """Self-contained HTML dashboard (theme-aware, no external assets)."""
    r = report
    rr = r.risk_ratings.get("counts_by_severity", {})
    cards = "".join(
        f'<div class="card sev-{s}"><div class="n">{rr.get(s,0)}</div>'
        f'<div class="l">{s}</div></div>' for s in _SEV_ORDER)

    def find_rows(findings):
        if not findings:
            return '<tr><td colspan="4"><em>None above threshold.</em></td></tr>'
        rows = []
        for f in findings:
            conf = f.get("confidence_json")
            if isinstance(conf, str):
                try:
                    conf = json.loads(conf)
                except Exception:
                    conf = {}
            rows.append(
                f'<tr><td><span class="pill sev-{f.get("severity","info")}">'
                f'{f.get("severity","info")}</span></td>'
                f'<td>{html.escape(f.get("title",""))}</td>'
                f'<td>{html.escape(f.get("category",""))}</td>'
                f'<td>{(conf or {}).get("band","?")}</td></tr>')
        return "".join(rows)

    metric_rows = "".join(
        f"<tr><td><code>{html.escape(k)}</code></td><td>{v}</td></tr>"
        for k, v in sorted(r.metrics.items()))

    meths = r.appendices.get("methodologies") or []
    meth_rows = "".join(
        f"<tr><td>{html.escape(m.get('title',''))}</td>"
        f"<td><code>{html.escape(m.get('domain',''))}</code></td>"
        f"<td>{m.get('phases',0)}</td><td>{m.get('techniques',0)}</td></tr>"
        for m in meths) or '<tr><td colspan=4><em>none</em></td></tr>'

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AEGIS Report — {html.escape(r.engagement)}</title>
<style>
:root{{--bg:#0b0e14;--fg:#e6e6e6;--muted:#9aa4b2;--card:#151a23;--line:#232a36;}}
@media (prefers-color-scheme: light){{:root{{--bg:#f7f8fa;--fg:#1a1f29;--muted:#5b6472;--card:#fff;--line:#e3e7ee;}}}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.55 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}}
.wrap{{max-width:1000px;margin:0 auto;padding:28px}}
h1{{font-size:24px;margin:0 0 4px}}.sub{{color:var(--muted);margin-bottom:24px}}
h2{{font-size:18px;margin:28px 0 12px;border-bottom:1px solid var(--line);padding-bottom:6px}}
.cards{{display:flex;gap:12px;flex-wrap:wrap}}
.card{{flex:1;min-width:110px;background:var(--card);border:1px solid var(--line);
border-radius:12px;padding:16px;text-align:center}}
.card .n{{font-size:28px;font-weight:700}}.card .l{{color:var(--muted);text-transform:capitalize}}
table{{width:100%;border-collapse:collapse;background:var(--card);border-radius:10px;overflow:hidden}}
th,td{{text-align:left;padding:9px 12px;border-bottom:1px solid var(--line);font-size:14px}}
th{{color:var(--muted);font-weight:600}}
.pill{{padding:2px 8px;border-radius:999px;font-size:12px;font-weight:600;text-transform:capitalize}}
.sev-critical{{color:#fff;background:#b3232f}}.sev-high{{color:#fff;background:#c8641a}}
.sev-medium{{color:#111;background:#d9b429}}.sev-low{{color:#fff;background:#2f6fb3}}
.sev-info{{color:var(--fg);background:var(--line)}}
.summary{{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px}}
code{{background:var(--line);padding:1px 5px;border-radius:5px}}
.overflow{{overflow-x:auto}}
</style></head>
<body><div class="wrap">
<h1>AEGIS Security Assessment</h1>
<div class="sub">{html.escape(r.engagement)} · generated {_ts(r.generated_at)}</div>
<div class="summary">{html.escape(r.executive_summary)}</div>
<h2>Risk at a glance</h2><div class="cards">{cards}</div>
<h2>AI Security Findings</h2><div class="overflow"><table>
<tr><th>Severity</th><th>Finding</th><th>Category</th><th>Confidence</th></tr>
{find_rows(r.ai_findings)}</table></div>
<h2>Web / API / MCP Findings</h2><div class="overflow"><table>
<tr><th>Severity</th><th>Finding</th><th>Category</th><th>Confidence</th></tr>
{find_rows(r.web_findings)}</table></div>
<h2>Security Metrics</h2><div class="overflow"><table>
<tr><th>Metric</th><th>Value</th></tr>{metric_rows or '<tr><td colspan=2><em>none</em></td></tr>'}
</table></div>
<h2>Coverage</h2><p>Behavioural coverage:
<strong>{r.coverage.get('mean',0):.0%}</strong> of measurable dimensions.</p>
<h2>Assessment Methodology Reference</h2><div class="overflow"><table>
<tr><th>Methodology</th><th>Domain</th><th>Phases</th><th>Techniques</th></tr>
{meth_rows}</table></div>
<p class="sub">Queryable via <code>aegis methodology</code> — OWASP WSTG · MITRE ATT&amp;CK · OWASP LLM/ASI · MITRE ATLAS · NIST AI RMF.</p>
</div></body></html>"""
