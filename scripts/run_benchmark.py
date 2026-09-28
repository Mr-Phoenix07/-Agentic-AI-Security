#!/usr/bin/env python3
"""Run the AEGIS offline accuracy benchmark and emit a timestamped report.

Produces, under docs/proof-of-concept/benchmark/:
  * benchmark_report.json   — full machine-readable results
  * BENCHMARK_REPORT.md     — human-readable accuracy report
  * benchmark.html          — self-contained dashboard (for screenshotting)
  * screenshots/*.png       — rendered dashboard (dark/light) if Chromium is present

Offline and self-contained: the benchmark assesses mock-provider fixtures with
known ground truth. No network, no keys, no external or unauthorized targets.
"""

from __future__ import annotations

import glob
import html
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
OUT = ROOT / "docs" / "proof-of-concept" / "benchmark"
SHOTS = OUT / "screenshots"
OUT.mkdir(parents=True, exist_ok=True)
SHOTS.mkdir(parents=True, exist_ok=True)


def ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _md(report: dict) -> str:
    t = report["totals"]
    L = [
        "# AEGIS — Offline Accuracy Benchmark",
        "",
        f"_Generated {ts()} · seed={report['seed']} · offline mock fixtures, "
        "no network/keys/external targets_",
        "",
        "## Headline — implemented-detection accuracy",
        "",
        "| Precision | Recall | F1 | TP | FP | FN | Cases |",
        "|:--:|:--:|:--:|:--:|:--:|:--:|:--:|",
        f"| **{t['precision']:.3f}** | **{t['recall']:.3f}** | **{t['f1']:.3f}** | "
        f"{t['tp']} | {t['fp']} | {t['fn']} | {t['graded_cases']} |",
        "",
        "Precision = no false alarms on the hardened control cases; "
        "Recall = every planted, deterministically-detectable weakness was found.",
        "",
        "## Per-case results",
        "",
        "| Case | Kind | Precision | Recall | F1 | TP | FP | FN |",
        "|------|------|:--:|:--:|:--:|:--:|:--:|:--:|",
    ]
    for c in report["cases"]:
        L.append(f"| `{c['case_id']}` | {c['kind']} | {c['precision']:.2f} | "
                 f"{c['recall']:.2f} | {c['f1']:.2f} | {c['tp']} | {c['fp']} | {c['fn']} |")
    L += ["", "### Detections (true positives)", ""]
    for c in report["cases"]:
        for m in c["matched"]:
            L.append(f"- ✅ `{c['case_id']}` — {m}")
    gaps = report.get("coverage_gaps") or []
    if gaps:
        L += ["", "## Documented coverage gaps (reported separately)", "",
              "These are honest known limitations — reported outside the headline "
              "because they need live testing, not declared-inventory review.", ""]
        for c in gaps:
            L.append(f"- ⚠️ `{c['case_id']}` — recall {c['recall']:.2f}; "
                     f"missed: {', '.join(c['missed']) or '—'} "
                     "(requires live two-principal testing; see "
                     "`docs/METHODOLOGY_WEBAPP.md`, WSTG-ATHZ-01).")
    L += ["", "## Reproduce", "", "```bash", "aegis benchmark            # summary",
          "aegis benchmark --json     # full JSON", "python scripts/run_benchmark.py",
          "```", "",
          "_Ground truth is defined in `aegis/benchmark/fixtures.py`; scoring in "
          "`aegis/benchmark/harness.py`._"]
    return "\n".join(L)


def _html(report: dict) -> str:
    t = report["totals"]

    def rows(cases):
        out = []
        for c in cases:
            out.append(
                f"<tr><td><code>{html.escape(c['case_id'])}</code></td>"
                f"<td>{html.escape(c['kind'])}</td>"
                f"<td>{c['precision']:.2f}</td><td>{c['recall']:.2f}</td>"
                f"<td>{c['f1']:.2f}</td><td>{c['tp']}</td><td>{c['fp']}</td>"
                f"<td>{c['fn']}</td></tr>")
        return "".join(out)

    gap_html = ""
    if report.get("coverage_gaps"):
        gap_html = ("<h2>Documented coverage gaps</h2><div class='overflow'><table>"
                    "<tr><th>Case</th><th>Kind</th><th>Precision</th><th>Recall</th>"
                    "<th>F1</th><th>TP</th><th>FP</th><th>FN</th></tr>"
                    + rows(report["coverage_gaps"]) + "</table></div>"
                    "<p class='sub'>Reported separately — needs live testing, not "
                    "declared-inventory review.</p>")

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AEGIS Accuracy Benchmark</title><style>
:root{{--bg:#0b0e14;--fg:#e6e6e6;--muted:#9aa4b2;--card:#151a23;--line:#232a36;--ok:#2f9e5b;}}
@media (prefers-color-scheme: light){{:root{{--bg:#f7f8fa;--fg:#1a1f29;--muted:#5b6472;--card:#fff;--line:#e3e7ee;--ok:#1f8a4c;}}}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.55 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}}
.wrap{{max-width:960px;margin:0 auto;padding:28px}}
h1{{font-size:24px;margin:0 0 4px}}.sub{{color:var(--muted);margin-bottom:20px}}
h2{{font-size:18px;margin:26px 0 12px;border-bottom:1px solid var(--line);padding-bottom:6px}}
.cards{{display:flex;gap:12px;flex-wrap:wrap}}
.card{{flex:1;min-width:120px;background:var(--card);border:1px solid var(--line);
border-radius:12px;padding:16px;text-align:center}}
.card .n{{font-size:30px;font-weight:800;color:var(--ok)}}.card .l{{color:var(--muted)}}
table{{width:100%;border-collapse:collapse;background:var(--card);border-radius:10px;overflow:hidden}}
th,td{{text-align:left;padding:9px 12px;border-bottom:1px solid var(--line);font-size:14px}}
th{{color:var(--muted);font-weight:600}}code{{background:var(--line);padding:1px 5px;border-radius:5px}}
.overflow{{overflow-x:auto}}
</style></head><body><div class="wrap">
<h1>AEGIS — Offline Accuracy Benchmark</h1>
<div class="sub">Generated {ts()} · seed {report['seed']} · offline mock fixtures (no network/keys)</div>
<div class="cards">
<div class="card"><div class="n">{t['precision']*100:.0f}%</div><div class="l">Precision</div></div>
<div class="card"><div class="n">{t['recall']*100:.0f}%</div><div class="l">Recall</div></div>
<div class="card"><div class="n">{t['f1']*100:.0f}%</div><div class="l">F1</div></div>
<div class="card"><div class="n">{t['tp']}</div><div class="l">True positives</div></div>
<div class="card"><div class="n">{t['fp']}</div><div class="l">False positives</div></div>
</div>
<h2>Per-case results ({t['graded_cases']} graded cases)</h2><div class="overflow"><table>
<tr><th>Case</th><th>Kind</th><th>Precision</th><th>Recall</th><th>F1</th><th>TP</th><th>FP</th><th>FN</th></tr>
{rows(report['cases'])}</table></div>
{gap_html}
<p class="sub">Ground truth: <code>aegis/benchmark/fixtures.py</code> · Scoring: <code>aegis/benchmark/harness.py</code></p>
</div></body></html>"""


def _screenshot(html_path: Path) -> None:
    try:
        from playwright.sync_api import sync_playwright
    except Exception as e:
        print(f"Playwright unavailable ({e}); skipping screenshots. HTML: {html_path}")
        return
    candidates = sorted(glob.glob("/opt/pw-browsers/chromium-*/chrome-linux/chrome"))
    link = Path("/opt/pw-browsers/chromium")
    if link.is_symlink():
        candidates.insert(0, str(link.resolve()))
    exe = next((c for c in candidates if Path(c).exists()), None)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%SUTC")
    url = html_path.resolve().as_uri()
    with sync_playwright() as p:
        kwargs = {"headless": True, "args": ["--no-sandbox", "--disable-gpu"]}
        if exe:
            kwargs["executable_path"] = exe
        browser = p.chromium.launch(**kwargs)
        for theme in ("dark", "light"):
            page = browser.new_page(viewport={"width": 1100, "height": 820},
                                    color_scheme=theme)
            page.goto(url, wait_until="networkidle")
            shot = SHOTS / f"benchmark_{theme}_{stamp}.png"
            page.screenshot(path=str(shot), full_page=True)
            print(f"  wrote {shot}")
            page.close()
        browser.close()


def main() -> int:
    import tempfile

    from aegis.benchmark import run_suite

    print(f"[{ts()}] Running AEGIS accuracy benchmark (offline)...")
    # Per-case assessment runs are intermediate artifacts; keep them out of the repo.
    runs_dir = Path(tempfile.mkdtemp(prefix="aegis_bench_runs_"))
    report = run_suite(seed=1337, workdir=runs_dir)
    d = report.to_dict()
    t = d["totals"]

    (OUT / "benchmark_report.json").write_text(json.dumps(d, indent=2))
    (OUT / "BENCHMARK_REPORT.md").write_text(_md(d))
    html_path = OUT / "benchmark.html"
    html_path.write_text(_html(d))

    print(f"[{ts()}] precision={t['precision']:.3f} recall={t['recall']:.3f} "
          f"f1={t['f1']:.3f} (tp={t['tp']} fp={t['fp']} fn={t['fn']}) "
          f"over {t['graded_cases']} cases; {t['coverage_gap_cases']} gap(s)")
    _screenshot(html_path)
    print(f"[{ts()}] wrote report to {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
