#!/usr/bin/env python3
"""Screenshot the generated AEGIS HTML dashboard/report as PoC evidence.

Uses the pre-installed Chromium via Playwright (headless). Produces PNGs of the
offline dashboard and the full Markdown-rendered report so the proof-of-concept
has visual, timestamped evidence of the platform running.

Falls back gracefully with a clear message if Playwright/Chromium is unavailable.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "proof-of-concept"
RUN = OUT / "aegis_run"
SHOTS = OUT / "screenshots"
SHOTS.mkdir(parents=True, exist_ok=True)


def _find_html() -> Path | None:
    # The report dir contains report.html / dashboard is dashboard.json; render
    # report.html which is the self-contained dashboard.
    for cand in RUN.rglob("*.html"):
        return cand
    return None


def main() -> int:
    html = _find_html()
    if html is None:
        print(f"No HTML report found under {RUN}; run scripts/run_poc.py first.")
        return 1

    try:
        from playwright.sync_api import sync_playwright
    except Exception as e:
        print(f"Playwright not available ({e}). Skipping screenshots. "
              f"HTML report is at: {html}")
        return 0

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%SUTC")
    url = html.resolve().as_uri()
    print(f"Rendering {url}")

    # Resolve the pre-installed Chromium binary (build may differ from the pip
    # package's expected build, so pin the executable explicitly).
    import glob as _glob
    candidates = [
        "/opt/pw-browsers/chromium/chrome-linux/chrome",
    ] + sorted(_glob.glob("/opt/pw-browsers/chromium-*/chrome-linux/chrome"))
    # Follow the 'chromium' symlink target too.
    link = Path("/opt/pw-browsers/chromium")
    if link.is_symlink():
        candidates.insert(0, str(link.resolve()))
    exe = next((c for c in candidates if Path(c).exists()), None)

    with sync_playwright() as p:
        launch_kwargs = {"headless": True, "args": ["--no-sandbox", "--disable-gpu"]}
        if exe:
            print(f"Using Chromium: {exe}")
            launch_kwargs["executable_path"] = exe
        browser = p.chromium.launch(**launch_kwargs)
        for theme, scheme in (("dark", "dark"), ("light", "light")):
            page = browser.new_page(viewport={"width": 1200, "height": 900},
                                    color_scheme=scheme)
            page.goto(url, wait_until="networkidle")
            shot = SHOTS / f"dashboard_{theme}_{stamp}.png"
            page.screenshot(path=str(shot), full_page=True)
            print(f"  wrote {shot}")
            page.close()
        browser.close()

    print("Screenshots complete.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
