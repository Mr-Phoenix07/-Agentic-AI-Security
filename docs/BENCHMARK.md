# Accuracy Benchmark

AEGIS measures its own **detection accuracy** the way a security scanner is
benchmarked: run the platform against targets whose weaknesses are **known in
advance** (ground truth) and compare what it reports to what should be there.

- **Code:** [`aegis/benchmark/`](../aegis/benchmark/) — `models.py` (scoring),
  `fixtures.py` (ground-truth cases), `harness.py` (runner).
- **CLI:** `aegis benchmark` (summary) · `aegis benchmark --json` (full report).
- **Report generator:** [`scripts/run_benchmark.py`](../scripts/run_benchmark.py)
  → writes JSON/Markdown/HTML + screenshots under
  [`docs/proof-of-concept/benchmark/`](proof-of-concept/benchmark/).

Everything is **offline and self-contained**: the fixtures use the deterministic
mock provider and declared-inventory surfaces — no network, no API keys, and no
external or unauthorized target. This is deliberately *not* a live HTB/CTF runner
(AEGIS is an authorization-gated assessment platform, not an exploitation engine);
it is a labelled test set that quantifies how reliably the detectors fire.

## What is measured

Per case, scoring is restricted to a set of *graded* finding categories so that
behavioural noise never counts against a surface-detection case:

| Term | Meaning |
|------|---------|
| **TP** (true positive)  | An expected (ground-truth) finding was reported. |
| **FN** (false negative) | An expected finding was missed. |
| **FP** (false positive) | A reported finding in a graded category matched no expected finding — measured especially on the **hardened control** cases, which should produce nothing. |
| **Precision** | TP / (TP + FP) — freedom from false alarms. |
| **Recall**    | TP / (TP + FN) — completeness of detection. |
| **F1**        | Harmonic mean of precision and recall. |

## Cases

| Case | Kind | Ground truth |
|------|------|--------------|
| `web-exposed-ai-api` | vulnerable | Unauth AI endpoint (AUTHZ), no-rate-limit AI (API_SECURITY), unauth state-changing (AUTHZ) |
| `mcp-open-surface` | vulnerable | Unauthenticated MCP transport + side-effecting tool without confirmation (MCP_EXPOSURE ×2) |
| `graphql-exposed-ai` | vulnerable | Unauthenticated AI resolver (AUTHZ) |
| `web-hardened-control` | hardened-control | **Nothing** (all endpoints authed + rate-limited) |
| `mcp-hardened-control` | hardened-control | **Nothing** (authed transport, all dangerous tools confirmed) |
| `llm-brittle-behavioural` | vulnerable (recall-only) | ≥1 robustness weakness on a low-quality LLM |

The hardened controls are what make precision meaningful: a detector that flags
everything would fail them.

## Documented coverage gaps (reported separately)

Honesty matters more than a perfect score, so the suite also includes cases that
AEGIS **cannot** currently detect and reports them *outside* the headline metric:

| Case | Why it's a gap |
|------|----------------|
| `web-authenticated-bola-gap` | BOLA/IDOR on an **authenticated** endpoint can't be found from declared inventory — it needs live two-principal testing (see [METHODOLOGY_WEBAPP](METHODOLOGY_WEBAPP.md), WSTG-ATHZ-01). |

These appear under `coverage_gaps` in the JSON and in a separate section of the
report, so the headline reflects *implemented* detections while the gaps stay
visible as future work.

## Latest result

See [`docs/proof-of-concept/benchmark/BENCHMARK_REPORT.md`](proof-of-concept/benchmark/BENCHMARK_REPORT.md)
and the dashboard screenshots. Reproduce anytime with:

```bash
aegis benchmark                 # summary table
python scripts/run_benchmark.py # full report + screenshots
pytest tests/test_benchmark.py  # scoring + fixtures under test
```

## Testing an authorized real target

The benchmark validates the *code*. To assess a **real** system you're authorized
to test (e.g. an AI/LLM/web-API surface exposed by an HTB/CTF target or your own
lab), add it to an engagement config's fail-closed authorization scope and run
`aegis run <config>.yaml` — see [`examples/authorized_targets.yaml`](../examples/authorized_targets.yaml).
AEGIS performs declared-inventory review and controlled, safe validation; it is
not an autonomous exploitation tool.
