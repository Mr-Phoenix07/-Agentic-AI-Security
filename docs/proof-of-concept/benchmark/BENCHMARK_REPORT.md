# AEGIS — Offline Accuracy Benchmark

_Generated 2026-09-28 06:55:43 UTC · seed=1337 · offline mock fixtures, no network/keys/external targets_

## Headline — implemented-detection accuracy

| Precision | Recall | F1 | TP | FP | FN | Cases |
|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| **1.000** | **1.000** | **1.000** | 7 | 0 | 0 | 6 |

Precision = no false alarms on the hardened control cases; Recall = every planted, deterministically-detectable weakness was found.

## Per-case results

| Case | Kind | Precision | Recall | F1 | TP | FP | FN |
|------|------|:--:|:--:|:--:|:--:|:--:|:--:|
| `web-exposed-ai-api` | vulnerable | 1.00 | 1.00 | 1.00 | 3 | 0 | 0 |
| `mcp-open-surface` | vulnerable | 1.00 | 1.00 | 1.00 | 2 | 0 | 0 |
| `graphql-exposed-ai` | vulnerable | 1.00 | 1.00 | 1.00 | 1 | 0 | 0 |
| `web-hardened-control` | hardened-control | 1.00 | 1.00 | 1.00 | 0 | 0 | 0 |
| `mcp-hardened-control` | hardened-control | 1.00 | 1.00 | 1.00 | 0 | 0 | 0 |
| `llm-brittle-behavioural` | vulnerable | 1.00 | 1.00 | 1.00 | 1 | 0 | 0 |

### Detections (true positives)

- ✅ `web-exposed-ai-api` — vuln-api:authorization -> Unauthenticated AI/inference endpoint
- ✅ `web-exposed-ai-api` — vuln-api:api_security -> AI endpoint without rate limiting
- ✅ `web-exposed-ai-api` — vuln-api:authorization -> Unauthenticated state-changing endpoint
- ✅ `mcp-open-surface` — vuln-mcp:mcp_exposure -> Unauthenticated MCP transport
- ✅ `mcp-open-surface` — vuln-mcp:mcp_exposure -> Side-effecting MCP tool without confirmation: send_email
- ✅ `graphql-exposed-ai` — vuln-graphql:authorization -> Unauthenticated AI/inference endpoint
- ✅ `llm-brittle-behavioural` — brittle-llm:robustness -> Response instability across equivalent prompts

## Documented coverage gaps (reported separately)

These are honest known limitations — reported outside the headline because they need live testing, not declared-inventory review.

- ⚠️ `web-authenticated-bola-gap` — recall 0.00; missed: bola-api:authorization (requires live two-principal testing; see `docs/METHODOLOGY_WEBAPP.md`, WSTG-ATHZ-01).

## Reproduce

```bash
aegis benchmark            # summary
aegis benchmark --json     # full JSON
python scripts/run_benchmark.py
```

_Ground truth is defined in `aegis/benchmark/fixtures.py`; scoring in `aegis/benchmark/harness.py`._