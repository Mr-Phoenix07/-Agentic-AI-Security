# Authorized-Use Policy & Security

## Authorized use only

AEGIS is a **defensive** security-evaluation platform. Use it only against systems
you **own** or are **explicitly authorized** to assess (signed statement of work,
written permission, your own lab).

This is enforced in code, not just policy:

- **Fail-closed authorization gate** (`aegis/core/authorization.py`). Every target
  interaction passes an allow-list of scope rules (hosts, URLs, model ids, CIDRs),
  optionally time-boxed and volume-capped, each carrying an audit reference. An
  **empty scope authorizes nothing**; out-of-scope requests are refused before any
  provider is contacted.
- **Offline by default.** The bundled mock target requires no network. Real
  endpoints only become reachable when you add an explicit, in-scope rule.
- **Benign, semantics-preserving probes.** The mutation framework re-encodes
  ordinary requests to measure robustness/consistency/parser-resilience — it does
  not attempt to defeat safeguards, and AEGIS does not ship exploit payloads or
  destructive techniques.
- **Non-intrusive surface review.** Web/API/MCP assessment reasons over a declared
  inventory and performs only narrow, authorized confirmatory checks; it does not
  invoke side-effecting/dangerous tools.

Verify your scope before running:

```bash
aegis scope-check engagement.yaml --url https://target.example.com --model your-model
```

## Handling of sensitive data

- API keys are read from `AEGIS_API_KEY` (env), never persisted to the report or
  DB. Do not commit keys.
- Evidence and transcripts are stored locally in SQLite / the report directory.
  Treat assessment output as sensitive and store it accordingly.

## Reporting a vulnerability in AEGIS

Please open a private report to the maintainer rather than a public issue. Include
a minimal reproduction and affected version.
