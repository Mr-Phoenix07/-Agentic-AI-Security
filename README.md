# AEGIS

**Autonomous Agentic AI Security Assessment & Adversarial Evaluation Platform**

AEGIS is a modular, explainable, **offline-capable** platform for continuous,
*authorized* security evaluation of AI systems and web applications. It combines
AI red-teaming, LLM behavioural evaluation, RAG assessment, agentic/MCP security,
and web/API VAPT into one closed-loop, multi-agent workflow that produces
reproducible evidence, standards-aligned findings, and defensive mitigation
guidance.

> _AEGIS backronym: **A**daptive **E**valuation & **G**uarded **I**nspection **S**ystem._

```
┌──────────────────────────────────────────────────────────────────────┐
│  objectives ─▶ PLAN ─▶ MAP ─▶ EVALUATE ─▶ ANALYZE ─▶ REMEDIATE ─▶ REPORT │
│                          ▲ 23 collaborating agents · adaptive loop ▲     │
└──────────────────────────────────────────────────────────────────────┘
```

---

## ⚖️ Authorized use only — this is a defensive tool

AEGIS assesses **systems you own or are explicitly authorized to assess**. That
constraint is not a footnote; it is an **enforced, fail-closed runtime gate**
([`aegis/core/authorization.py`](aegis/core/authorization.py)):

- Every request to any target passes an **allow-list** of scope rules (hosts,
  URLs, model ids, CIDRs), optionally time-boxed and volume-capped, each carrying
  an audit reference (signed SoW, ticket).
- An **empty scope authorizes nothing.** Out-of-scope requests never reach a
  provider — they are refused and recorded.
- The prompt-mutation framework generates *semantics-preserving re-encodings of
  benign requests* to measure robustness, parser resilience, and calibration —
  **not** to defeat safeguards.

```bash
aegis scope-check engagement.yaml --url https://not-authorized.example.com
# URL https://not-authorized.example.com: DENIED — not covered by any active scope rule
```

---

## Why AEGIS

| Principle | How it shows up |
|-----------|-----------------|
| **Offline capability** | Core has **zero hard dependencies**; a built-in deterministic mock target runs the whole pipeline with no network or API keys. |
| **Reproducibility** | Content-addressed probes, seeded RNG, per-finding reproduction metadata, SQLite record of every probe/response/evidence. |
| **Explainability** | Behavioural attribution always; TransformerLens/SHAP/Captum white-box when weights are available (graceful fallback otherwise). |
| **Evidence-first** | Confidence is a Wilson-interval **precision** measure, not a vibe. Severity is derived from measured shortfall × confidence. |
| **Vendor independence** | Pluggable providers (mock, any OpenAI-compatible endpoint: Ollama/vLLM/LM Studio/authorized gateways). |
| **Standards-aligned** | Findings map to OWASP LLM Top 10, OWASP API Top 10, OWASP Top 10, ASVS, MITRE ATLAS, NIST AI RMF. |

---

## Quickstart

```bash
# 1. Run the fully-offline demo (no keys, no network)
python examples/run_demo.py
#    ...or, if installed:  pip install -e .  &&  aegis demo

# 2. Inspect the agent collective and the workflow order
aegis agents

# 3. See reproducible prompt variants for any text
aegis mutate "Explain how TLS certificate validation works." --count 8

# 4. Browse the built-in testing methodologies (web-app, Active Directory, AI red-team)
aegis methodology                       # list
aegis methodology webapp                # OWASP WSTG-aligned web/API methodology
aegis methodology active-directory      # MITRE ATT&CK-aligned AD methodology
aegis methodology ai-redteam            # OWASP LLM/ASI + ATLAS AI red-team methodology

# 5. Measure detection accuracy on offline ground-truth fixtures
aegis benchmark                         # precision / recall / F1 summary

# 6. Run a real engagement from a config (edit the authorization scope first!)
aegis run examples/authorized_targets.yaml --fail-on high
```

Run the tests:

```bash
pip install pytest
pytest -q            # 48 tests, fully offline
```

---

## The agent collective

Twenty-three specialized, collaborating agents over a shared blackboard state,
each with declared responsibilities, inputs/outputs, confidence estimation, and
stopping conditions.

```mermaid
flowchart LR
    subgraph PLAN
      ORCH([Orchestrator]) --> PLN[Planner] --> SCH[Task Scheduler]
    end
    subgraph MAP
      CAP[Capability Mapping] & BND[Boundary Mapping]
      WRC[Web Recon] & ASM[Attack-Surface Mapping]
    end
    subgraph EVALUATE
      PMU[Prompt Mutation] --> POP[Prompt Optimization] --> ADE[Adaptive Evaluation]
      CNV[Conversation] & LCX[Long-Context] & RAG[RAG Analysis]
    end
    subgraph ANALYZE
      IVR[Information Verification] --> VUL[Vulnerability Assessment]
      API[API Security] --> VUL
      VUL --> CVL[Controlled Validation] --> EVD[Evidence Collection] --> RSK[Risk Analysis]
    end
    subgraph REMEDIATE
      EXP[Explainability] & MIT[Mitigation Recommendation]
    end
    subgraph REPORT
      REP[Reporting] & DSH[Dashboard]
    end
    SCH --> MAP --> EVALUATE --> ANALYZE --> REMEDIATE --> REPORT
```

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for each agent's contract and
the full data-flow / interaction diagrams.

---

## What it assesses

**AI behavioural dimensions** (black-box, provider-agnostic): instruction
following, reasoning consistency, response stability, robustness to formatting,
long-context retention, confidence calibration, multilingual behaviour, structured
output, grounding, context management.

**Prompt mutation framework** — 20 semantics-preserving transforms probing parser
resilience and consistency: Unicode normalization, homoglyphs, mixed-script/
Cyrillic, bidi isolates, zero-width injection, nested documents, taxonomy/tables,
OCR-like noise, JSON/XML/YAML/Markdown re-serialization, academic/fictional
framing, instruction-hierarchy layering, ambiguity, multi-document reasoning,
persona/style changes, conversation restarts, long-context anchors, mixed
language. Deterministic and reproducible.

**RAG pipelines** — grounding rate, unsupported-citation detection, retrieval
quality, source attribution.

**Agentic / MCP surfaces** — dangerous tools callable without confirmation,
unauthenticated transports, excessive agency.

**Web / API surfaces** — unauthenticated AI/inference endpoints, missing rate
limits (unbounded consumption), unauthenticated state-changing endpoints, BOLA/
BFLA-prone patterns.

**Cross-domain correlation** — behavioural weaknesses on an *exposed* AI/agent
surface are automatically elevated.

---

## Testing methodologies

AEGIS ships a **machine-readable, framework-mapped methodology knowledge base**
([`aegis/methodology/`](aegis/methodology/)) covering the three domains it
assesses. Each technique documents the assessment objective **and** the detection
telemetry + mitigation that closes it — defensive by construction, no weaponized
recipes — and every technique carries an industry-framework mapping. Query it with
`aegis methodology`, and it is appended to every generated report (§11).

| Methodology | Aligned to | Doc | Code |
|-------------|-----------|-----|------|
| **Web Application & API Pentesting** | OWASP WSTG v4.2, OWASP Top 10, API Top 10, ASVS, PTES, ATT&CK | [METHODOLOGY_WEBAPP](docs/METHODOLOGY_WEBAPP.md) | [`methodology/webapp.py`](aegis/methodology/webapp.py) |
| **Active Directory Security Assessment** | MITRE ATT&CK, MS *Securing AD* / tiering, CISA, NIST 800-53 | [METHODOLOGY_ACTIVE_DIRECTORY](docs/METHODOLOGY_ACTIVE_DIRECTORY.md) | [`methodology/active_directory.py`](aegis/methodology/active_directory.py) |
| **AI / LLM / Agentic Red-Teaming** | OWASP LLM Top 10, OWASP Agentic (ASI), MITRE ATLAS, NIST AI RMF | [METHODOLOGY_AI_REDTEAM](docs/METHODOLOGY_AI_REDTEAM.md) | [`methodology/ai_redteam.py`](aegis/methodology/ai_redteam.py) |

The AI red-team methodology integrates the phased model from the
[AI Red-Teaming Guide](https://github.com/requie/AI-Red-Teaming-Guide) and the
engagement-pipeline shape from [redamon](https://github.com/samugit83/redamon),
re-expressed inside AEGIS's authorization-gated, safe-by-construction model.

---

## Controlled external-tool integration

AEGIS orchestrates external tooling (Nmap, Nuclei, httpx, ffuf, Semgrep, Trivy,
…) — but the language model never authors a command line. Every tool passes
through **one controlled, auditable choke point** with a standardized adapter
contract, so "AI + Kali tools" glue becomes safe by construction.

```bash
# inventory the registry (executable adapters vs documentation-only contracts)
aegis tools list

# preview intelligent test selection for an observed target (planning only)
aegis tools select --kind web_app --signals http,https,web,domain,graphql,jwt

# recursive, scope-bounded scan (dry-run by default; --live executes)
aegis tools scan engagement.yaml --target https://authorized.example --signals http,web,domain
```

**Recursive scanning** ([`RecursiveScanner`](aegis/tools/pipeline.py)) chains
tools so discoveries drive deeper scans (subdomains → live services → endpoints
→ deeper scans). It stays safe because **every derived target is re-checked
against the authorization scope before it can be scanned** (out-of-scope targets
are dropped and audited, never touched) and the whole scan is bounded by hard
depth / target / invocation budgets with cycle-proof dedup.

**Approval-gated validation** ([`Validator`](aegis/tools/validation.py)) turns a
lead into a confirmed finding *only when a controlled re-run produces evidence*.
Non-destructive re-observation runs through the same gates; anything needing an
exploitation/credential-class tool resolves to `MANUAL_REQUIRED` (a human,
explicitly authorized, implements a scoped adapter) — AEGIS never auto-exploits.
Even a `CONFIRMED` finding's severity stays provisional pending the risk engine
and human review.

The [`ToolExecutor`](aegis/tools/execution.py) enforces, for **every** run:
fail-closed **scope validation** (out-of-scope targets never spawn a process),
**no-shell** argv built from typed params, **dry-run by default**, **human
approval gates** for active/intrusive tools, offline-mode network blocking,
engagement-level `exploitation` / `credential_testing` switches (default off),
and an **immutable audit record** (`tool_runs`) for allowed, refused, and errored
attempts alike. Exploitation / credential / DoS tools are **documentation-only
contracts** — present for planning, never auto-runnable until a human implements
and authorizes a scoped adapter. See
[`docs/TOOL_INTEGRATION.md`](docs/TOOL_INTEGRATION.md) and
[`aegis/tools/`](aegis/tools/).

---

## Accuracy benchmark

How accurate is the detection engine? AEGIS ships an **offline accuracy
benchmark** ([`aegis/benchmark/`](aegis/benchmark/), `aegis benchmark`) that runs
the platform against self-contained fixtures with **known ground truth** and
reports precision / recall / F1 — the security-tool equivalent of a labelled test
set. Hardened *control* cases (which should yield nothing) make the precision
number meaningful, and honest **coverage gaps** (e.g. authenticated BOLA, which
needs live testing) are reported separately rather than hidden. Fully offline: no
network, keys, or external targets. See [docs/BENCHMARK.md](docs/BENCHMARK.md) and
the [latest result](docs/proof-of-concept/benchmark/BENCHMARK_REPORT.md).

---

## The adaptive evaluation loop

```
receive objectives → plan → generate probes → execute → collect → analyze
→ estimate confidence → find gaps → generate targeted follow-ups → refine
→ (repeat until coverage & confidence targets, or budget) → findings + mitigations
```

The loop grows its probe pool each round, re-analyses the full pool so sample
sizes (and thus confidence) rise, and biases follow-ups toward under-covered or
low-confidence dimensions — weighted by **historical priors** from memory. Scoring
of any individual probe is fixed, so adaptivity never compromises reproducibility.

---

## Project layout

```
aegis/
  core/          types · config · authorization gate · events · confidence · memory
  methodology/   framework-mapped web-app · Active Directory · AI red-team methodologies
  benchmark/     offline accuracy benchmark (ground-truth fixtures + scoring)
  mutation/      transform library + reproducible engine
  providers/     mock (offline) · OpenAI-compatible (Ollama/vLLM/gateways)
  targets/       LLM · RAG · Web/API · MCP target adapters
  evaluation/    metrics · behavioral/long-context/RAG analyzers · adaptive loop
  agents/        23 agents + rule-based adjudication
  graph/         shared state · orchestrator + phase state machine (LangGraph-optional)
  explainability/behavioral (always) · internals (TransformerLens/SHAP/Captum, optional)
  reporting/     framework mappings · report model · MD/HTML/JSON renderers
  observability/ structured logging · tracing (OpenTelemetry-optional)
  storage/       SQLite schema + persistence
  cli.py         run · demo · mutate · scope-check · agents · methodology · benchmark
docs/            architecture, workflow, MCP, database, deployment, deliverables,
                 methodology (web-app / Active Directory / AI red-team)
tests/           48 offline tests
examples/        authorized_targets.yaml · run_demo.py
```

---

## The 15 design deliverables

Every deliverable from the platform brief is implemented and documented — see the
index in **[`docs/DELIVERABLES.md`](docs/DELIVERABLES.md)**.

## Optional integrations

Install extras to light up richer backends (all optional, all graceful-fallback):

```bash
pip install -e ".[extras]"          # yaml config, jinja2, requests providers
pip install -e ".[graph]"           # LangGraph runtime
pip install -e ".[explain]"         # TransformerLens / SHAP / Captum / BertViz
pip install -e ".[observability]"   # OpenTelemetry / MLflow / Arize Phoenix
pip install -e ".[integrations]"    # Promptfoo / DeepEval / Inspect AI / Garak / ART / TextAttack
```

## License

MIT — see [LICENSE](LICENSE). Use only against systems you own or are explicitly
authorized to assess.
