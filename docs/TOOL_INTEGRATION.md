# Controlled Tool Integration Layer

> Deliverables addressed: **tool adapter architecture** (§4/§35.5), **tool
> registry format** (§35.12), **intelligent test selection** (§11), **tool
> sandbox / controlled execution** (§21), **AI safety controls** (§34).

AEGIS's agents orchestrate *external* security tooling — Nmap, Nuclei, httpx,
ffuf, Semgrep, Trivy, and so on. The danger with "AI + Kali tools" glue is that
a language model ends up choosing and running commands directly. AEGIS is built
the other way around: **every external tool passes through one controlled,
auditable choke point**, and the model never authors a command line.

Package: [`aegis/tools/`](../aegis/tools/)

```
aegis/tools/
├── spec.py        # the standardized adapter contract (metadata + typed params)
├── catalog.py     # built-in adapters (executable) + documentation-only contracts
├── registry.py    # the registry + intelligent, explainable test selection
└── execution.py   # the single controlled execution choke point
```

## The adapter contract (`ToolSpec`)

Every tool is described by a `ToolSpec` before AEGIS will touch it (spec §4):

| Field | Meaning |
|-------|---------|
| `name` / `binary` | logical name and the allow-listed executable |
| `category` | capability bucket (`recon`, `web_scan`, `network`, `static_analysis`, …) |
| `purpose` | one-line description |
| `risk_level` | `PASSIVE < SAFE < ACTIVE < INTRUSIVE < DANGEROUS` |
| `supported_targets` | which `TargetKind`s it applies to |
| `applies_when` | observed signals that make it applicable (`http`, `graphql`, `domain`, …) |
| `requires_network` | blocked in offline mode against non-local targets |
| `evidence_format` | `text` / `json` / `jsonl` / `xml` |
| `input_schema` | structured, documented parameters |
| `command_builder` | **structured params → argv `list[str]`** (no shell string) |
| `parser` | raw output → structured `ParsedObservation`s |

A tool is invoked with a **`ToolInvocation`** (`tool`, `target`, structured
`params`, attribution, reason) — never a free-form command. The `command_builder`
turns validated params into an argv token list; `build_argv_safe()` rejects a
pre-joined string so shell semantics can't sneak back in.

### Executable vs. documentation-only

`command_builder is None` marks a **documentation-only contract**: AEGIS knows
the tool exists and how it fits the plan, but **will refuse to auto-run it**.
This is how exploitation / credential / DoS class tools (`sqlmap`, `metasploit`,
`hydra`) are represented — present for *planning* ("an IDOR here could be
validated with X"), but requiring a human to implement and authorize a scoped
adapter. No offensive payloads live in the catalog.

## Intelligent test selection (`ToolRegistry.select`)

Given an observed `TargetProfile` (kind + signals) the registry returns a
`SelectionPlan` — the applicable tools **with a reason for each**, plus the
tools it *excluded* and why. Nothing is executed; this is planning.

```bash
aegis tools list
aegis tools select --kind web_app --signals http,https,web,domain,graphql,jwt
```

Example (a React + Node + GraphQL + JWT web target): `subfinder`, `httpx`,
`whatweb`, `nuclei`, `ffuf`, `gobuster` are selected as runnable; `sqlmap` /
`hydra` surface as **advisory** (documentation-only, not enabled).

## The controlled executor (`ToolExecutor`)

Nothing in AEGIS calls `subprocess` directly — it goes through the executor,
which enforces, in strict order, and records **an immutable audit record for
every attempt (allowed, refused, or errored)**:

1. **Known & executable** — registered tool with a `command_builder`; binary on
   the allow-list. Documentation-only tools are refused here.
2. **Scope validation (fail-closed)** — the target is routed through the
   engagement's `AuthorizationScope`. Out of scope ⇒ refused; **nothing spawns**.
3. **Offline policy** — network tools are refused against non-local targets when
   `offline=True`.
4. **Engagement class switches** — `DANGEROUS` tools require `exploitation=True`;
   credential tools require `credential_testing=True`; both default off.
5. **No shell** — argv is a validated `list[str]` run with `shell=False` and a
   minimal env. There is no interpolation and no model-authored command line.
6. **Approval gate** — anything at or above `ACTIVE` risk requires a human
   approval callback to return `True` (default: deny — fail-closed).
7. **Dry-run by default** — the executor resolves and validates everything and
   returns the argv it *would* run, executing nothing, unless a caller explicitly
   opts into real execution.
8. **Bounded execution** — wall-clock timeout, captured stdout/stderr, exit code.

```python
from aegis.tools import ToolRegistry, ToolExecutor, ToolInvocation
from aegis.core.authorization import AuthorizationScope, ScopeRule

scope = AuthorizationScope([ScopeRule(
    label="engagement-42", hosts=["*.authorized.example"],
    url_globs=["https://authorized.example/*"], authorization_ref="SoW-42")])

reg = ToolRegistry()
ex = ToolExecutor(scope, dry_run=True,                 # preview only
                  approval=lambda inv, spec, dec: True) # human-in-the-loop

res = ex.run(ToolInvocation(tool="nuclei",
                            target="https://authorized.example",
                            reason="signature scan of authorized surface"),
             reg.get("nuclei"))
# res.argv -> the exact command; res.dry_run == True; nothing executed.
# ex.audit_log[-1] -> the ToolRunRecord (scope decision, approval, outcome).
```

Even in real-execution mode with all approvals granted, an out-of-scope target
is refused **before any process is spawned**.

## Audit trail

Each `ToolRunRecord` is emitted on the message bus (`tool.run`) and can be
persisted append-only to the `tool_runs` table
([`aegis/storage/schema.sql`](../aegis/storage/schema.sql)) via
`Database.save_tool_run(...)`. The record captures the command, target, scope
decision, approval, risk level, dry-run flag, exit code, and outcome — satisfying
the "record every tool call" requirement of the AI safety controls (§34) and the
trust hierarchy *raw output → parsed observation → analysis → validated finding*.

## Recursive scanning ([`pipeline.py`](../aegis/tools/pipeline.py))

`RecursiveScanner` chains tools so discoveries drive deeper scans — subdomains →
live HTTP services → discovered endpoints → deeper scans — without hand-feeding
each step. It's a breadth-first loop over a `ToolRunner` (so every run still goes
through the controlled executor).

```bash
# dry-run: selects & validates what it would run at each hop, executes nothing
aegis tools scan engagement.yaml --target https://authorized.example --signals http,web,domain

# live: executes against explicitly authorized targets (tools must be installed)
aegis tools scan engagement.yaml --target https://authorized.example --live --approve-active
```

What keeps recursion safe rather than runaway:

- **Every derived target is scope-checked before it can enter the frontier**
  (`AuthorizationScope.allows_url`, a *non-mutating* check that doesn't consume
  rate budget). A subdomain or endpoint a tool surfaces but scope doesn't cover
  is **dropped and audited — never scanned**. Seeds are gated the same way.
- **Hard budgets** — `PipelineBudget(max_depth, max_targets, max_invocations,
  max_expansion_per_node)` — plus a visited-set that dedupes normalized targets,
  so a cycle can't loop. When a budget trips, the scan stops and records why.
- **Conservative expansion** — only a few well-understood observation kinds
  (`subdomain`, `open_port`, `http_service`, `path`) derive new *scan* targets;
  a `template_match` is a *finding candidate for validation*, not a new target.

`PipelineResult` records the targets scanned (with depth + provenance), the
parent→child edges, every dropped out-of-scope target, the invocation count, and
the stop reason.

## Approval-gated validation ([`validation.py`](../aegis/tools/validation.py))

An observation is a lead, not a confirmed vulnerability. `Validator` adjudicates
a lead into a `ValidationResult` **only when a controlled re-run produces
evidence**, honoring the trust hierarchy. Two strategies, and the boundary is the
point:

- **Non-destructive re-observation** (default) — re-run the same class of *safe*
  detection (`nuclei` by template id, `nmap` on the specific port, `httpx` on the
  URL) and confirm the signal reproduces. Still scope- and approval-gated;
  changes no state.
- **Intrusive validation** (`sqlmap`/`hydra`/`metasploit` class) — these are
  documentation-only contracts, so a lead needing one resolves to
  **`MANUAL_REQUIRED`** with proposed steps for a human (or `REFUSED` if the class
  isn't enabled). Never executed autonomously.

Outcomes: `CONFIRMED` (reproduced, with `Evidence`), `NOT_REPRODUCED`,
`INCONCLUSIVE` (e.g. ran in dry-run), `REFUSED` (scope/approval/policy), or
`MANUAL_REQUIRED`. A `CONFIRMED` result can be promoted with `Validator.to_finding`
— and even then **severity stays provisional**: the risk engine plus human review
set final severity, per the rule that a model alone never does.

```python
from aegis.tools import ToolRunner, Validator, ValidationRequest
v = Validator(ToolRunner(registry, executor))
result = v.validate(ValidationRequest(observation=obs))   # obs from a scan
# result.status -> CONFIRMED / NOT_REPRODUCED / INCONCLUSIVE / REFUSED / MANUAL_REQUIRED
```

## Adding a tool

Implement a `command_builder` (structured params → argv) and, optionally, a
`parser`, then register a `ToolSpec`. The orchestrator picks it up automatically
via `applies_when` / `supported_targets` — the executor's guarantees apply with
no further wiring. For an intrusive tool, ship it **documentation-only** (no
builder) until a human implements and authorizes the adapter for the engagement.
