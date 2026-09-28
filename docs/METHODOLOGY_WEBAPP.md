# Web Application & API Penetration Testing Methodology

> **Authorized use only.** Every technique below is for applications you **own or
> are explicitly authorized to assess**. In AEGIS, active probing of a live web
> target is gated by the fail-closed authorization scope
> ([`aegis/core/authorization.py`](../aegis/core/authorization.py)); passive steps
> reason over the declared attack-surface inventory. This document is the
> human-readable companion to the machine-readable methodology in
> [`aegis/methodology/webapp.py`](../aegis/methodology/webapp.py) — run
> `aegis methodology webapp` to query it.

This methodology follows the **OWASP Web Security Testing Guide (WSTG) v4.2**
category structure and the **PTES** engagement lifecycle, mapping each step to
OWASP Top 10 (2021), the OWASP API Security Top 10 (2023), OWASP ASVS, and MITRE
ATT&CK Enterprise. Each technique pairs the **assessment objective** with the
**detection** telemetry and **mitigation** control that closes it, so a finding
is immediately actionable for both red and blue teams.

## Engagement lifecycle (PTES)

1. **Pre-engagement** — scope, rules of engagement, signed authorization, test
   windows, emergency contacts. Recorded as authorization-scope rules in AEGIS.
2. **Intelligence gathering** — passive recon and surface mapping (Phase 1).
3. **Threat modeling** — data flows, trust boundaries, abuse cases.
4. **Vulnerability analysis & exploitation** — Phases 2–5, executed only within
   scope, non-destructively, with active confirmation via controlled validation.
5. **Post-exploitation** — impact demonstration limited to what authorization allows.
6. **Reporting** — reproducible, standards-mapped findings + remediation (Phase 6).

## Phases & techniques

### Phase 1 — Reconnaissance & Information Gathering
Map the application surface, technologies, and entry points before any active test.

| ID | Technique | What it determines | Frameworks |
|----|-----------|--------------------|------------|
| `WSTG-INFO-01` | Passive surface & fingerprinting | Hosts, subdomains, tech stack, version/error disclosure | WSTG-INFO, ATT&CK T1595/T1592 |
| `WSTG-CONF-01` | Configuration & deployment review | TLS posture, security headers, CORS, cookie flags, default/admin exposure | WSTG-CONF, A05:2021, ASVS V14 |

**Key mitigations:** suppress version banners, remove debug endpoints, enforce
HSTS/CSP and strict CORS, set `Secure`/`HttpOnly`/`SameSite` on cookies.

### Phase 2 — Identity, Authentication & Session Management
Verify users are authenticated robustly and sessions cannot be hijacked or fixed.

| ID | Technique | What it determines | Frameworks |
|----|-----------|--------------------|------------|
| `WSTG-ATHN-01` | Authentication robustness | Brute-force/credential-stuffing resistance, username enumeration, MFA enforcement | A07:2021, ATT&CK T1110/T1078 |
| `WSTG-SESS-01` | Session management | Token entropy, fixation resistance, logout/idle invalidation, transport flags | A07:2021, ASVS V3 |

**Key mitigations:** rate-limit + progressive lockout, uniform auth errors,
rotate session id on login, server-side logout invalidation, short idle timeouts.

### Phase 3 — Authorization
Confirm access controls enforce least privilege across objects and functions.

| ID | Technique | What it determines | Frameworks |
|----|-----------|--------------------|------------|
| `WSTG-ATHZ-01` | Broken object/function level authorization (BOLA/BFLA, IDOR) | Horizontal/vertical privilege escalation | A01:2021, API1/API5:2023 |

**Key mitigations:** enforce per-object ownership server-side, deny-by-default
function authorization, use unpredictable identifiers.

### Phase 4 — Input Validation & Injection
Determine whether untrusted input can alter query, command, markup, or template semantics.

| ID | Technique | What it determines | Frameworks |
|----|-----------|--------------------|------------|
| `WSTG-INPV-05` | Injection (SQL/NoSQL/command/template) | Input crossing a code/data boundary | A03:2021, ATT&CK T1190 |
| `WSTG-INPV-01` | Cross-site scripting (reflected/stored/DOM) | Unencoded rendering into a browser context | A03:2021 |
| `WSTG-INPV-19` | Server-side request forgery (SSRF) | Coerced server-side requests (e.g., cloud metadata) | A10:2021, ATT&CK T1190 |

**Assessment posture:** use benign, non-destructive marker inputs to observe
differential behaviour; confirm only via the authorized controlled-validation
path. **Key mitigations:** parameterized queries, context-aware output encoding,
strict CSP, egress allow-lists + metadata blocking (IMDSv2).

### Phase 5 — Business Logic & API Security
Test workflow integrity and API-specific weaknesses beyond generic injection.

| ID | Technique | What it determines | Frameworks |
|----|-----------|--------------------|------------|
| `WSTG-BUSL-01` | Business-logic & workflow abuse | Replay/reorder/tamper, race conditions, limit bypass | WSTG-BUSL, API6:2023 |
| `API-RL-01` | Unrestricted resource consumption & rate limiting | Auth + rate/quota on costly/AI endpoints | API4/API2:2023, A04:2021 |

**Key mitigations:** server-side state/invariant checks, idempotency keys,
per-principal rate/cost limits, pagination and payload-size caps.

### Phase 6 — Analysis, Evidence & Reporting
Turn measured weaknesses into reproducible, standards-mapped findings.

| ID | Technique | What it determines | Frameworks |
|----|-----------|--------------------|------------|
| `RPT-01` | Evidence collection & standards mapping | Reproducibility, severity, framework alignment | PTES Reporting, ASVS V1 |

Severity is derived from measured impact × confidence; every finding is bound to
a **regression test** and re-tested after remediation.

## Mapping to AEGIS

- Web/API surfaces are modelled as declared inventory in
  [`aegis/targets/surface.py`](../aegis/targets/surface.py).
- Recon, attack-surface, and API-security agents in
  [`aegis/agents/`](../aegis/agents/) reason over that inventory.
- Findings map to frameworks via
  [`aegis/reporting/frameworks.py`](../aegis/reporting/frameworks.py) and appear
  in the generated report's **§6 Web / API / MCP Security Findings**.

## References

- OWASP Web Security Testing Guide v4.2
- OWASP Top 10:2021 · OWASP API Security Top 10:2023 · OWASP ASVS 4.0
- Penetration Testing Execution Standard (PTES)
- MITRE ATT&CK Enterprise
