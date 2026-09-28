# Active Reconnaissance (authorized live probing)

Most of AEGIS reviews **declared inventory**. This module is the one place that
touches a **live target over the network** — for the safe reconnaissance and
configuration-review phase of a real web pentest, and nothing more.

- **Code:** [`aegis/active/http_probe.py`](../aegis/active/http_probe.py)
  (`SafeHTTPProbe`) · agent [`aegis/agents/active_recon.py`](../aegis/agents/active_recon.py)
- **CLI:** `aegis probe <url> --config <engagement.yaml>`
- **In an engagement:** set `active_probe: true` on a web target (see below).

## Safety model — non-destructive by construction

| Guarantee | How |
|-----------|-----|
| **Authorized first** | Every URL passes the fail-closed `AuthorizationScope` **before** any request is sent. Out-of-scope URLs are refused and recorded, never contacted. |
| **Read-only methods** | Only `GET` / `HEAD`. No `POST`/`PUT`/`DELETE`, no state-changing requests. |
| **No exploitation** | No injection payloads, no parameter fuzzing, no auth/brute-force attempts. |
| **Bounded traffic** | Hard request cap (`--max-requests`, default 20) and optional polite delay. |
| **No secret exfiltration** | Sensitive-path checks test *reachability* (status code) only — contents are never downloaded, parsed, or logged. |

> This is deliberately the recon/hardening half of a pentest. Active
> **exploitation** (confirming SQLi/XSS/RCE, bypassing auth, dumping data) is out
> of scope for AEGIS by design — it stays a defensible, authorization-gated tool.

## What it checks

| Check | Finding (category) | Framework |
|-------|--------------------|-----------|
| Missing security headers (HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy) | `api_security` | OWASP A05, WSTG-CONF-07 |
| Plaintext HTTP (no TLS) | `api_security` | WSTG-CONF-08 |
| Cookies missing Secure/HttpOnly/SameSite | `session_management` | WSTG-SESS-02 |
| Permissive CORS (`ACAO: *` + credentials) | `api_security` | WSTG-CONF-07 |
| Server / X-Powered-By version banner | `data_exposure` | WSTG-INFO-02 |
| Exposed `.git` / `.env` / `.svn` / `server-status` (reachability) | `data_exposure` | WSTG-CONF-04 |
| Missing `security.txt` | `monitoring_auditability` | WSTG-INFO-01 |

Findings flow into the normal candidate → validation → risk → report pipeline.

## CLI usage

```bash
# Preferred: authorization comes from an engagement config's fail-closed scope
aegis probe https://app.you-are-authorized-to-test.example --config engagement.yaml

# Or attest authorization inline (scopes just this host); refused without it
aegis probe https://your-lab.local --i-am-authorized "SoW-2026-014"

aegis probe https://your-lab.local --i-am-authorized "SoW-2026-014" --json
```

Exit code is non-zero if a High/Critical finding is reported (handy in CI).

## Enabling it inside `aegis run`

Add a web target with a real `endpoint` and opt in with `active_probe: true`.
It runs **only** when both are present and the scope authorizes the host — a
normal declared-inventory or mock engagement never sends live traffic.

```yaml
authorization:
  rules:
    - label: "authorized-web-lab"
      hosts: ["your-lab.local", "127.0.0.1"]
      url_globs: ["http://your-lab.local*", "http://127.0.0.1*"]
      authorization_ref: "SoW-2026-014 (signed)"

targets:
  - id: "web-app"
    kind: "web_app"
    provider: "mock"          # provider is unused by the passive HTTP probe
    endpoint: "http://your-lab.local:8080/"
    metadata:
      active_probe: true       # opt in to live, non-destructive recon
      max_probe_requests: 20
```

See [`examples/active_recon_engagement.yaml`](../examples/active_recon_engagement.yaml).

## Note on this cloud environment

Active probing reaches whatever the environment's network policy allows. From a
restricted cloud container it can reach `127.0.0.1` (a local lab) but not
arbitrary external hosts; run it from a machine that can reach your authorized
target.
