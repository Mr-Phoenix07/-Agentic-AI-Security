"""Web Application & API penetration-testing methodology.

Structured after the **OWASP Web Security Testing Guide (WSTG) v4.2** test
categories and the **PTES** engagement lifecycle, mapped to OWASP Top 10 (2021),
OWASP API Security Top 10 (2023), OWASP ASVS, and MITRE ATT&CK Enterprise where
a technique corresponds to an adversary behaviour.

Every technique is expressed at the methodology altitude — objective, authorized
assessment approach, weakness signals, detection guidance, and mitigation — so it
drives both offensive coverage on an *authorized* engagement and defensive
hardening. It contains no weaponized payloads; active checks are executed only by
the controlled-validation agent within the fail-closed authorization scope.
"""

from __future__ import annotations

from ..core.types import FindingCategory as FC
from ..core.types import Severity as S
from .models import Methodology, Phase, Technique

_REFERENCES = {
    "owasp_wstg": "OWASP Web Security Testing Guide v4.2",
    "owasp_top10": "OWASP Top 10:2021",
    "owasp_api": "OWASP API Security Top 10:2023",
    "owasp_asvs": "OWASP Application Security Verification Standard 4.0",
    "mitre_attack": "MITRE ATT&CK Enterprise",
    "ptes": "Penetration Testing Execution Standard",
}


WEBAPP = Methodology(
    id="webapp",
    title="Web Application & API Penetration Testing",
    domain="web_app",
    summary=(
        "A phased, OWASP-WSTG-aligned methodology for assessing the security of "
        "web applications and their APIs on authorized engagements — from passive "
        "reconnaissance through input-validation, authentication/authorization, "
        "session, business-logic and API testing, each step paired with the "
        "detection and mitigation guidance a defender needs."
    ),
    authorization_note=(
        "Run only against applications you own or are explicitly authorized to "
        "assess. In AEGIS, active probing of a live web target is gated by the "
        "fail-closed authorization scope (aegis/core/authorization.py); passive "
        "steps reason over the declared attack-surface inventory."
    ),
    references=_REFERENCES,
    phases=[
        Phase(
            id="recon",
            name="Reconnaissance & Information Gathering",
            goal="Map the application surface, technologies, and entry points before any active test.",
            techniques=[
                Technique(
                    id="WSTG-INFO-01",
                    name="Passive surface & fingerprinting",
                    objective="Enumerate hosts, subdomains, technologies, and framework/version disclosure without touching sensitive functionality.",
                    approach="Review declared endpoints/OpenAPI/GraphQL schema; correlate response headers, error pages, and public metadata to fingerprint the stack.",
                    signals=["Verbose Server/X-Powered-By headers", "Framework debug/stack traces", "Exposed .git, backup, or swagger endpoints"],
                    detection=["Alert on scanning bursts and 404 walks", "Monitor for enumeration of well-known paths"],
                    mitigations=["Suppress version banners", "Remove debug endpoints from production", "Serve generic error pages"],
                    frameworks={"owasp_wstg": ["WSTG-INFO-02", "WSTG-INFO-08"], "mitre_attack": ["T1595 Active Scanning", "T1592 Gather Victim Host Information"]},
                    category=FC.DATA_EXPOSURE,
                    severity_hint=S.LOW,
                    tags=["recon", "passive"],
                ),
                Technique(
                    id="WSTG-CONF-01",
                    name="Configuration & deployment review",
                    objective="Identify insecure platform/config: default files, exposed admin, TLS posture, security headers, CORS.",
                    approach="Inspect TLS configuration, HTTP security headers (HSTS, CSP, X-Content-Type-Options), CORS policy, and cookie flags against ASVS baselines.",
                    signals=["Missing HSTS/CSP", "Permissive CORS (Access-Control-Allow-Origin: *) with credentials", "Cookies without Secure/HttpOnly/SameSite"],
                    detection=["Continuous header/TLS posture monitoring", "Config drift detection in CI"],
                    mitigations=["Enforce security headers at the edge", "Restrict CORS to explicit origins", "Set Secure/HttpOnly/SameSite on cookies"],
                    frameworks={"owasp_wstg": ["WSTG-CONF-07", "WSTG-CONF-08"], "owasp_top10": ["A05:2021 Security Misconfiguration"], "owasp_asvs": ["V14 Configuration"]},
                    category=FC.API_SECURITY,
                    severity_hint=S.MEDIUM,
                    tags=["config", "headers", "tls"],
                ),
            ],
        ),
        Phase(
            id="identity",
            name="Identity, Authentication & Session Management",
            goal="Verify that users are authenticated robustly and sessions cannot be hijacked or fixed.",
            techniques=[
                Technique(
                    id="WSTG-ATHN-01",
                    name="Authentication robustness",
                    objective="Assess resistance to credential stuffing, brute force, weak password policy, and username enumeration.",
                    approach="Measure lockout/rate-limit behaviour, response-timing/message differences between valid and invalid users, and MFA enforcement — using benign, authorized test accounts.",
                    signals=["No lockout or rate limiting on login", "Distinct error for valid vs invalid usernames", "MFA bypassable via alternate flow"],
                    detection=["Alert on failed-login spikes per account/IP", "Detect impossible-travel and credential-stuffing patterns"],
                    mitigations=["Rate-limit and progressive lockout", "Uniform authentication error messages", "Enforce MFA and strong password policy"],
                    frameworks={"owasp_wstg": ["WSTG-ATHN-03", "WSTG-IDNT-04"], "owasp_top10": ["A07:2021 Identification and Authentication Failures"], "mitre_attack": ["T1110 Brute Force", "T1078 Valid Accounts"]},
                    category=FC.AUTHN,
                    severity_hint=S.HIGH,
                    tags=["auth", "mfa"],
                ),
                Technique(
                    id="WSTG-SESS-01",
                    name="Session management",
                    objective="Verify session tokens are unpredictable, rotated on privilege change, invalidated on logout, and protected in transit.",
                    approach="Analyze token entropy/scope, fixation resistance (rotation on login), logout/idle-timeout invalidation, and cookie transport flags.",
                    signals=["Session id not rotated after login (fixation)", "Token valid after logout", "Predictable/short session identifiers"],
                    detection=["Track concurrent sessions per principal", "Alert on session reuse from new geo/device"],
                    mitigations=["Rotate session id on authentication", "Server-side session invalidation on logout", "Short idle timeouts, high-entropy tokens"],
                    frameworks={"owasp_wstg": ["WSTG-SESS-02", "WSTG-SESS-03"], "owasp_top10": ["A07:2021"], "owasp_asvs": ["V3 Session Management"]},
                    category=FC.SESSION,
                    severity_hint=S.HIGH,
                    tags=["session"],
                ),
            ],
        ),
        Phase(
            id="authorization",
            name="Authorization",
            goal="Confirm access controls enforce least privilege across objects and functions.",
            techniques=[
                Technique(
                    id="WSTG-ATHZ-01",
                    name="Broken object/function level authorization (BOLA/BFLA)",
                    objective="Detect horizontal and vertical privilege escalation: accessing other users' objects or admin functions.",
                    approach="With two authorized low-privilege test principals, verify that object identifiers and privileged functions are enforced server-side, not by client-side controls.",
                    signals=["Object accessible by changing an id (IDOR)", "Admin function reachable by a normal user", "Authorization decided client-side"],
                    detection=["Log and alert on cross-tenant object access", "Monitor privileged-endpoint calls by role"],
                    mitigations=["Enforce per-object ownership checks server-side", "Deny-by-default function authorization", "Use unpredictable, non-sequential identifiers"],
                    frameworks={"owasp_wstg": ["WSTG-ATHZ-04"], "owasp_api": ["API1:2023 BOLA", "API5:2023 BFLA"], "owasp_top10": ["A01:2021 Broken Access Control"]},
                    category=FC.AUTHZ,
                    severity_hint=S.CRITICAL,
                    tags=["idor", "bola", "bfla", "access-control"],
                ),
            ],
        ),
        Phase(
            id="input",
            name="Input Validation & Injection",
            goal="Determine whether untrusted input can alter query, command, markup, or template semantics.",
            techniques=[
                Technique(
                    id="WSTG-INPV-05",
                    name="Injection (SQL/NoSQL/command/template)",
                    objective="Assess whether user input crosses a code/data boundary in queries, OS commands, or template engines.",
                    approach="Send benign, non-destructive marker inputs to observe differential responses and error behaviour; confirm findings only via the authorized controlled-validation path — never destructive payloads.",
                    signals=["Database/SQL errors reflected to the client", "Differential timing on boolean conditions", "Template/expression evaluation of input"],
                    detection=["WAF/RASP alerts on injection patterns", "Log query errors and anomalous query shapes"],
                    mitigations=["Parameterized queries / prepared statements", "Context-aware output handling", "Least-privilege DB accounts; disable dangerous template features"],
                    frameworks={"owasp_wstg": ["WSTG-INPV-05", "WSTG-INPV-12"], "owasp_top10": ["A03:2021 Injection"], "mitre_attack": ["T1190 Exploit Public-Facing Application"]},
                    category=FC.INPUT_VALIDATION,
                    severity_hint=S.CRITICAL,
                    tags=["sqli", "injection", "ssti", "rce"],
                ),
                Technique(
                    id="WSTG-INPV-01",
                    name="Cross-site scripting (reflected/stored/DOM)",
                    objective="Assess whether input is rendered into a browser context without correct encoding, enabling script execution.",
                    approach="Inject benign, non-persistent markers into reflected and DOM sinks under authorization; review CSP and output-encoding of each sink.",
                    signals=["Input reflected unencoded into HTML/JS/attribute context", "DOM sink writes location/innerHTML from input", "No or weak CSP"],
                    detection=["CSP violation reporting", "Alert on script-like input in stored fields"],
                    mitigations=["Context-aware output encoding", "Strict CSP with nonces", "Sanitize/allow-list rich input; framework auto-escaping"],
                    frameworks={"owasp_wstg": ["WSTG-INPV-01", "WSTG-CLNT-01"], "owasp_top10": ["A03:2021 Injection"]},
                    category=FC.INPUT_VALIDATION,
                    severity_hint=S.HIGH,
                    tags=["xss", "client-side"],
                ),
                Technique(
                    id="WSTG-INPV-19",
                    name="Server-side request forgery (SSRF)",
                    objective="Determine whether the server can be coerced into making attacker-controlled requests (e.g., to cloud metadata or internal services).",
                    approach="Review URL/host-taking parameters and their egress controls; validate only against authorized, non-production endpoints.",
                    signals=["Server fetches arbitrary user-supplied URLs", "Access to link-local metadata (169.254.169.254)", "No egress allow-list"],
                    detection=["Egress monitoring for internal/metadata destinations", "Alert on outbound requests from app tier to RFC1918/link-local"],
                    mitigations=["Egress allow-list and metadata endpoint blocking", "Validate/resolve and pin destinations", "Use IMDSv2 / hop-limit on cloud metadata"],
                    frameworks={"owasp_wstg": ["WSTG-INPV-19"], "owasp_top10": ["A10:2021 SSRF"], "mitre_attack": ["T1190"]},
                    category=FC.INPUT_VALIDATION,
                    severity_hint=S.HIGH,
                    tags=["ssrf", "cloud"],
                ),
            ],
        ),
        Phase(
            id="logic-api",
            name="Business Logic & API Security",
            goal="Test workflow integrity and API-specific weaknesses beyond generic injection.",
            techniques=[
                Technique(
                    id="WSTG-BUSL-01",
                    name="Business-logic & workflow abuse",
                    objective="Identify flows that can be replayed, reordered, or manipulated (price/quantity tampering, race conditions, insufficient limits).",
                    approach="Model the intended state machine and test for skipped/duplicated steps and value tampering with authorized accounts.",
                    signals=["State transitions enforceable client-side only", "Race conditions on limited resources", "Negative/overflow quantities accepted"],
                    detection=["Anomaly detection on transaction sequences", "Idempotency and rate monitoring"],
                    mitigations=["Server-side state and invariant checks", "Idempotency keys and atomic operations", "Enforce business limits server-side"],
                    frameworks={"owasp_wstg": ["WSTG-BUSL-01", "WSTG-BUSL-07"], "owasp_api": ["API6:2023 Unrestricted Access to Sensitive Business Flows"]},
                    category=FC.API_SECURITY,
                    severity_hint=S.HIGH,
                    tags=["logic", "race"],
                ),
                Technique(
                    id="API-RL-01",
                    name="Unrestricted resource consumption & rate limiting",
                    objective="Determine whether expensive or state-changing endpoints (including AI/inference) enforce authentication and rate/quota limits.",
                    approach="Review declared endpoints for auth requirement and rate-limit metadata; measure quota enforcement on authorized test traffic.",
                    signals=["Unauthenticated AI/inference endpoint", "No rate limit on costly operation", "Unbounded pagination/expansion"],
                    detection=["Per-principal quota and cost monitoring", "Alert on volume/cost spikes"],
                    mitigations=["Authentication + per-principal rate/cost limits", "Pagination caps and payload-size limits", "Circuit breakers on expensive paths"],
                    frameworks={"owasp_api": ["API4:2023 Unrestricted Resource Consumption", "API2:2023 Broken Authentication"], "owasp_top10": ["A04:2021 Insecure Design"]},
                    category=FC.API_SECURITY,
                    severity_hint=S.MEDIUM,
                    tags=["api", "rate-limit", "ai-endpoint"],
                ),
            ],
        ),
        Phase(
            id="report",
            name="Analysis, Evidence & Reporting",
            goal="Turn measured weaknesses into reproducible, standards-mapped findings with remediation.",
            techniques=[
                Technique(
                    id="RPT-01",
                    name="Evidence collection & standards mapping",
                    objective="Record reproducible evidence for each finding and map it to OWASP/ASVS/ATT&CK with severity and confidence.",
                    approach="Capture request/response transcripts and reproduction metadata; derive severity from measured impact × confidence, and attach mitigation + regression tests.",
                    signals=["Findings lacking reproduction steps", "Unmapped or unrated findings"],
                    detection=["N/A (reporting discipline)"],
                    mitigations=["Track each finding to a regression test", "Re-test after remediation to confirm closure"],
                    frameworks={"ptes": ["Reporting"], "owasp_asvs": ["V1 Architecture, Design and Threat Modeling"]},
                    category=FC.MONITORING,
                    severity_hint=S.INFO,
                    tags=["reporting", "evidence"],
                ),
            ],
        ),
    ],
)
