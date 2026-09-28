"""Safe, authorized **active** HTTP reconnaissance.

This is the one place in AEGIS that touches a live target over the network. It
performs the *reconnaissance and configuration-review* phase of a real web
pentest — and nothing more:

    * Every request is authorized **first** against the fail-closed
      :class:`~aegis.core.authorization.AuthorizationScope`. An out-of-scope URL
      never leaves the process.
    * Only **GET / HEAD** are issued. No payloads, no parameter fuzzing, no
      authentication attempts, no brute force, no state-changing or destructive
      requests — this is non-intrusive by construction.
    * A hard request cap and an optional polite delay bound the traffic.
    * Sensitive-path checks only test *reachability* (status code); they never
      download, parse, or log secret contents.

The result is a set of real, evidence-backed :class:`~aegis.core.types.Finding`
objects (missing security headers, weak TLS enforcement, insecure cookies,
permissive CORS, banner/version disclosure, exposed VCS/dotfiles) mapped to the
same frameworks the rest of the platform uses. Active *exploitation* is
deliberately out of scope.

Pure standard library (``urllib``) so it adds no hard dependency.
"""

from __future__ import annotations

import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from http.cookies import SimpleCookie
from urllib.parse import urljoin, urlsplit

from ..core.authorization import AuthorizationError, AuthorizationScope
from ..core.types import Confidence, EvaluationMode, Finding, FindingCategory, Severity
from ..reporting.frameworks import frameworks_for, mitigations_for

# Security headers we expect on a hardened HTTP response.
_SECURITY_HEADERS = {
    "strict-transport-security": ("HSTS (Strict-Transport-Security)", Severity.MEDIUM),
    "content-security-policy": ("Content-Security-Policy", Severity.MEDIUM),
    "x-content-type-options": ("X-Content-Type-Options", Severity.LOW),
    "x-frame-options": ("X-Frame-Options / frame-ancestors", Severity.LOW),
    "referrer-policy": ("Referrer-Policy", Severity.LOW),
}

# Read-only sensitive paths whose *reachability* indicates exposure. Contents are
# never downloaded or logged — only the status code is inspected.
_SENSITIVE_PATHS = [
    ("/.git/HEAD", "Exposed Git metadata (.git)", Severity.HIGH),
    ("/.env", "Exposed environment file (.env)", Severity.HIGH),
    ("/.svn/entries", "Exposed SVN metadata (.svn)", Severity.MEDIUM),
    ("/server-status", "Exposed Apache server-status", Severity.MEDIUM),
    ("/.well-known/security.txt", "No security.txt (informational)", Severity.INFO),
]


@dataclass
class CheckResult:
    check: str
    status: str          # "pass" | "finding" | "info" | "error"
    detail: str = ""
    url: str = ""


@dataclass
class ProbeOutcome:
    target: str
    findings: list[Finding] = field(default_factory=list)
    checks: list[CheckResult] = field(default_factory=list)
    requests_made: int = 0
    denied: list[str] = field(default_factory=list)   # URLs refused by scope
    errors: list[str] = field(default_factory=list)


class SafeHTTPProbe:
    """Non-destructive, scope-gated active HTTP reconnaissance."""

    USER_AGENT = "AEGIS-SafeProbe/0.1 (+authorized-assessment)"

    def __init__(self, scope: AuthorizationScope | None, *, target_id: str = "web",
                 timeout: float = 8.0, max_requests: int = 20,
                 delay: float = 0.0) -> None:
        self.scope = scope
        self.target_id = target_id
        self.timeout = timeout
        self.max_requests = max_requests
        self.delay = delay
        self._count = 0

    # -- gated, non-destructive fetch -------------------------------------- #
    def _fetch(self, url: str, method: str = "GET"):
        """Authorize, then issue a single GET/HEAD. Returns (status, headers) or raises."""
        if method not in ("GET", "HEAD"):
            raise ValueError("SafeHTTPProbe only issues GET/HEAD requests")
        if self.scope is not None:
            # Fail-closed: refuse (and never send) an out-of-scope URL.
            try:
                self.scope.require_url(url)
            except AuthorizationError as e:
                raise _Refused(str(e)) from e
        if self._count >= self.max_requests:
            raise RuntimeError(f"request cap reached ({self.max_requests})")
        if self.delay and self._count:
            time.sleep(self.delay)
        self._count += 1

        req = urllib.request.Request(url, method=method,
                                     headers={"User-Agent": self.USER_AGENT})
        # Do not auto-follow redirects: we want to observe them (e.g. http->https).
        opener = urllib.request.build_opener(_NoRedirect())
        try:
            resp = opener.open(req, timeout=self.timeout)
            return resp.getcode(), _headers_dict(resp.headers), resp.geturl()
        except urllib.error.HTTPError as e:
            # An HTTP status (401/403/404/3xx) is a valid observation, not an error.
            return e.code, _headers_dict(e.headers), url

    # -- public: run the recon suite --------------------------------------- #
    def probe(self, base_url: str) -> ProbeOutcome:
        out = ProbeOutcome(target=base_url)
        base_url = base_url.rstrip("/") + "/"
        scheme = urlsplit(base_url).scheme.lower()

        # 1) Base response: security headers, banners, cookies, CORS.
        try:
            status, headers, _ = self._fetch(base_url, "GET")
            out.checks.append(CheckResult("reachability", "pass",
                                          f"HTTP {status}", base_url))
            self._check_security_headers(headers, base_url, out)
            self._check_banners(headers, base_url, out)
            self._check_cookies(headers, base_url, out)
            self._check_tls(scheme, headers, base_url, out)
        except _Refused as e:
            out.denied.append(str(e))
            out.checks.append(CheckResult("reachability", "error", str(e), base_url))
            return out
        except Exception as e:  # network/timeout — record and continue where possible
            out.errors.append(f"{type(e).__name__}: {e}")
            out.checks.append(CheckResult("reachability", "error",
                                          f"{type(e).__name__}: {e}", base_url))

        # 2) CORS reflection (send a foreign Origin; observe ACAO).
        self._check_cors(base_url, out)

        # 3) Exposed sensitive paths (reachability only).
        self._check_sensitive_paths(base_url, out)

        out.requests_made = self._count
        return out

    # -- individual checks -------------------------------------------------- #
    def _check_security_headers(self, headers, url, out):
        for key, (label, sev) in _SECURITY_HEADERS.items():
            if key not in headers:
                out.findings.append(self._finding(
                    f"Missing security header: {label}",
                    FindingCategory.API_SECURITY, sev,
                    f"Response from {url} does not set {label}.",
                    "Weakens defense-in-depth against clickjacking, MIME sniffing, "
                    "protocol downgrade, or injection.",
                    0.9, wstg="WSTG-CONF-07"))
                out.checks.append(CheckResult(f"header:{key}", "finding",
                                              "missing", url))
            else:
                out.checks.append(CheckResult(f"header:{key}", "pass", "present", url))

    def _check_banners(self, headers, url, out):
        for h in ("server", "x-powered-by", "x-aspnet-version"):
            if headers.get(h):
                out.findings.append(self._finding(
                    f"Version/banner disclosure: {h}",
                    FindingCategory.DATA_EXPOSURE, Severity.LOW,
                    f"{h}: {headers[h]!r} disclosed by {url}.",
                    "Reveals stack/version detail useful for targeting known CVEs.",
                    0.8, wstg="WSTG-INFO-02"))
                out.checks.append(CheckResult(f"banner:{h}", "finding",
                                              headers[h], url))

    def _check_cookies(self, headers, url, out):
        raw = headers.get("set-cookie")
        if not raw:
            return
        jar = SimpleCookie()
        try:
            jar.load(raw)
        except Exception:
            return
        for name in jar:
            low = raw.lower()
            missing = [flag for flag, present in (
                ("Secure", "secure" in low),
                ("HttpOnly", "httponly" in low),
                ("SameSite", "samesite" in low),
            ) if not present]
            if missing:
                out.findings.append(self._finding(
                    f"Insecure cookie flags on '{name}': missing {', '.join(missing)}",
                    FindingCategory.SESSION, Severity.MEDIUM,
                    f"Cookie '{name}' from {url} is missing {', '.join(missing)}.",
                    "Session cookies without Secure/HttpOnly/SameSite are exposed to "
                    "theft (XSS) or transport interception.",
                    0.85, wstg="WSTG-SESS-02"))
                out.checks.append(CheckResult(f"cookie:{name}", "finding",
                                              f"missing {','.join(missing)}", url))

    def _check_tls(self, scheme, headers, url, out):
        if scheme == "http":
            out.findings.append(self._finding(
                "Plaintext HTTP (no TLS)", FindingCategory.API_SECURITY,
                Severity.MEDIUM,
                f"{url} is served over plaintext HTTP.",
                "Traffic (including credentials/session tokens) can be intercepted "
                "or tampered with in transit.",
                0.9, wstg="WSTG-CONF-08"))
            out.checks.append(CheckResult("tls", "finding", "plaintext http", url))
        elif "strict-transport-security" in headers:
            out.checks.append(CheckResult("tls", "pass", "https + HSTS", url))

    def _check_cors(self, url, out):
        origin = "https://aegis-cors-probe.example"
        req = urllib.request.Request(url, method="GET", headers={
            "User-Agent": self.USER_AGENT, "Origin": origin})
        try:
            if self.scope is not None:
                try:
                    self.scope.require_url(url)
                except AuthorizationError as e:
                    out.denied.append(str(e))
                    return
            if self._count >= self.max_requests:
                return
            self._count += 1
            opener = urllib.request.build_opener(_NoRedirect())
            resp = opener.open(req, timeout=self.timeout)
            headers = _headers_dict(resp.headers)
        except urllib.error.HTTPError as e:
            headers = _headers_dict(e.headers)
        except Exception as e:
            out.errors.append(f"cors: {type(e).__name__}: {e}")
            return
        acao = headers.get("access-control-allow-origin", "")
        acac = headers.get("access-control-allow-credentials", "").lower()
        if acao == "*" and acac == "true":
            out.findings.append(self._finding(
                "Permissive CORS with credentials", FindingCategory.API_SECURITY,
                Severity.HIGH,
                f"{url} returns Access-Control-Allow-Origin: * with "
                "Allow-Credentials: true.",
                "Any origin can read authenticated responses (credential/data leak).",
                0.9, wstg="WSTG-CONF-07"))
            out.checks.append(CheckResult("cors", "finding", "ACAO:* + creds", url))
        elif acao in ("*", origin):
            out.checks.append(CheckResult("cors", "info",
                                          f"reflects origin ({acao})", url))
        else:
            out.checks.append(CheckResult("cors", "pass", acao or "not set", url))

    def _check_sensitive_paths(self, base_url, out):
        for path, label, sev in _SENSITIVE_PATHS:
            url = urljoin(base_url, path.lstrip("/"))
            try:
                status, _headers, _ = self._fetch(url, "GET")
            except _Refused as e:
                out.denied.append(str(e))
                continue
            except Exception as e:
                out.errors.append(f"{path}: {type(e).__name__}: {e}")
                continue
            reachable = status == 200
            is_security_txt = path.endswith("security.txt")
            if is_security_txt:
                # Informational: absence is the (minor) finding.
                if not reachable:
                    out.findings.append(self._finding(
                        "No security.txt published", FindingCategory.MONITORING,
                        Severity.INFO, f"{url} not found (HTTP {status}).",
                        "A security.txt eases coordinated vulnerability disclosure.",
                        0.6, wstg="WSTG-INFO-01"))
                out.checks.append(CheckResult(f"path:{path}",
                                              "info" if not reachable else "pass",
                                              f"HTTP {status}", url))
            elif reachable:
                out.findings.append(self._finding(
                    label, FindingCategory.DATA_EXPOSURE, sev,
                    f"{url} is reachable (HTTP 200) — sensitive resource exposed.",
                    "Exposed VCS metadata / config can leak source, secrets, or "
                    "internal structure.",
                    0.85, wstg="WSTG-CONF-04"))
                out.checks.append(CheckResult(f"path:{path}", "finding",
                                              "HTTP 200 (exposed)", url))
            else:
                out.checks.append(CheckResult(f"path:{path}", "pass",
                                              f"HTTP {status}", url))

    # -- finding builder ---------------------------------------------------- #
    def _finding(self, title, category, severity, root, impact, conf,
                 wstg: str | None = None) -> Finding:
        frameworks = dict(frameworks_for(category) or {})
        if wstg:
            frameworks = {**frameworks, "owasp_wstg": [wstg]}
        return Finding(
            title=title, category=category, severity=severity,
            mode=EvaluationMode.GREY_BOX,
            confidence=Confidence(conf, "active non-destructive HTTP recon", 1),
            target_id=self.target_id, summary=root, root_cause=root, impact=impact,
            frameworks=frameworks, mitigations=mitigations_for(category))


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
class _Refused(Exception):
    """Raised when the authorization scope refuses a URL."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None  # do not auto-follow; caller inspects the 3xx


def _headers_dict(headers) -> dict:
    """Lower-cased header map. ``Set-Cookie`` is joined (may repeat)."""
    out: dict[str, str] = {}
    if headers is None:
        return out
    try:
        items = headers.items()
    except Exception:
        return out
    for k, v in items:
        lk = k.lower()
        if lk in out:
            out[lk] += "; " + v
        else:
            out[lk] = v
    return out
