"""Tests for the safe, authorized active-recon HTTP probe.

Runs a real (local, self-owned) HTTP server on 127.0.0.1 and probes it — proving
the active path works end-to-end over the network — while asserting the
fail-closed authorization gate refuses anything out of scope.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from aegis.active import SafeHTTPProbe
from aegis.core.authorization import AuthorizationScope, ScopeRule, localhost_scope


class _VulnHandler(BaseHTTPRequestHandler):
    """Deliberately-misconfigured responses (missing headers, weak cookie, banner)."""

    server_version = "TestServer/9.9"      # banner disclosure
    sys_version = ""

    def log_message(self, *a):             # silence test output
        return

    def _send(self, code=200, extra=None):
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        # Insecure cookie: no Secure/HttpOnly/SameSite.
        self.send_header("Set-Cookie", "sid=abc123; Path=/")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(b"<html>ok</html>")

    def do_GET(self):
        if self.path.startswith("/.git/HEAD"):
            self._send(200)                # simulate exposed VCS metadata
        elif self.path.startswith("/.well-known/security.txt"):
            self.send_response(404)
            self.end_headers()
        elif self.path in ("/.env", "/.svn/entries", "/server-status"):
            self.send_response(404)
            self.end_headers()
        else:
            self._send(200)                # base page: no security headers

    do_HEAD = do_GET


@pytest.fixture()
def local_server():
    server = HTTPServer(("127.0.0.1", 0), _VulnHandler)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{port}/"
    finally:
        server.shutdown()
        server.server_close()


def _titles(outcome):
    return " | ".join(f.title for f in outcome.findings)


def test_probe_detects_misconfigurations_on_authorized_local_target(local_server):
    probe = SafeHTTPProbe(localhost_scope(), target_id="local-lab")
    out = probe.probe(local_server)

    assert out.requests_made > 0
    assert not out.denied
    titles = _titles(out).lower()
    # Missing security headers
    assert "content-security-policy" in titles
    assert "hsts" in titles or "strict-transport-security" in titles
    # Insecure cookie
    assert "insecure cookie" in titles
    # Banner disclosure
    assert "banner disclosure" in titles
    # Plaintext HTTP
    assert "plaintext http" in titles
    # Exposed .git
    assert ".git" in titles


def test_probe_findings_are_framework_mapped(local_server):
    out = SafeHTTPProbe(localhost_scope()).probe(local_server)
    assert out.findings
    for f in out.findings:
        assert f.frameworks, f"{f.title} must carry a framework mapping"
        assert f.target_id


def test_out_of_scope_target_is_refused_and_never_probed(local_server):
    # Scope authorizes only example.com — the local server is out of scope.
    scope = AuthorizationScope([ScopeRule(
        label="only-example", hosts=["example.com"],
        url_globs=["https://example.com*"], authorization_ref="test")])
    out = SafeHTTPProbe(scope).probe(local_server)
    assert out.findings == []
    assert out.denied, "an out-of-scope base URL must be recorded as denied"


def test_empty_scope_denies_everything(local_server):
    out = SafeHTTPProbe(AuthorizationScope([])).probe(local_server)
    assert out.findings == []
    assert out.denied


def test_probe_only_issues_get_or_head():
    probe = SafeHTTPProbe(localhost_scope())
    with pytest.raises(ValueError):
        probe._fetch("http://127.0.0.1/", method="POST")


def test_request_cap_is_enforced(local_server):
    probe = SafeHTTPProbe(localhost_scope(), max_requests=1)
    out = probe.probe(local_server)
    # The cap bounds total traffic; at most `max_requests` were issued.
    assert out.requests_made <= 1
