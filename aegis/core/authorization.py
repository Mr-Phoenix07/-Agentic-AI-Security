"""Authorization scope enforcement — the safety spine of AEGIS.

The platform's single most important constraint is: *operate only on systems the
operator owns or is explicitly authorized to assess.* This module turns that
constraint from a policy sentence into an **enforced runtime gate** that every
target interaction must pass through.

Model
-----
An :class:`AuthorizationScope` is an allow-list of rules. A rule authorizes a
set of hosts/URLs/model-ids, optionally time-boxed and rate-limited, and carries
an audit reference (engagement id, ticket, signed statement of work). Any probe
whose destination is not covered by an active rule is **refused** — it never
reaches a provider.

This is deliberately fail-closed: an empty scope authorizes nothing.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import re
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse


class AuthorizationError(PermissionError):
    """Raised when an interaction falls outside the authorized scope."""


@dataclass
class ScopeRule:
    """A single authorization grant.

    Attributes
    ----------
    label:      human name for the engagement / grant.
    hosts:      glob patterns matched against a target host (e.g. ``*.example.com``).
    url_globs:  glob patterns matched against full URLs.
    model_ids:  glob patterns matched against model identifiers (offline/API models).
    cidrs:      IP ranges authorized (for internal endpoints).
    not_before / not_after: optional UNIX-time window for the grant.
    max_requests: optional cap enforced by the guard (rate/volume ceiling).
    authorization_ref: audit pointer (SoW id, ticket, signed-consent hash).
    """

    label: str
    hosts: list[str] = field(default_factory=list)
    url_globs: list[str] = field(default_factory=list)
    model_ids: list[str] = field(default_factory=list)
    cidrs: list[str] = field(default_factory=list)
    not_before: float | None = None
    not_after: float | None = None
    max_requests: int | None = None
    authorization_ref: str = ""

    def active(self, at: float | None = None) -> bool:
        at = at if at is not None else time.time()
        if self.not_before is not None and at < self.not_before:
            return False
        if self.not_after is not None and at > self.not_after:
            return False
        return True

    def _host_ok(self, host: str) -> bool:
        host = (host or "").lower()
        if any(fnmatch.fnmatch(host, pat.lower()) for pat in self.hosts):
            return True
        if self.cidrs and host:
            try:
                ip = ipaddress.ip_address(host)
                if any(ip in ipaddress.ip_network(c, strict=False) for c in self.cidrs):
                    return True
            except ValueError:
                pass
        return False

    def matches_url(self, url: str) -> bool:
        if any(fnmatch.fnmatch(url, pat) for pat in self.url_globs):
            return True
        host = urlparse(url).hostname or ""
        return self._host_ok(host)

    def matches_model(self, model_id: str) -> bool:
        return any(fnmatch.fnmatch((model_id or "").lower(), pat.lower())
                   for pat in self.model_ids)


@dataclass
class ScopeDecision:
    allowed: bool
    reason: str
    rule_label: str | None = None


class AuthorizationScope:
    """Fail-closed allow-list guard.

    Usage::

        scope = AuthorizationScope.from_dict(cfg["authorization"])
        scope.require_url("https://api.internal.example.com/v1/chat")   # raises if denied
    """

    def __init__(self, rules: list[ScopeRule] | None = None,
                 dry_run: bool = False) -> None:
        self.rules: list[ScopeRule] = rules or []
        self.dry_run = dry_run
        self._request_counts: dict[str, int] = {}

    # -- construction ------------------------------------------------------- #
    @classmethod
    def from_dict(cls, data: dict) -> AuthorizationScope:
        rules = [ScopeRule(**r) for r in (data.get("rules") or [])]
        return cls(rules=rules, dry_run=bool(data.get("dry_run", False)))

    # -- evaluation --------------------------------------------------------- #
    def _record_and_check_rate(self, rule: ScopeRule) -> str | None:
        if rule.max_requests is None:
            return None
        n = self._request_counts.get(rule.label, 0) + 1
        self._request_counts[rule.label] = n
        if n > rule.max_requests:
            return f"rate/volume ceiling exceeded ({n} > {rule.max_requests})"
        return None

    def allows_url(self, url: str) -> bool:
        """Non-mutating scope test: does the URL fall within an active rule?

        Unlike :meth:`check_url`, this does **not** count against any rate/volume
        ceiling, so it is safe for *planning* decisions where no request is
        actually sent (e.g. deciding whether a discovered target may enter a
        recursive scan's frontier). Real sends must still go through
        :meth:`check_url` / :meth:`require_url`, which enforce the volume caps.
        """
        if not url:
            return False
        return any(r.active() and r.matches_url(url) for r in self.rules)

    def check_url(self, url: str) -> ScopeDecision:
        if not url:
            return ScopeDecision(False, "empty URL")
        for rule in self.rules:
            if not rule.active():
                continue
            if rule.matches_url(url):
                over = self._record_and_check_rate(rule)
                if over:
                    return ScopeDecision(False, over, rule.label)
                return ScopeDecision(True, f"authorized by '{rule.label}'"
                                     + (f" ({rule.authorization_ref})"
                                        if rule.authorization_ref else ""),
                                     rule.label)
        return ScopeDecision(False, f"'{url}' not covered by any active scope rule")

    def check_model(self, model_id: str) -> ScopeDecision:
        for rule in self.rules:
            if not rule.active():
                continue
            if rule.matches_model(model_id):
                over = self._record_and_check_rate(rule)
                if over:
                    return ScopeDecision(False, over, rule.label)
                return ScopeDecision(True, f"authorized by '{rule.label}'", rule.label)
        return ScopeDecision(
            False, f"model '{model_id}' not covered by any active scope rule")

    # -- enforcement (raising) --------------------------------------------- #
    def require_url(self, url: str) -> ScopeDecision:
        d = self.check_url(url)
        if not d.allowed and not self.dry_run:
            raise AuthorizationError(
                f"Refused: {d.reason}. Add an explicit scope rule for authorized "
                f"targets only.")
        return d

    def require_model(self, model_id: str) -> ScopeDecision:
        d = self.check_model(model_id)
        if not d.allowed and not self.dry_run:
            raise AuthorizationError(
                f"Refused: {d.reason}. Add an explicit scope rule for authorized "
                f"targets only.")
        return d

    # -- introspection ------------------------------------------------------ #
    @property
    def is_empty(self) -> bool:
        return not self.rules

    def summary(self) -> dict:
        return {
            "rules": [
                {
                    "label": r.label,
                    "hosts": r.hosts,
                    "url_globs": r.url_globs,
                    "model_ids": r.model_ids,
                    "cidrs": r.cidrs,
                    "authorization_ref": r.authorization_ref,
                    "active": r.active(),
                    "max_requests": r.max_requests,
                }
                for r in self.rules
            ],
            "dry_run": self.dry_run,
            "request_counts": dict(self._request_counts),
        }


_LOCALHOST = re.compile(r"^(localhost|127\.0\.0\.1|::1|0\.0\.0\.0)$", re.I)


def localhost_scope(label: str = "local-lab") -> AuthorizationScope:
    """Convenience scope for self-owned localhost labs and the offline mock."""
    return AuthorizationScope([
        ScopeRule(
            label=label,
            hosts=["localhost", "127.0.0.1", "::1"],
            url_globs=["mock://*", "http://localhost*", "http://127.0.0.1*"],
            model_ids=["mock-*", "local/*"],
            authorization_ref="self-owned local lab",
        )
    ])
