"""Authorized **active** reconnaissance.

Unlike the rest of AEGIS (which reviews *declared* inventory), this package
touches a live target over the network — but only for the safe, non-destructive
recon / configuration-review phase of a web pentest, and only after the
fail-closed authorization scope permits each URL. There is no exploitation here.
"""

from __future__ import annotations

from .http_probe import CheckResult, ProbeOutcome, SafeHTTPProbe

__all__ = ["SafeHTTPProbe", "ProbeOutcome", "CheckResult"]
