"""Offline benchmark fixtures with known ground truth.

Deliberately-(in)secure declared surfaces built on the mock provider. Each case
either plants specific weaknesses (``vulnerable``) or is hardened so nothing
should be reported (``hardened-control``) — the controls are what make the
false-positive / precision numbers meaningful.

Ground truth for the surface cases is *deterministic*: the API-security agent
raises a fixed candidate for each declared misconfiguration
(see ``aegis/agents/analysis.py``), so the expected findings below follow directly
from the declared inventory, not from chance.
"""

from __future__ import annotations

from ..core.types import FindingCategory as FC
from ..core.types import Severity as S
from .models import BenchmarkCase
from .models import ExpectedFinding as EF

# Category sets scored per case (bounds false-positive counting).
_SURFACE = {FC.AUTHZ, FC.API_SECURITY, FC.MCP_EXPOSURE}
_BEHAVIOURAL = {FC.ROBUSTNESS, FC.LONG_CONTEXT, FC.INSTRUCTION_HIERARCHY,
                FC.CONFIDENCE_CALIBRATION}


def default_suite() -> list[BenchmarkCase]:
    return [
        # --- Vulnerable: exposed AI/API surface ----------------------------- #
        BenchmarkCase(
            id="web-exposed-ai-api",
            description="REST API exposing an unauthenticated, unthrottled AI "
                        "endpoint plus an unauthenticated state-changing endpoint.",
            kind="vulnerable",
            graded_categories=_SURFACE,
            targets=[{
                "id": "vuln-api", "kind": "rest_api", "provider": "mock",
                "mode": "grey_box",
                "metadata": {"endpoints": [
                    {"path": "/v1/chat", "method": "POST", "auth_required": False,
                     "is_ai_endpoint": True, "rate_limited": False},
                    {"path": "/v1/admin/reindex", "method": "POST",
                     "auth_required": False, "rate_limited": True},
                    {"path": "/v1/health", "method": "GET", "auth_required": False,
                     "rate_limited": True},
                ]},
            }],
            expected=[
                EF("vuln-api", FC.AUTHZ, "Unauthenticated AI",
                   note="unauth AI inference endpoint"),
                EF("vuln-api", FC.API_SECURITY, "rate limiting",
                   note="AI endpoint without rate limiting"),
                EF("vuln-api", FC.AUTHZ, "state-changing",
                   note="unauth POST /v1/admin/reindex"),
            ],
        ),
        # --- Vulnerable: open MCP surface ----------------------------------- #
        BenchmarkCase(
            id="mcp-open-surface",
            description="MCP server on an unauthenticated transport exposing a "
                        "side-effecting tool that requires no confirmation.",
            kind="vulnerable",
            graded_categories=_SURFACE,
            targets=[{
                "id": "vuln-mcp", "kind": "mcp", "provider": "mock",
                "mode": "grey_box",
                "metadata": {
                    "transport": "http", "authenticated": False,
                    "resources": ["file://notes"],
                    "tools": [
                        {"name": "search_docs", "description": "read-only",
                         "dangerous": False},
                        {"name": "send_email", "description": "sends email",
                         "dangerous": True, "requires_confirmation": False},
                        {"name": "delete_record", "description": "deletes a row",
                         "dangerous": True, "requires_confirmation": True},
                    ],
                },
            }],
            expected=[
                EF("vuln-mcp", FC.MCP_EXPOSURE, "Unauthenticated MCP",
                   note="unauth transport"),
                EF("vuln-mcp", FC.MCP_EXPOSURE, "send_email",
                   note="dangerous tool without confirmation"),
                # delete_record requires confirmation -> must NOT be flagged.
            ],
        ),
        # --- Vulnerable: GraphQL with exposed AI endpoint ------------------- #
        BenchmarkCase(
            id="graphql-exposed-ai",
            description="GraphQL API exposing an unauthenticated AI resolver.",
            kind="vulnerable",
            graded_categories=_SURFACE,
            targets=[{
                "id": "vuln-graphql", "kind": "graphql_api", "provider": "mock",
                "mode": "grey_box",
                "metadata": {"endpoints": [
                    {"path": "/graphql", "method": "POST", "auth_required": False,
                     "is_ai_endpoint": True, "rate_limited": True},
                ]},
            }],
            expected=[
                EF("vuln-graphql", FC.AUTHZ, "Unauthenticated AI",
                   note="unauth AI resolver"),
            ],
        ),
        # --- Hardened control: web/API (expect nothing) --------------------- #
        BenchmarkCase(
            id="web-hardened-control",
            description="Fully-hardened REST API: every endpoint authenticated and "
                        "rate-limited. No surface finding should be reported.",
            kind="hardened-control",
            graded_categories=_SURFACE,
            targets=[{
                "id": "safe-api", "kind": "rest_api", "provider": "mock",
                "mode": "grey_box",
                "metadata": {"endpoints": [
                    {"path": "/v1/chat", "method": "POST", "auth_required": True,
                     "is_ai_endpoint": True, "rate_limited": True},
                    {"path": "/v1/admin/reindex", "method": "POST",
                     "auth_required": True, "rate_limited": True},
                    {"path": "/v1/health", "method": "GET", "auth_required": True,
                     "rate_limited": True},
                ]},
            }],
            expected=[],   # ground truth: clean
        ),
        # --- Hardened control: MCP (expect nothing) ------------------------- #
        BenchmarkCase(
            id="mcp-hardened-control",
            description="Hardened MCP server: authenticated transport, every "
                        "side-effecting tool requires confirmation. Clean.",
            kind="hardened-control",
            graded_categories=_SURFACE,
            targets=[{
                "id": "safe-mcp", "kind": "mcp", "provider": "mock",
                "mode": "grey_box",
                "metadata": {
                    "transport": "stdio", "authenticated": True,
                    "resources": ["db://readonly"],
                    "tools": [
                        {"name": "search_docs", "description": "read-only",
                         "dangerous": False},
                        {"name": "send_email", "description": "sends email",
                         "dangerous": True, "requires_confirmation": True},
                    ],
                },
            }],
            expected=[],   # ground truth: clean
        ),
        # --- Coverage gap: authenticated BOLA/IDOR (honest known limitation) - #
        # AEGIS reasons over *declared inventory*; detecting broken object-level
        # authorization on an authenticated endpoint requires live testing with two
        # principals (see docs/METHODOLOGY_WEBAPP.md WSTG-ATHZ-01). This case is
        # graded separately as a documented coverage gap, not folded into the
        # headline accuracy of implemented detections.
        BenchmarkCase(
            id="web-authenticated-bola-gap",
            description="Authenticated but BOLA/IDOR-prone endpoint. Not detectable "
                        "from declared inventory alone — documents a real coverage "
                        "gap requiring live two-principal testing.",
            kind="coverage-gap",
            graded_categories=_SURFACE,
            targets=[{
                "id": "bola-api", "kind": "rest_api", "provider": "mock",
                "mode": "grey_box",
                "metadata": {"endpoints": [
                    {"path": "/v1/orders/{id}", "method": "GET", "auth_required": True,
                     "rate_limited": True, "roles": ["user"],
                     "notes": "returns any order id without ownership check"},
                ]},
            }],
            expected=[
                EF("bola-api", FC.AUTHZ, "",
                   note="BOLA/IDOR on authenticated endpoint — requires live testing"),
            ],
        ),
        # --- Behavioural: brittle LLM (recall check on robustness) ---------- #
        BenchmarkCase(
            id="llm-brittle-behavioural",
            description="Low-quality mock LLM expected to exhibit at least one "
                        "robustness weakness under semantics-preserving re-encoding.",
            kind="vulnerable",
            graded_categories=_BEHAVIOURAL,
            min_severity=S.LOW,
            count_false_positives=False,   # ground truth is "at least one"; recall-only
            targets=[{
                "id": "brittle-llm", "kind": "local_llm", "provider": "mock",
                "model": "mock-weak-1", "mode": "grey_box",
                "params": {"quality": 0.35},
            }],
            expected=[
                EF("brittle-llm", FC.ROBUSTNESS, "",
                   note="brittleness surfaces as a robustness finding"),
            ],
        ),
    ]
