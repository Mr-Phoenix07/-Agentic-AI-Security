"""Web / API / MCP surface targets.

These represent *authorized* application surfaces. Rather than an active exploit
engine, AEGIS models each surface as a declared, machine-readable inventory
(endpoints, auth requirements, AI/inference endpoints, MCP tools/resources,
integrations). The recon, attack-surface, API-security, and MCP agents reason
over this inventory — a configuration/behavioural review that is safe by
construction — and the controlled-validation agent performs only the narrow,
authorized active checks that a finding requires.

Populating the inventory can be automated (crawl an OpenAPI/GraphQL schema, read
an MCP ``tools/list`` response) or supplied from an engagement's scoping doc.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..core.types import TargetKind
from .base import Target


@dataclass
class Endpoint:
    path: str
    method: str = "GET"
    auth_required: bool = True
    roles: list[str] = field(default_factory=list)
    is_ai_endpoint: bool = False
    rate_limited: bool = True
    input_schema: dict = field(default_factory=dict)
    notes: str = ""


@dataclass
class MCPTool:
    name: str
    description: str = ""
    dangerous: bool = False            # performs side effects / external calls
    requires_confirmation: bool = False
    scopes: list[str] = field(default_factory=list)


@dataclass
class WebTarget(Target):
    endpoints: list[Endpoint] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.kind not in (TargetKind.WEB_APP, TargetKind.REST_API,
                             TargetKind.GRAPHQL_API, TargetKind.AI_GATEWAY):
            self.kind = TargetKind.WEB_APP

    def attack_surface(self) -> dict:
        return {
            "endpoints": [e.__dict__ for e in self.endpoints],
            "ai_endpoints": [e.__dict__ for e in self.endpoints if e.is_ai_endpoint],
            "unauthenticated": [e.__dict__ for e in self.endpoints
                                if not e.auth_required],
        }


@dataclass
class MCPTarget(Target):
    tools: list[MCPTool] = field(default_factory=list)
    resources: list[str] = field(default_factory=list)
    transport: str = "stdio"           # stdio|http|sse
    authenticated: bool = True

    def __post_init__(self) -> None:
        self.kind = TargetKind.MCP

    def attack_surface(self) -> dict:
        return {
            "transport": self.transport,
            "authenticated": self.authenticated,
            "tools": [t.__dict__ for t in self.tools],
            "dangerous_tools": [t.__dict__ for t in self.tools if t.dangerous],
            "unconfirmed_dangerous_tools": [
                t.__dict__ for t in self.tools
                if t.dangerous and not t.requires_confirmation
            ],
            "resources": self.resources,
        }
