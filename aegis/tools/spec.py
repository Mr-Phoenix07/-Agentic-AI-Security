"""Tool adapter specification — the standardized interface every external
security tool is described by before AEGIS will touch it.

This module is *pure metadata + typed contracts*. It contains no execution
logic and no offensive payloads. It exists so that the orchestrator can reason
about tools abstractly (category, risk, applicable targets, evidence format)
and so that the controlled executor (:mod:`aegis.tools.execution`) has a single,
auditable contract to enforce.

Design principles
-----------------
* **Structured, not free-form.** A tool is invoked by handing it *validated,
  typed parameters*; a tool's ``command_builder`` turns those into an argv
  ``list[str]``. AEGIS never runs a model-authored shell string. If a tool has
  no ``command_builder`` it is a *documentation-only* registry entry describing
  the integration contract — it cannot be auto-executed.
* **Risk is first-class.** Every tool declares a :class:`RiskLevel`. Anything
  above :attr:`RiskLevel.PASSIVE` is gated behind explicit approval by the
  executor; intrusive/dangerous categories are intentionally left without an
  auto ``command_builder`` so a human must implement and authorize the adapter.
* **Fail-closed by default.** Absent metadata means "not applicable" / "not
  allowed", never "assume yes".
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

from ..core.types import TargetKind

if TYPE_CHECKING:  # avoids a runtime import cycle (execution imports spec)
    from .execution import ToolResult


class ToolCategory(str, Enum):
    """Capability bucket — mirrors how the spec organizes tooling by capability
    rather than by a flat vendor list."""

    RECON = "recon"                     # dns/subdomain/service discovery
    FINGERPRINT = "fingerprint"         # technology identification
    WEB_ENUM = "web_enumeration"        # content/endpoint/parameter discovery
    WEB_SCAN = "web_scan"               # template/signature web checks
    API_SCAN = "api_scan"               # api surface analysis
    NETWORK = "network"                 # port/service/protocol analysis
    STATIC_ANALYSIS = "static_analysis" # source/secret/dependency scanning
    CONTAINER = "container"             # image/IaC/cluster posture
    AI_REDTEAM = "ai_redteam"           # LLM/RAG/agent/MCP adversarial eval
    # --- gated categories: no auto command_builder is shipped for these ---
    EXPLOITATION = "exploitation"       # PoC/exploit validation
    CREDENTIAL = "credential"           # authentication strength testing
    DOS = "denial_of_service"           # availability testing


class RiskLevel(int, Enum):
    """How intrusive a tool is against the target.

    The executor uses this to decide whether human approval is mandatory.
    """

    PASSIVE = 0     # observes only; no packets sent to the target (e.g. OSINT, wayback)
    SAFE = 1        # active but read-only/non-mutating (banner grab, GET-based checks)
    ACTIVE = 2      # active enumeration that may generate noise (dir brute, fuzzing)
    INTRUSIVE = 3   # may alter state / trigger protections (auth checks, injections)
    DANGEROUS = 4   # exploitation / credential attacks / availability impact

    @property
    def requires_approval(self) -> bool:
        return self >= RiskLevel.ACTIVE

    @property
    def requires_credential_flag(self) -> bool:
        """Whether the engagement must explicitly enable this class of testing."""
        return self >= RiskLevel.INTRUSIVE


# A command_builder receives a validated ``ToolInvocation`` and returns argv.
# It must NEVER return a shell string and must NEVER interpolate untrusted input
# without escaping into a single argv element (params are passed as list items,
# so shell metacharacters are inert — there is no shell).
CommandBuilder = Callable[["ToolInvocation"], list[str]]

# A parser turns raw tool output into structured, provenance-tagged observations.
OutputParser = Callable[["ToolResult"], list["ParsedObservation"]]


@dataclass(frozen=True)
class ToolSpec:
    """The standardized adapter interface (spec §4).

    ``command_builder is None`` marks a *documentation-only* entry: AEGIS knows
    the tool exists and how it fits, but will refuse to execute it until a human
    implements and authorizes the adapter. This is how exploitation/credential
    tooling is represented — present in the registry for planning, but never
    auto-runnable.
    """

    name: str
    binary: str                                  # executable name; allow-listed by executor
    version_flag: str = "--version"
    category: ToolCategory = ToolCategory.RECON
    purpose: str = ""
    risk_level: RiskLevel = RiskLevel.SAFE
    supported_targets: tuple[TargetKind, ...] = ()
    # Which observed technologies/signals make this tool *applicable*.
    applies_when: tuple[str, ...] = ()           # free tags matched against fingerprint
    requires_network: bool = True                # blocked in offline mode unless local target
    evidence_format: str = "text"                # text|json|xml|jsonl
    default_timeout_s: int = 300
    # Structured input schema (documentation for operators & UIs).
    input_schema: dict[str, str] = field(default_factory=dict)
    command_builder: CommandBuilder | None = None
    parser: OutputParser | None = None
    references: tuple[str, ...] = ()             # links to tool docs
    notes: str = ""

    @property
    def executable(self) -> bool:
        """True only if AEGIS can actually build an argv for this tool."""
        return self.command_builder is not None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "binary": self.binary,
            "category": self.category.value,
            "purpose": self.purpose,
            "risk_level": self.risk_level.name.lower(),
            "risk_rank": int(self.risk_level),
            "requires_approval": self.risk_level.requires_approval,
            "supported_targets": [t.value for t in self.supported_targets],
            "applies_when": list(self.applies_when),
            "requires_network": self.requires_network,
            "evidence_format": self.evidence_format,
            "executable": self.executable,
            "input_schema": dict(self.input_schema),
            "references": list(self.references),
            "notes": self.notes,
        }


@dataclass
class ToolInvocation:
    """A validated request to run a tool against a single authorized target.

    The ``target`` is the raw destination (URL / host / model id) that the
    executor routes through the authorization scope *before* anything runs.
    ``params`` are structured, tool-specific options — never a raw command line.
    """

    tool: str                                    # ToolSpec.name
    target: str
    params: dict[str, Any] = field(default_factory=dict)
    engagement: str = ""
    requested_by: str = "orchestrator"           # agent/user attribution for audit
    reason: str = ""                             # why this test was selected

    def opt(self, key: str, default: Any = None) -> Any:
        return self.params.get(key, default)


@dataclass
class ParsedObservation:
    """A single structured signal extracted from a tool's raw output.

    Deliberately *below* the ``Finding`` layer: parsers report what a tool
    literally emitted (an open port, a matched template, a discovered path).
    Promotion to a validated finding happens later, with evidence, per the
    platform's trust hierarchy (raw output → observation → analysis → finding).
    """

    kind: str                                    # "open_port"|"tech"|"path"|"template_match"...
    value: str
    detail: dict[str, Any] = field(default_factory=dict)
    severity_hint: str = "info"                  # advisory only; risk engine decides
    raw_ref: str = ""                            # pointer into raw output (line/offset)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "value": self.value,
            "detail": dict(self.detail),
            "severity_hint": self.severity_hint,
            "raw_ref": self.raw_ref,
        }


def build_argv_safe(parts: Sequence[Any]) -> list[str]:
    """Coerce builder output into a clean argv, rejecting shell-string misuse.

    A ``command_builder`` must return a sequence of tokens. We stringify each
    token and forbid returning a single pre-joined command line (a common way
    to accidentally reintroduce shell semantics). Because we exec with a list
    and no shell, embedded metacharacters in a token are inert.
    """
    if isinstance(parts, (str, bytes)):
        raise ValueError(
            "command_builder must return a list of argv tokens, not a joined string"
        )
    argv = [str(p) for p in parts]
    if not argv:
        raise ValueError("command_builder produced an empty argv")
    return argv
