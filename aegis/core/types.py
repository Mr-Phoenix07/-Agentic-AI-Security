"""Core domain types shared across the AEGIS platform.

Everything here is pure standard-library (dataclasses + enums) so the core runs
offline with zero third-party dependencies. These types form the *lingua franca*
that agents, the evaluation loop, storage, and reporting all speak.

Design goals:
    * Reproducibility  — every object carries stable ids and timestamps.
    * Explainability    — findings and observations record *why*, not just *what*.
    * Evidence-first    — claims are backed by concrete, replayable evidence.
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


# --------------------------------------------------------------------------- #
# Enumerations
# --------------------------------------------------------------------------- #
class Severity(str, Enum):
    """CVSS-flavoured qualitative severity ladder."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]

    # Order by rank, not by string value. All four operators are defined
    # explicitly because ``str`` (our mixin) already provides lexical ones.
    def __lt__(self, other: Severity) -> bool:
        return self.rank < other.rank

    def __le__(self, other: Severity) -> bool:
        return self.rank <= other.rank

    def __gt__(self, other: Severity) -> bool:
        return self.rank > other.rank

    def __ge__(self, other: Severity) -> bool:
        return self.rank >= other.rank


class EvaluationMode(str, Enum):
    """Visibility available to the assessor. Findings must declare which was used."""

    BLACK_BOX = "black_box"   # only inputs/outputs
    GREY_BOX = "grey_box"     # partial internals: logs, configs, some metadata
    WHITE_BOX = "white_box"   # full internals: weights, activations, source


class TargetKind(str, Enum):
    LOCAL_LLM = "local_llm"
    API_LLM = "api_llm"
    RAG = "rag"
    MULTI_AGENT = "multi_agent"
    MCP = "mcp"
    COPILOT = "copilot"
    WEB_APP = "web_app"
    REST_API = "rest_api"
    GRAPHQL_API = "graphql_api"
    AI_GATEWAY = "ai_gateway"
    CLOUD_AI = "cloud_ai"
    HYBRID = "hybrid"


class FindingCategory(str, Enum):
    """High-level buckets used for correlation and framework mapping."""

    PROMPT_INJECTION = "prompt_injection"
    INSTRUCTION_HIERARCHY = "instruction_hierarchy"
    ROBUSTNESS = "robustness"
    HALLUCINATION = "hallucination"
    CONFIDENCE_CALIBRATION = "confidence_calibration"
    LONG_CONTEXT = "long_context"
    RAG_GROUNDING = "rag_grounding"
    RAG_RETRIEVAL = "rag_retrieval"
    TOOL_USE = "tool_use"
    AGENT_AUTONOMY = "agent_autonomy"
    MCP_EXPOSURE = "mcp_exposure"
    DATA_EXPOSURE = "data_exposure"
    AUTHN = "authentication"
    AUTHZ = "authorization"
    SESSION = "session_management"
    API_SECURITY = "api_security"
    INPUT_VALIDATION = "input_validation"
    MONITORING = "monitoring_auditability"
    CROSS_DOMAIN = "cross_domain"
    OTHER = "other"


class ProbeStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    ERRORED = "errored"
    SKIPPED = "skipped"          # e.g. blocked by authorization scope


class AgentStatus(str, Enum):
    IDLE = "idle"
    RUNNING = "running"
    WAITING = "waiting"
    DONE = "done"
    FAILED = "failed"


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def new_id(prefix: str = "obj") -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def now_ts() -> float:
    return time.time()


def stable_hash(*parts: Any) -> str:
    """Deterministic content hash — used to dedupe probes/evidence reproducibly."""
    h = hashlib.sha256()
    for p in parts:
        h.update(json.dumps(p, sort_keys=True, default=str).encode("utf-8"))
    return h.hexdigest()[:16]


def clamp01(x: float) -> float:
    return max(0.0, min(1.0, float(x)))


# --------------------------------------------------------------------------- #
# Confidence
# --------------------------------------------------------------------------- #
@dataclass
class Confidence:
    """A calibrated confidence score with a human-readable rationale.

    We keep confidence *first-class* rather than a bare float so that every
    agent must justify its certainty — a core explainability requirement.
    """

    value: float = 0.5                    # 0..1
    rationale: str = ""
    sample_size: int = 0                  # observations backing the estimate

    def __post_init__(self) -> None:
        self.value = clamp01(self.value)

    @property
    def band(self) -> str:
        v = self.value
        if v >= 0.85:
            return "high"
        if v >= 0.6:
            return "medium"
        if v >= 0.3:
            return "low"
        return "very_low"

    def to_dict(self) -> dict:
        return {"value": round(self.value, 4), "band": self.band,
                "rationale": self.rationale, "sample_size": self.sample_size}


# --------------------------------------------------------------------------- #
# Evidence & probes
# --------------------------------------------------------------------------- #
@dataclass
class Evidence:
    """A concrete, replayable artifact supporting an observation or finding."""

    id: str = field(default_factory=lambda: new_id("ev"))
    kind: str = "transcript"              # transcript|http|metric|activation|screenshot|log
    summary: str = ""
    payload: dict = field(default_factory=dict)   # request/response, values, etc.
    target_id: str | None = None
    probe_id: str | None = None
    created_at: float = field(default_factory=now_ts)
    # Reproducibility knobs — enough to replay the exact interaction.
    reproduction: dict = field(default_factory=dict)  # {seed, params, prompt_hash,...}

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Probe:
    """A single planned interaction with a target.

    A probe is the atom of assessment: a rendered prompt/request plus the
    provenance (which transforms were applied) needed to reproduce it.
    """

    id: str = field(default_factory=lambda: new_id("probe"))
    objective: str = ""                   # what capability/boundary this tests
    category: FindingCategory = FindingCategory.ROBUSTNESS
    mode: EvaluationMode = EvaluationMode.BLACK_BOX
    payload: dict = field(default_factory=dict)   # {"prompt": ..., "messages": ...}
    provenance: list[str] = field(default_factory=list)  # transform lineage
    seed_id: str | None = None         # id of the seed prompt this derived from
    expectation: dict = field(default_factory=dict)      # what a robust system does
    tags: list[str] = field(default_factory=list)

    @property
    def content_hash(self) -> str:
        return stable_hash(self.payload, self.category.value, self.mode.value)


@dataclass
class ProbeResult:
    """The outcome of executing a probe against a target."""

    id: str = field(default_factory=lambda: new_id("res"))
    probe_id: str = ""
    target_id: str = ""
    status: ProbeStatus = ProbeStatus.COMPLETED
    response: dict = field(default_factory=dict)   # raw provider response
    latency_ms: float = 0.0
    tokens: dict = field(default_factory=dict)     # {"prompt": n, "completion": n}
    error: str | None = None
    created_at: float = field(default_factory=now_ts)
    evidence: list[Evidence] = field(default_factory=list)

    @property
    def text(self) -> str:
        """Best-effort extraction of the model's textual output."""
        r = self.response or {}
        for key in ("text", "output", "content", "completion", "answer"):
            if isinstance(r.get(key), str):
                return r[key]
        # OpenAI-style
        try:
            return r["choices"][0]["message"]["content"]
        except Exception:
            try:
                return r["choices"][0]["text"]
            except Exception:
                return json.dumps(r) if r else ""


# --------------------------------------------------------------------------- #
# Observations & findings
# --------------------------------------------------------------------------- #
@dataclass
class Observation:
    """A measured behavioral characteristic (not necessarily a vulnerability).

    Observations feed the risk-analysis agent, which promotes some of them to
    findings. Keeping them distinct preserves the audit trail from raw signal
    to adjudicated risk.
    """

    id: str = field(default_factory=lambda: new_id("obs"))
    dimension: str = ""                   # e.g. "instruction_following"
    metric: str = ""                      # e.g. "override_rate"
    value: float = 0.0
    unit: str = "ratio"
    direction: str = "higher_is_better"   # or lower_is_better
    confidence: Confidence = field(default_factory=Confidence)
    evidence_ids: list[str] = field(default_factory=list)
    context: dict = field(default_factory=dict)
    created_at: float = field(default_factory=now_ts)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["confidence"] = self.confidence.to_dict()
        return d


@dataclass
class Finding:
    """An adjudicated security-relevant conclusion with mitigation guidance."""

    id: str = field(default_factory=lambda: new_id("find"))
    title: str = ""
    category: FindingCategory = FindingCategory.OTHER
    severity: Severity = Severity.INFO
    mode: EvaluationMode = EvaluationMode.BLACK_BOX
    confidence: Confidence = field(default_factory=Confidence)
    target_id: str | None = None
    summary: str = ""
    root_cause: str = ""
    impact: str = ""
    evidence_ids: list[str] = field(default_factory=list)
    observation_ids: list[str] = field(default_factory=list)
    # Framework references, filled by reporting.frameworks
    frameworks: dict = field(default_factory=dict)   # {"owasp_llm": ["LLM01"], ...}
    mitigations: list[str] = field(default_factory=list)
    regression_tests: list[str] = field(default_factory=list)
    created_at: float = field(default_factory=now_ts)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["category"] = self.category.value
        d["severity"] = self.severity.value
        d["mode"] = self.mode.value
        d["confidence"] = self.confidence.to_dict()
        return d
