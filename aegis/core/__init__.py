"""Core domain layer: types, config, authorization, events, confidence, memory."""

from __future__ import annotations

from .authorization import AuthorizationError, AuthorizationScope, ScopeRule
from .confidence import agree, from_effect, wilson_lower_bound
from .config import Config, LoopConfig, TargetConfig, default_config
from .events import Message, MessageBus
from .types import (
    AgentStatus,
    Confidence,
    EvaluationMode,
    Evidence,
    Finding,
    FindingCategory,
    Observation,
    Probe,
    ProbeResult,
    ProbeStatus,
    Severity,
    TargetKind,
    new_id,
    now_ts,
    stable_hash,
)

__all__ = [
    "AuthorizationError", "AuthorizationScope", "ScopeRule",
    "Config", "LoopConfig", "TargetConfig", "default_config",
    "agree", "from_effect", "wilson_lower_bound",
    "Message", "MessageBus",
    "AgentStatus", "Confidence", "EvaluationMode", "Evidence", "Finding",
    "FindingCategory", "Observation", "Probe", "ProbeResult", "ProbeStatus",
    "Severity", "TargetKind", "new_id", "now_ts", "stable_hash",
]
