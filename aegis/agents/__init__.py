"""The AEGIS agent collective.

Twenty-four specialized, collaborating agents (the core twenty-three plus the
opt-in :class:`ActiveReconAgent`). ``WORKFLOW_ORDER`` is the canonical
dependency-respecting execution sequence; each agent's ``should_run`` gates it
per target kind, so the same order serves LLM, RAG, web, API, and MCP
assessments — and, when explicitly enabled, safe live web reconnaissance.
"""

from __future__ import annotations

from .active_recon import ActiveReconAgent
from .analysis import (
    APISecurityAgent,
    ControlledValidationAgent,
    EvidenceCollectionAgent,
    InformationVerificationAgent,
    RAGAnalysisAgent,
    RiskAnalysisAgent,
    VulnerabilityAssessmentAgent,
)
from .base import BaseAgent
from .interaction import (
    AdaptiveEvaluationAgent,
    ConversationAgent,
    LongContextAgent,
    PromptMutationAgent,
    PromptOptimizationAgent,
)
from .mapping import (
    AttackSurfaceMappingAgent,
    BoundaryMappingAgent,
    CapabilityMappingAgent,
    WebReconAgent,
)
from .planning import Planner, TaskScheduler
from .reporting_agents import (
    DashboardAgent,
    ExplainabilityAgent,
    MitigationRecommendationAgent,
    ReportingAgent,
)

# Canonical, dependency-ordered pipeline (gated per target by should_run).
WORKFLOW_ORDER: list[type[BaseAgent]] = [
    Planner,
    TaskScheduler,
    CapabilityMappingAgent,
    BoundaryMappingAgent,
    WebReconAgent,
    AttackSurfaceMappingAgent,
    PromptMutationAgent,
    PromptOptimizationAgent,
    ConversationAgent,
    AdaptiveEvaluationAgent,
    LongContextAgent,
    RAGAnalysisAgent,
    InformationVerificationAgent,
    ActiveReconAgent,
    APISecurityAgent,
    VulnerabilityAssessmentAgent,
    ControlledValidationAgent,
    EvidenceCollectionAgent,
    RiskAnalysisAgent,
    ExplainabilityAgent,
    MitigationRecommendationAgent,
    ReportingAgent,
    DashboardAgent,
]

REGISTRY: dict[str, type[BaseAgent]] = {cls.name: cls for cls in WORKFLOW_ORDER}

__all__ = ["BaseAgent", "WORKFLOW_ORDER", "REGISTRY",
           *[cls.__name__ for cls in WORKFLOW_ORDER]]
