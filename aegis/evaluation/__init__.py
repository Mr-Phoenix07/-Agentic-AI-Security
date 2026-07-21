"""Evaluation engine: metrics, behavioral/long-context/RAG analyzers, and the
adaptive closed-loop evaluator."""

from __future__ import annotations

from .behavioral import DIMENSIONS, Analyzer, ProbePair, default_analyzers
from .longcontext import default_longcontext_analyzers
from .loop import (
    DIMENSION_TRANSFORMS,
    AdaptiveEvaluator,
    EvaluationReport,
    RoundLog,
)
from .rag import default_rag_analyzers

__all__ = [
    "DIMENSIONS", "Analyzer", "ProbePair", "default_analyzers",
    "default_longcontext_analyzers", "default_rag_analyzers",
    "AdaptiveEvaluator", "EvaluationReport", "RoundLog", "DIMENSION_TRANSFORMS",
]
