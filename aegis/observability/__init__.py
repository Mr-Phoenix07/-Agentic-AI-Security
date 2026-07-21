"""Observability: structured logging + tracing (OpenTelemetry-optional)."""

from __future__ import annotations

from .logging import BoundLogger, get_logger
from .tracing import Tracer, default_tracer, span

__all__ = ["BoundLogger", "get_logger", "Tracer", "default_tracer", "span"]
