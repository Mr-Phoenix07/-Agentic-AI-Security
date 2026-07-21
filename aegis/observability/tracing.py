"""Tracing / spans with OpenTelemetry when available, no-op otherwise.

Agents wrap their work in :func:`span` so an assessment produces a trace tree
(orchestrator → agent → probe). If ``opentelemetry`` is installed the spans are
real OTel spans (export to Jaeger/Tempo/Arize Phoenix); otherwise a lightweight
in-memory span recorder is used so the timeline is still queryable offline.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field

try:  # optional
    from opentelemetry import trace as _otel  # type: ignore

    _HAVE_OTEL = True
except Exception:  # pragma: no cover
    _HAVE_OTEL = False


@dataclass
class SpanRecord:
    name: str
    start: float
    end: float | None = None
    attributes: dict = field(default_factory=dict)
    children: list[SpanRecord] = field(default_factory=list)

    @property
    def duration_ms(self) -> float:
        return round(((self.end or time.perf_counter()) - self.start) * 1000, 3)

    def to_dict(self) -> dict:
        return {"name": self.name, "duration_ms": self.duration_ms,
                "attributes": self.attributes,
                "children": [c.to_dict() for c in self.children]}


class Tracer:
    """In-memory tracer with a span stack; mirrors to OTel if present."""

    def __init__(self, service: str = "aegis") -> None:
        self.service = service
        self.roots: list[SpanRecord] = []
        self._stack: list[SpanRecord] = []
        self._otel = _otel.get_tracer(service) if _HAVE_OTEL else None

    @contextmanager
    def span(self, name: str, **attributes) -> Iterator[SpanRecord]:
        rec = SpanRecord(name=name, start=time.perf_counter(), attributes=attributes)
        if self._stack:
            self._stack[-1].children.append(rec)
        else:
            self.roots.append(rec)
        self._stack.append(rec)
        otel_cm = (self._otel.start_as_current_span(name) if self._otel
                   else _nullcontext())
        try:
            with otel_cm:
                yield rec
        finally:
            rec.end = time.perf_counter()
            self._stack.pop()

    def timeline(self) -> list[dict]:
        return [r.to_dict() for r in self.roots]


@contextmanager
def _nullcontext():
    yield None


# A default process tracer for convenience.
default_tracer = Tracer()


@contextmanager
def span(name: str, **attributes):
    with default_tracer.span(name, **attributes) as rec:
        yield rec
