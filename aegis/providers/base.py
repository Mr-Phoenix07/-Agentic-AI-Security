"""Provider abstraction — the boundary between AEGIS and a model/endpoint.

A :class:`Provider` is a thin, uniform interface for *sending a request and
getting a response*. It is where authorization is enforced (no request leaves
the platform without passing the scope guard) and where reproducibility metadata
is captured.

Providers are pluggable and vendor-independent: the offline :class:`MockProvider`
lets the whole platform run with no network or API keys, while
:class:`OpenAICompatProvider` speaks to any OpenAI-compatible endpoint (local
llama.cpp / Ollama / vLLM / LM Studio, or an authorized hosted gateway).
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional

from ..core.authorization import AuthorizationScope


@dataclass
class ProviderRequest:
    prompt: Optional[str] = None
    messages: Optional[list[dict]] = None      # [{"role","content"}, ...]
    params: dict = field(default_factory=dict)  # temperature, max_tokens, seed...
    # For authorization checks:
    model: Optional[str] = None
    endpoint: Optional[str] = None

    def as_messages(self) -> list[dict]:
        if self.messages:
            return self.messages
        return [{"role": "user", "content": self.prompt or ""}]

    def as_text(self) -> str:
        if self.prompt is not None:
            return self.prompt
        return "\n".join(m.get("content", "") for m in (self.messages or []))


@dataclass
class ProviderResponse:
    text: str = ""
    raw: dict = field(default_factory=dict)
    latency_ms: float = 0.0
    tokens: dict = field(default_factory=dict)
    model: Optional[str] = None
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {"text": self.text, "raw": self.raw, "latency_ms": self.latency_ms,
                "tokens": self.tokens, "model": self.model, "error": self.error}


class Provider(ABC):
    """Base provider. Subclasses implement :meth:`_complete`."""

    name = "provider"

    def __init__(self, scope: Optional[AuthorizationScope] = None,
                 model: Optional[str] = None, endpoint: Optional[str] = None,
                 params: Optional[dict] = None) -> None:
        self.scope = scope
        self.model = model
        self.endpoint = endpoint
        self.default_params = params or {}

    # -- authorization gate ------------------------------------------------- #
    def _authorize(self, req: ProviderRequest) -> None:
        if self.scope is None:
            return  # no scope configured == caller assumes responsibility
        endpoint = req.endpoint or self.endpoint
        model = req.model or self.model
        if endpoint:
            self.scope.require_url(endpoint)
        elif model:
            self.scope.require_model(model)
        else:
            # Nothing to identify the target — fail closed unless dry-run.
            self.scope.require_model("<unspecified>")

    # -- public API --------------------------------------------------------- #
    def complete(self, req: ProviderRequest) -> ProviderResponse:
        self._authorize(req)
        merged = {**self.default_params, **(req.params or {})}
        req = ProviderRequest(prompt=req.prompt, messages=req.messages,
                              params=merged, model=req.model or self.model,
                              endpoint=req.endpoint or self.endpoint)
        start = time.perf_counter()
        try:
            resp = self._complete(req)
        except Exception as e:  # normalise provider errors
            return ProviderResponse(error=f"{type(e).__name__}: {e}",
                                    latency_ms=(time.perf_counter() - start) * 1000)
        if not resp.latency_ms:
            resp.latency_ms = (time.perf_counter() - start) * 1000
        resp.model = resp.model or req.model
        return resp

    @abstractmethod
    def _complete(self, req: ProviderRequest) -> ProviderResponse: ...
