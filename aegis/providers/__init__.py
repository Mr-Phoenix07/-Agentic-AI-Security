"""Vendor-independent provider layer.

The offline :class:`MockProvider` is always available; other providers are built
on demand so optional deps stay optional.
"""

from __future__ import annotations

from typing import Optional

from ..core.authorization import AuthorizationScope
from .base import Provider, ProviderRequest, ProviderResponse
from .mock import MockProvider


def build_provider(kind: str, *, scope: Optional[AuthorizationScope] = None,
                   model: Optional[str] = None, endpoint: Optional[str] = None,
                   params: Optional[dict] = None) -> Provider:
    """Factory mapping a provider key to an instance."""
    kind = (kind or "mock").lower()
    if kind == "mock":
        return MockProvider(scope=scope, model=model or "mock-secure-1",
                            params=params, quality=(params or {}).get("quality", 0.8))
    if kind in ("openai_compat", "openai", "ollama", "vllm", "local"):
        from .openai_compat import OpenAICompatProvider

        if not endpoint:
            raise ValueError(f"provider '{kind}' requires an endpoint")
        return OpenAICompatProvider(endpoint=endpoint, model=model or "gpt-4o-mini",
                                    scope=scope, params=params)
    raise ValueError(f"unknown provider kind: {kind}")


__all__ = ["Provider", "ProviderRequest", "ProviderResponse", "MockProvider",
           "build_provider"]
