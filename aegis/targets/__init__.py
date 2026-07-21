"""Target layer: the systems under authorized assessment."""

from __future__ import annotations

from ..core.authorization import AuthorizationScope
from ..core.config import TargetConfig
from ..core.types import EvaluationMode, TargetKind
from ..providers import build_provider
from .base import Target
from .rag import Document, RAGTarget
from .surface import Endpoint, MCPTarget, MCPTool, WebTarget

__all__ = ["Target", "RAGTarget", "Document", "WebTarget", "MCPTarget", "MCPTool",
           "Endpoint", "build_target"]


def build_target(cfg: TargetConfig, scope: AuthorizationScope | None = None) -> Target:
    """Instantiate a :class:`Target` from a :class:`TargetConfig`."""
    provider = build_provider(cfg.provider, scope=scope, model=cfg.model,
                              endpoint=cfg.endpoint, params=cfg.params)
    mode = EvaluationMode(cfg.mode)
    kind = TargetKind(cfg.kind)
    meta = {"model": cfg.model, "endpoint": cfg.endpoint, **cfg.metadata}

    if kind == TargetKind.RAG:
        docs = [Document(**d) for d in cfg.metadata.get("corpus", [])]
        return RAGTarget(id=cfg.id, kind=kind, provider=provider, mode=mode,
                         metadata=meta, corpus=docs,
                         top_k=cfg.metadata.get("top_k", 3))
    if kind == TargetKind.MCP:
        tools = [MCPTool(**t) for t in cfg.metadata.get("tools", [])]
        return MCPTarget(id=cfg.id, kind=kind, provider=provider, mode=mode,
                         metadata=meta, tools=tools,
                         resources=cfg.metadata.get("resources", []),
                         transport=cfg.metadata.get("transport", "stdio"),
                         authenticated=cfg.metadata.get("authenticated", True))
    if kind in (TargetKind.WEB_APP, TargetKind.REST_API, TargetKind.GRAPHQL_API,
                TargetKind.AI_GATEWAY):
        eps = [Endpoint(**e) for e in cfg.metadata.get("endpoints", [])]
        return WebTarget(id=cfg.id, kind=kind, provider=provider, mode=mode,
                         metadata=meta, endpoints=eps)
    return Target(id=cfg.id, kind=kind, provider=provider, mode=mode, metadata=meta)
