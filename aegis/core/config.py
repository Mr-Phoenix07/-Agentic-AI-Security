"""Configuration loading for AEGIS.

Pure-stdlib config with an optional YAML upgrade (used only if ``pyyaml`` is
installed; otherwise JSON works everywhere). Config binds together the
authorization scope, targets, storage location, and evaluation thresholds.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from .authorization import AuthorizationScope

try:  # optional
    import yaml  # type: ignore

    _HAVE_YAML = True
except Exception:  # pragma: no cover
    _HAVE_YAML = False


@dataclass
class TargetConfig:
    id: str
    kind: str                              # matches types.TargetKind values
    provider: str = "mock"                 # provider key
    endpoint: Optional[str] = None
    model: Optional[str] = None
    params: dict = field(default_factory=dict)
    mode: str = "black_box"                # black_box|grey_box|white_box
    metadata: dict = field(default_factory=dict)


@dataclass
class LoopConfig:
    """Stopping conditions for the adaptive evaluation loop."""

    max_rounds: int = 6
    probes_per_round: int = 12
    coverage_target: float = 0.85          # fraction of dimensions probed
    confidence_target: float = 0.8         # mean confidence to stop
    min_rounds: int = 2
    seed: int = 1337                       # reproducibility


@dataclass
class Config:
    engagement: str = "unnamed-engagement"
    workdir: Path = field(default_factory=lambda: Path("./aegis_runs"))
    db_path: Optional[Path] = None
    scope: AuthorizationScope = field(default_factory=AuthorizationScope)
    targets: list[TargetConfig] = field(default_factory=list)
    loop: LoopConfig = field(default_factory=LoopConfig)
    log_level: str = "INFO"
    raw: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.workdir = Path(self.workdir)
        if self.db_path is None:
            self.db_path = self.workdir / "aegis.db"
        self.db_path = Path(self.db_path)

    # -- loaders ------------------------------------------------------------ #
    @classmethod
    def from_dict(cls, data: dict) -> "Config":
        loop = LoopConfig(**(data.get("loop") or {}))
        scope = AuthorizationScope.from_dict(data.get("authorization") or {})
        targets = [TargetConfig(**t) for t in (data.get("targets") or [])]
        return cls(
            engagement=data.get("engagement", "unnamed-engagement"),
            workdir=Path(data.get("workdir", "./aegis_runs")),
            db_path=Path(data["db_path"]) if data.get("db_path") else None,
            scope=scope,
            targets=targets,
            loop=loop,
            log_level=data.get("log_level", "INFO"),
            raw=data,
        )

    @classmethod
    def load(cls, path: str | os.PathLike) -> "Config":
        p = Path(path)
        text = p.read_text(encoding="utf-8")
        if p.suffix.lower() in (".yaml", ".yml"):
            if not _HAVE_YAML:
                raise RuntimeError(
                    "YAML config requires 'pyyaml' (pip install aegis-ai-security[extras]) "
                    "or provide JSON.")
            data = yaml.safe_load(text)
        else:
            data = json.loads(text)
        return cls.from_dict(data or {})

    def target(self, target_id: str) -> Optional[TargetConfig]:
        return next((t for t in self.targets if t.id == target_id), None)

    def to_dict(self) -> dict[str, Any]:
        return {
            "engagement": self.engagement,
            "workdir": str(self.workdir),
            "db_path": str(self.db_path),
            "authorization": self.scope.summary(),
            "targets": [t.__dict__ for t in self.targets],
            "loop": self.loop.__dict__,
            "log_level": self.log_level,
        }


def default_config(engagement: str = "demo") -> Config:
    """A safe, runnable default that only authorizes the offline mock target."""
    from .authorization import localhost_scope

    cfg = Config(engagement=engagement, scope=localhost_scope())
    cfg.targets = [
        TargetConfig(id="mock-llm", kind="local_llm", provider="mock",
                     model="mock-secure-1", mode="grey_box"),
    ]
    return cfg
