"""Explanation data model."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Explanation:
    method: str                     # e.g. "behavioral.transform_attribution"
    availability: str = "available"  # available|degraded|unavailable
    summary: str = ""
    attributions: list[dict] = field(default_factory=list)  # ranked contributors
    artifacts: dict = field(default_factory=dict)           # curves, diffs, ...
    notes: str = ""

    def to_dict(self) -> dict:
        return self.__dict__
