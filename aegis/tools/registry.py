"""Tool registry and intelligent test selection.

The registry holds :class:`ToolSpec` objects and answers the platform's core
"which tools apply here?" question — the intelligent decision layer from spec
§11/§31. It does *not* run anything (that is the executor's job); it reasons over
metadata plus an observed :class:`TargetProfile` and the engagement scope.

The selection is deliberately conservative and explainable:

* A tool applies only if the target *kind* is in its ``supported_targets`` **and**
  at least one of its ``applies_when`` tags is present in the observed profile
  (or the tool declares no tags, meaning "generally applicable to the kind").
* Tools whose risk class the engagement has not enabled are filtered out with a
  recorded reason, so the plan explains *why* something was or wasn't selected.
* Documentation-only tools are surfaced as *advisories* (relevant but not
  auto-runnable), never as executable steps.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..core.types import TargetKind
from .catalog import default_catalog
from .spec import RiskLevel, ToolCategory, ToolSpec


@dataclass
class TargetProfile:
    """What reconnaissance/fingerprinting has observed about a target.

    ``signals`` are free-form tags (e.g. "http", "graphql", "jwt", "llm",
    "rag", "domain", "source") matched against each tool's ``applies_when``.
    Kept as a set so selection is order-independent and deduplicated.
    """

    target: str
    kind: TargetKind = TargetKind.WEB_APP
    signals: set[str] = field(default_factory=set)

    def add(self, *tags: str) -> TargetProfile:
        for t in tags:
            if t:
                self.signals.add(t.lower())
        return self


@dataclass
class SelectedTool:
    spec: ToolSpec
    reason: str
    runnable: bool                       # executable AND risk-class enabled
    advisory: bool = False               # relevant but documentation-only/gated


@dataclass
class SelectionPlan:
    target: str
    kind: str
    signals: list[str]
    selected: list[SelectedTool]
    excluded: list[tuple[str, str]]      # (tool_name, why-excluded)

    def runnable_specs(self) -> list[ToolSpec]:
        return [s.spec for s in self.selected if s.runnable]

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "kind": self.kind,
            "signals": self.signals,
            "selected": [
                {"tool": s.spec.name, "category": s.spec.category.value,
                 "risk": s.spec.risk_level.name.lower(), "reason": s.reason,
                 "runnable": s.runnable, "advisory": s.advisory}
                for s in self.selected
            ],
            "excluded": [{"tool": n, "reason": r} for n, r in self.excluded],
        }


class ToolRegistry:
    """A collection of tool specs with applicability reasoning."""

    def __init__(self, specs: list[ToolSpec] | None = None) -> None:
        self._specs: dict[str, ToolSpec] = {}
        for spec in (specs if specs is not None else default_catalog()):
            self.register(spec)

    # -- registration ------------------------------------------------------- #
    def register(self, spec: ToolSpec) -> None:
        if spec.name in self._specs:
            raise ValueError(f"tool '{spec.name}' already registered")
        self._specs[spec.name] = spec

    def get(self, name: str) -> ToolSpec | None:
        return self._specs.get(name)

    def all(self) -> list[ToolSpec]:
        return list(self._specs.values())

    def by_category(self, category: ToolCategory) -> list[ToolSpec]:
        return [s for s in self._specs.values() if s.category == category]

    # -- intelligent selection --------------------------------------------- #
    def select(
        self,
        profile: TargetProfile,
        *,
        credential_testing: bool = False,
        exploitation: bool = False,
        max_risk: RiskLevel = RiskLevel.INTRUSIVE,
    ) -> SelectionPlan:
        """Return the applicable tools for an observed target, with reasons.

        ``max_risk`` caps how intrusive a *runnable* tool may be for this plan;
        tools above the cap are still surfaced as advisories.
        """
        selected: list[SelectedTool] = []
        excluded: list[tuple[str, str]] = []

        for spec in self._specs.values():
            # 1) target-kind applicability
            if spec.supported_targets and profile.kind not in spec.supported_targets:
                excluded.append((spec.name,
                                 f"target kind '{profile.kind.value}' unsupported"))
                continue
            # 2) signal applicability (empty applies_when => generally applicable)
            if spec.applies_when and not (set(spec.applies_when) & profile.signals):
                excluded.append((spec.name,
                                 "no matching signal in target profile"))
                continue

            reason = self._reason(spec, profile)

            # 3) documentation-only => advisory
            if not spec.executable:
                selected.append(SelectedTool(spec, reason + " (documentation-only)",
                                             runnable=False, advisory=True))
                continue

            # 4) risk-class gating
            if spec.risk_level > max_risk:
                selected.append(SelectedTool(
                    spec, reason + f" (exceeds max_risk={max_risk.name.lower()})",
                    runnable=False, advisory=True))
                continue
            if spec.risk_level == RiskLevel.DANGEROUS and not exploitation:
                selected.append(SelectedTool(
                    spec, reason + " (exploitation not enabled)",
                    runnable=False, advisory=True))
                continue
            if (spec.category == ToolCategory.CREDENTIAL
                    and not credential_testing):
                selected.append(SelectedTool(
                    spec, reason + " (credential_testing not enabled)",
                    runnable=False, advisory=True))
                continue

            selected.append(SelectedTool(spec, reason, runnable=True))

        # deterministic ordering: runnable first, then by risk then name
        selected.sort(key=lambda s: (not s.runnable, int(s.spec.risk_level),
                                     s.spec.name))
        return SelectionPlan(
            target=profile.target, kind=profile.kind.value,
            signals=sorted(profile.signals), selected=selected, excluded=excluded,
        )

    @staticmethod
    def _reason(spec: ToolSpec, profile: TargetProfile) -> str:
        matched = sorted(set(spec.applies_when) & profile.signals)
        if matched:
            return f"{spec.category.value}: signals {matched} present"
        return f"{spec.category.value}: applicable to {profile.kind.value}"
