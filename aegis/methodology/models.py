"""Machine-readable assessment-methodology model.

AEGIS represents each testing methodology (web application, Active Directory,
AI red-teaming) as structured, serializable data rather than free-form prose so
that it can be:

    * queried from the CLI (``aegis methodology ...``),
    * mapped to the same industry frameworks the reporting layer already uses,
    * cross-referenced with :class:`~aegis.core.types.FindingCategory`, and
    * exported into an engagement plan / report appendix.

Design posture (identical to the rest of AEGIS): every technique is described
at the *methodology* altitude — objective, what a robust system does, the
detection signals a defender should see, and the mitigation — **not** as a
ready-to-run exploit recipe. This keeps the knowledge base useful for authorized
assessment and blue-team hardening while staying safe by construction. Active,
intrusive checks remain gated behind the fail-closed authorization scope and the
controlled-validation agent, exactly as for the live-target adapters.

Pure standard library (dataclasses + enums) so it runs fully offline.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

from ..core.types import FindingCategory, Severity


@dataclass
class Technique:
    """A single methodology step: what to assess and how to defend against it.

    A ``Technique`` deliberately records the *defensive* half of the picture
    (``detection`` + ``mitigations``) alongside the assessment ``objective`` so
    a finding produced from it is immediately actionable.
    """

    id: str                                   # stable id, e.g. "WSTG-ATHN-01"
    name: str
    objective: str                            # what the test determines
    approach: str                             # how it is assessed (authorized, safe)
    signals: list[str] = field(default_factory=list)      # indicators of weakness
    detection: list[str] = field(default_factory=list)    # blue-team detections
    mitigations: list[str] = field(default_factory=list)
    frameworks: dict[str, list[str]] = field(default_factory=dict)
    category: FindingCategory = FindingCategory.OTHER
    severity_hint: Severity = Severity.INFO
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["category"] = self.category.value
        d["severity_hint"] = self.severity_hint.value
        return d


@dataclass
class Phase:
    """A named stage of an engagement grouping related techniques."""

    id: str
    name: str
    goal: str
    techniques: list[Technique] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "goal": self.goal,
            "techniques": [t.to_dict() for t in self.techniques],
        }


@dataclass
class Methodology:
    """A complete, phased assessment methodology for one domain."""

    id: str
    title: str
    domain: str                               # web_app | active_directory | ai_red_team
    summary: str
    authorization_note: str
    references: dict[str, str] = field(default_factory=dict)
    phases: list[Phase] = field(default_factory=list)

    # -- convenience accessors ------------------------------------------------
    def techniques(self) -> list[Technique]:
        return [t for ph in self.phases for t in ph.techniques]

    def technique_count(self) -> int:
        return sum(len(ph.techniques) for ph in self.phases)

    def find(self, technique_id: str) -> Technique | None:
        for t in self.techniques():
            if t.id.lower() == technique_id.lower():
                return t
        return None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "domain": self.domain,
            "summary": self.summary,
            "authorization_note": self.authorization_note,
            "references": self.references,
            "phase_count": len(self.phases),
            "technique_count": self.technique_count(),
            "phases": [ph.to_dict() for ph in self.phases],
        }
