"""Assessment-methodology knowledge base.

Machine-readable, framework-mapped testing methodologies for the three domains
AEGIS covers, exposed through a small registry so the CLI, reporting layer, and
engagement planning can query them uniformly:

    * ``webapp``            — Web Application & API Penetration Testing (OWASP WSTG)
    * ``active-directory``  — Active Directory Security Assessment (MITRE ATT&CK)
    * ``ai-redteam``        — AI / LLM / Agentic Red-Teaming (OWASP LLM/ASI, ATLAS)

Each methodology is defensive by construction: techniques document *what* to
assess plus the *detection* and *mitigation* that close the gap, never a
weaponized recipe. Active checks stay behind the fail-closed authorization gate.
"""

from __future__ import annotations

from .active_directory import ACTIVE_DIRECTORY
from .ai_redteam import AI_REDTEAM
from .models import Methodology, Phase, Technique
from .webapp import WEBAPP

# id -> Methodology
REGISTRY: dict[str, Methodology] = {
    WEBAPP.id: WEBAPP,
    ACTIVE_DIRECTORY.id: ACTIVE_DIRECTORY,
    AI_REDTEAM.id: AI_REDTEAM,
}

# Convenient aliases people are likely to type.
_ALIASES = {
    "web": "webapp",
    "web-app": "webapp",
    "webapp": "webapp",
    "ad": "active-directory",
    "active_directory": "active-directory",
    "activedirectory": "active-directory",
    "ai": "ai-redteam",
    "ai_redteam": "ai-redteam",
    "redteam": "ai-redteam",
    "llm": "ai-redteam",
}


def list_methodologies() -> list[Methodology]:
    """Return all registered methodologies (stable order)."""
    return list(REGISTRY.values())


def get_methodology(name: str) -> Methodology | None:
    """Look up a methodology by id or a common alias (case-insensitive)."""
    key = (name or "").strip().lower()
    key = _ALIASES.get(key, key)
    return REGISTRY.get(key)


def all_techniques() -> list[Technique]:
    """Flatten every technique across every methodology."""
    return [t for m in REGISTRY.values() for t in m.techniques()]


def to_dict() -> dict:
    """Serialize the whole knowledge base (for export/report appendix)."""
    return {
        "methodologies": [m.to_dict() for m in REGISTRY.values()],
        "methodology_count": len(REGISTRY),
        "technique_count": sum(m.technique_count() for m in REGISTRY.values()),
    }


__all__ = [
    "Methodology", "Phase", "Technique",
    "REGISTRY", "list_methodologies", "get_methodology",
    "all_techniques", "to_dict",
    "WEBAPP", "ACTIVE_DIRECTORY", "AI_REDTEAM",
]
