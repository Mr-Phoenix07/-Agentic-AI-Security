"""Tests for the assessment-methodology knowledge base."""

from __future__ import annotations

import json

import pytest

import aegis.methodology as M
from aegis.core.types import FindingCategory, Severity
from aegis.methodology.models import Methodology, Phase, Technique


def test_registry_has_three_domains():
    ids = {m.id for m in M.list_methodologies()}
    assert ids == {"webapp", "active-directory", "ai-redteam"}


def test_every_methodology_is_well_formed():
    for m in M.list_methodologies():
        assert isinstance(m, Methodology)
        assert m.title and m.summary and m.authorization_note
        assert m.references, f"{m.id} must cite frameworks"
        assert m.phases, f"{m.id} must have phases"
        assert m.technique_count() >= len(m.phases)
        for ph in m.phases:
            assert isinstance(ph, Phase)
            assert ph.techniques, f"{m.id}/{ph.id} must have techniques"


def test_every_technique_is_defensive_and_mapped():
    """A technique must carry defensive value (mitigations) and a framework map."""
    for t in M.all_techniques():
        assert isinstance(t, Technique)
        assert t.objective and t.approach
        assert t.mitigations, f"{t.id} must document mitigations"
        assert t.frameworks, f"{t.id} must map to a framework"
        assert isinstance(t.category, FindingCategory)
        assert isinstance(t.severity_hint, Severity)


def test_technique_ids_are_unique():
    ids = [t.id for t in M.all_techniques()]
    assert len(ids) == len(set(ids)), "technique ids must be globally unique"


@pytest.mark.parametrize("alias,expected", [
    ("web", "webapp"),
    ("web-app", "webapp"),
    ("ad", "active-directory"),
    ("active_directory", "active-directory"),
    ("ai", "ai-redteam"),
    ("llm", "ai-redteam"),
    ("WEBAPP", "webapp"),
])
def test_aliases_resolve(alias, expected):
    m = M.get_methodology(alias)
    assert m is not None and m.id == expected


def test_unknown_methodology_returns_none():
    assert M.get_methodology("does-not-exist") is None


def test_find_technique_by_id_case_insensitive():
    web = M.get_methodology("webapp")
    assert web.find("wstg-inpv-05") is not None
    assert web.find("WSTG-INPV-05").severity_hint == Severity.CRITICAL


def test_knowledge_base_serializes_to_json():
    payload = M.to_dict()
    assert payload["methodology_count"] == 3
    assert payload["technique_count"] == len(M.all_techniques())
    # Round-trips through JSON without error.
    text = json.dumps(payload)
    assert "webapp" in text and "active-directory" in text and "ai-redteam" in text


def test_active_directory_maps_to_attack_and_is_authorized():
    ad = M.get_methodology("active-directory")
    note = ad.authorization_note.lower()
    assert "authorized" in note or "own" in note
    # ATT&CK technique ids appear in the mappings.
    joined = json.dumps(ad.to_dict())
    assert "T1558" in joined  # Kerberos-related ATT&CK techniques
