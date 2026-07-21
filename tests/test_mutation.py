from __future__ import annotations

import random

from aegis.core.types import FindingCategory
from aegis.mutation import MutationEngine, Seed, default_transforms
from aegis.mutation.transforms import (
    BidiEdgeCase,
    HomoglyphSubstitution,
    LongContextReference,
    UnicodeNormalizationVariant,
    ZeroWidthInjection,
)


def _seed():
    return Seed(text="Explain how TLS certificate validation works.",
                category=FindingCategory.ROBUSTNESS)


def test_engine_is_deterministic():
    eng = MutationEngine(seed=42)
    a = eng.generate([_seed()], per_seed=12)
    b = eng.generate([_seed()], per_seed=12)
    assert [p.content_hash for p in a] == [p.content_hash for p in b]


def test_generated_probes_are_unique_and_include_identity():
    eng = MutationEngine(seed=7)
    probes = eng.generate([_seed()], per_seed=15)
    hashes = [p.content_hash for p in probes]
    assert len(hashes) == len(set(hashes))
    assert any(p.provenance == ["identity"] for p in probes)


def test_transforms_preserve_nonempty_output():
    rng = random.Random(0)
    for t in default_transforms():
        res = t.apply("The quick brown fox jumps over ABC 123.", rng)
        assert res.text
        assert res.transform == t.name


def test_homoglyph_actually_substitutes():
    out = HomoglyphSubstitution(rate=1.0).apply("cape", random.Random(1))
    # 'a','c','e' have cyrillic homoglyphs; text should change but read the same.
    assert out.text != "cape"
    assert out.notes["swapped"] >= 1


def test_zero_width_injection_adds_invisible_chars():
    out = ZeroWidthInjection().apply("hello world foobar baz", random.Random(2))
    assert any(c in out.text for c in "​‌‍⁠")


def test_bidi_is_reversible_wrap():
    out = BidiEdgeCase().apply("hello", random.Random(3))
    assert out.reversible
    assert "hello" in out.text


def test_unicode_normalization_roundtrips_semantics():
    out = UnicodeNormalizationVariant().apply("café", random.Random(4))
    assert out.notes["form"] in ("NFC", "NFD", "NFKC", "NFKD")


def test_long_context_reference_embeds_anchor():
    out = LongContextReference(filler_paragraphs=8).apply("Q?", random.Random(5))
    assert out.notes["anchor"] in out.text
    assert out.notes["filler_paragraphs"] == 8


def test_apply_chain_salt_varies_output():
    eng = MutationEngine(seed=1)
    seed = _seed()
    v0 = eng.apply_chain(seed, ["homoglyph_substitution"], salt=0)
    v1 = eng.apply_chain(seed, ["homoglyph_substitution"], salt=1)
    assert v0.lineage == ["homoglyph_substitution"]
    # different salt -> generally different substitution positions
    assert v0.text != v1.text or v0.notes != v1.notes


def test_identity_passthrough_in_chain():
    eng = MutationEngine(seed=1)
    v = eng.apply_chain(_seed(), ["identity"])
    assert v.lineage == ["identity"]
    assert v.text == _seed().text
