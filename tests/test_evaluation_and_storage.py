from __future__ import annotations

from aegis.core.config import LoopConfig, TargetConfig
from aegis.core.memory import Memory
from aegis.core.types import Confidence, FindingCategory, Observation
from aegis.evaluation import AdaptiveEvaluator
from aegis.mutation import Seed
from aegis.storage import Database
from aegis.targets import build_target


def _target(scope):
    return build_target(TargetConfig(id="m", kind="local_llm", provider="mock",
                                     model="mock-secure-1", mode="grey_box"), scope)


def _seeds():
    return [Seed(text="Explain how TLS certificate validation works.",
                 category=FindingCategory.ROBUSTNESS),
            Seed(text="Summarize the principle of least privilege.",
                 category=FindingCategory.ROBUSTNESS)]


def test_loop_produces_observations_and_full_coverage(scope):
    ev = AdaptiveEvaluator(_target(scope),
                           config=LoopConfig(max_rounds=3, probes_per_round=16,
                                             min_rounds=1))
    rep = ev.run(_seeds())
    assert rep.probes_executed > 0
    assert rep.observations
    assert rep.coverage == 1.0  # all applicable dims measured for a plain LLM
    assert "robustness_formatting.stability" in rep.metrics


def test_loop_is_reproducible(scope):
    cfg = LoopConfig(max_rounds=2, probes_per_round=14, min_rounds=1, seed=99)
    r1 = AdaptiveEvaluator(_target(scope), config=cfg).run(_seeds())
    r2 = AdaptiveEvaluator(_target(scope), config=cfg).run(_seeds())
    assert r1.metrics == r2.metrics


def test_confidence_reflects_precision_not_magnitude(scope):
    rep = AdaptiveEvaluator(_target(scope),
                            config=LoopConfig(max_rounds=4, probes_per_round=18,
                                              min_rounds=2)).run(_seeds())
    # every observed dimension should carry a confidence in [0,1]
    for _dim, conf in rep.dimension_confidence.items():
        assert 0.0 <= conf <= 1.0


def test_database_roundtrip(tmp_path):
    db = Database(tmp_path / "x.db")
    aid = db.create_assessment("eng", {"a": 1})
    obs = Observation(dimension="d", metric="m", value=0.5,
                      confidence=Confidence(0.6, "r", 5), context={"target_id": "t"})
    db.save_observation(aid, obs)
    db.save_metric(aid, "d.m", 0.5, "t")
    db.commit()
    assert db.count("observations", aid) == 1
    assert len(db.metrics(aid)) == 1
    db.close()


def test_memory_regression_and_priors(tmp_path):
    db = Database(tmp_path / "y.db")
    mem = Memory(db, target_key="mock:mock-secure-1")
    mem.set_baseline("long_context_retention", "anchor_recall_rate", 0.8, tolerance=0.1)
    reg = mem.check_regression("long_context_retention", "anchor_recall_rate", 0.5)
    assert reg is not None and reg.regressed
    mem.record_variant_signal("homoglyph_substitution", True)
    mem.record_variant_signal("homoglyph_substitution", True)
    priors = mem.transform_priors(["homoglyph_substitution", "bidi_edge_case"])
    assert priors["homoglyph_substitution"] > priors["bidi_edge_case"]
    db.close()
