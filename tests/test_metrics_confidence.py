from __future__ import annotations

from aegis.core.confidence import (
    agree,
    measurement_confidence,
    wilson_interval,
)
from aegis.evaluation import metrics


def test_cosine_identical_is_one():
    assert metrics.cosine_similarity("a b c", "a b c") == 1.0


def test_cosine_disjoint_is_zero():
    assert metrics.cosine_similarity("apple pie", "quantum flux") == 0.0


def test_consistency_score_range():
    s = metrics.consistency_score(["the cat sat", "the cat sat here", "a dog ran"])
    assert 0.0 <= s <= 1.0


def test_ece_perfect_calibration_is_low():
    # confidence matches accuracy in each bucket
    pairs = [(0.9, True)] * 9 + [(0.9, False)] * 1  # 90% conf, 90% correct
    assert metrics.expected_calibration_error(pairs) < 0.05


def test_ece_miscalibration_is_high():
    pairs = [(0.95, False)] * 10  # always confident, always wrong
    assert metrics.expected_calibration_error(pairs) > 0.8


def test_brier_bounds():
    assert metrics.brier_score([(1.0, True)]) == 0.0
    assert metrics.brier_score([(1.0, False)]) == 1.0


def test_wilson_interval_widens_for_small_n():
    lo1, hi1 = wilson_interval(1, 2)
    lo2, hi2 = wilson_interval(10, 20)
    assert (hi1 - lo1) > (hi2 - lo2)


def test_measurement_confidence_grows_with_n():
    c_small = measurement_confidence(0.0, 2)
    c_large = measurement_confidence(0.0, 40)
    assert c_large.value > c_small.value


def test_measurement_confidence_high_for_extreme_large_n():
    # A confidently-poor result: value 0.0 measured over many trials -> high conf.
    c = measurement_confidence(0.0, 60)
    assert c.value > 0.7


def test_agree_noisy_or_increases_confidence():
    from aegis.core.types import Confidence
    combined = agree([Confidence(0.5), Confidence(0.5)])
    assert combined.value > 0.5


def test_grounding_rate():
    traces = [
        {"cited_ids": ["D1"], "retrieved_ids": ["D1", "D2"]},   # grounded
        {"cited_ids": ["D9"], "retrieved_ids": ["D1"]},         # ungrounded
    ]
    assert metrics.grounding_rate(traces) == 0.5
