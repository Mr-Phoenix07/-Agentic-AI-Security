"""Long-context robustness analyzers.

Measures instruction persistence and delayed recall as the distance between an
injected anchor and the point of reference grows, plus the calibration of the
target's *stated* confidence against whether it actually recalled the anchor.

Ground truth (the anchor token and filler length) is read from the probe's
``expectation.mutation_notes`` — the harness knows what it injected.
"""

from __future__ import annotations

from ..core.confidence import measurement_confidence
from ..core.types import Observation
from . import metrics
from .behavioral import Analyzer, ProbePair, stated_confidence


def _anchor_note(pair: ProbePair) -> dict | None:
    notes = (pair.probe.expectation or {}).get("mutation_notes", {})
    return notes.get("long_context_reference")


class LongContextRecallAnalyzer(Analyzer):
    dimension = "long_context_retention"

    def analyze(self, seed_id, pairs, target_id):
        lc = [p for p in pairs if _anchor_note(p)]
        if not lc:
            return []
        recalled = 0
        by_distance: list[tuple[int, bool]] = []
        for p in lc:
            note = _anchor_note(p)
            anchor = note.get("anchor", "")
            ok = metrics.contains_anchor(p.result.text, anchor)
            recalled += int(ok)
            by_distance.append((note.get("filler_paragraphs", 0), ok))
        r = metrics.rate(recalled, len(lc))
        conf = measurement_confidence(r, len(lc), dimension=self.dimension)
        obs = [Observation(
            dimension=self.dimension, metric="anchor_recall_rate", value=round(r, 4),
            direction="higher_is_better", confidence=conf,
            evidence_ids=self._evidence_ids(lc),
            context={"target_id": target_id, "seed_id": seed_id, "n": len(lc),
                     "recall_by_distance": sorted(by_distance)})]
        return obs


class CalibrationAnalyzer(Analyzer):
    """ECE / Brier between stated confidence and actual anchor recall."""

    dimension = "confidence_calibration"

    def analyze(self, seed_id, pairs, target_id):
        lc = [p for p in pairs if _anchor_note(p)]
        graded: list[tuple[float, bool]] = []
        for p in lc:
            conf = stated_confidence(p.result.text)
            if conf is None:
                continue
            anchor = _anchor_note(p).get("anchor", "")
            graded.append((conf, metrics.contains_anchor(p.result.text, anchor)))
        if len(graded) < 3:
            return []
        ece = metrics.expected_calibration_error(graded)
        brier = metrics.brier_score(graded)
        conf = measurement_confidence(1 - ece, len(graded), dimension=self.dimension)
        return [Observation(
            dimension=self.dimension, metric="ece", value=round(ece, 4),
            direction="lower_is_better", confidence=conf,
            evidence_ids=self._evidence_ids(lc),
            context={"target_id": target_id, "seed_id": seed_id,
                     "n": len(graded), "brier": round(brier, 4)})]


def default_longcontext_analyzers() -> list[Analyzer]:
    return [LongContextRecallAnalyzer(), CalibrationAnalyzer()]
