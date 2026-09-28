"""Benchmark data model: ground-truth cases and accuracy scoring.

AEGIS measures its own detection *accuracy* the way a scanner benchmark does:
run the platform against targets whose weaknesses are **known in advance**
(ground truth) and compare what it reports to what should be there. Everything
here is offline and self-contained — the cases use the deterministic mock
provider and declared-inventory surfaces, so there is no network, no keys, and
no external or unauthorized target involved.

Scoring is restricted, per case, to a set of *graded* finding categories so that
behavioural noise never counts against a surface-detection case (and vice-versa):

    * True positive (TP)  — an expected finding is reported.
    * False negative (FN) — an expected finding is missed.
    * False positive (FP) — a reported finding in a graded category matches no
                             expected finding (measured especially on hardened
                             control cases, which expect nothing).

From TP/FP/FN we derive precision, recall and F1 — the headline accuracy numbers.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

from ..core.types import FindingCategory, Severity


@dataclass
class ExpectedFinding:
    """One ground-truth positive: a weakness that *should* be detected."""

    target_id: str
    category: FindingCategory
    title_contains: str = ""            # optional substring to disambiguate
    note: str = ""

    def matches(self, finding: dict) -> bool:
        if finding.get("target_id") != self.target_id:
            return False
        if finding.get("category") != self.category.value:
            return False
        if self.title_contains:
            return self.title_contains.lower() in (finding.get("title", "").lower())
        return True

    def to_dict(self) -> dict:
        d = asdict(self)
        d["category"] = self.category.value
        return d


@dataclass
class BenchmarkCase:
    """A target scenario with known ground truth.

    ``graded_categories`` bounds what counts as a false positive: only reported
    findings in these categories are scored, so a surface case is not penalised
    for (real) behavioural findings on an LLM in the same scenario.
    """

    id: str
    description: str
    targets: list[dict]
    expected: list[ExpectedFinding] = field(default_factory=list)
    graded_categories: set[FindingCategory] = field(default_factory=set)
    min_severity: Severity = Severity.LOW
    kind: str = "vulnerable"            # "vulnerable" | "hardened-control"
    # When ground truth is intentionally incomplete (e.g. "at least one robustness
    # weakness"), score recall only so extra *real* findings are not counted as FPs.
    count_false_positives: bool = True

    def graded_values(self) -> set[str]:
        return {c.value for c in self.graded_categories}


@dataclass
class CaseResult:
    case_id: str
    kind: str
    tp: int = 0
    fp: int = 0
    fn: int = 0
    matched: list[str] = field(default_factory=list)   # expected that were found
    missed: list[str] = field(default_factory=list)    # expected that were missed
    spurious: list[str] = field(default_factory=list)  # graded findings not expected
    reported: list[dict] = field(default_factory=list)  # compact finding summaries

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 1.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom else 1.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    def to_dict(self) -> dict:
        d = asdict(self)
        d.update(precision=round(self.precision, 4),
                 recall=round(self.recall, 4), f1=round(self.f1, 4))
        return d


@dataclass
class BenchmarkReport:
    seed: int
    cases: list[CaseResult] = field(default_factory=list)
    generated_at: float = 0.0

    # Cases tagged as documented coverage gaps are reported separately and never
    # dragged into the headline accuracy of *implemented* detections.
    GAP_KIND = "coverage-gap"

    @property
    def graded_cases(self) -> list[CaseResult]:
        return [c for c in self.cases if c.kind != self.GAP_KIND]

    @property
    def gap_cases(self) -> list[CaseResult]:
        return [c for c in self.cases if c.kind == self.GAP_KIND]

    @property
    def tp(self) -> int:
        return sum(c.tp for c in self.graded_cases)

    @property
    def fp(self) -> int:
        return sum(c.fp for c in self.graded_cases)

    @property
    def fn(self) -> int:
        return sum(c.fn for c in self.graded_cases)

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 1.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom else 1.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    def to_dict(self) -> dict:
        return {
            "seed": self.seed,
            "generated_at": self.generated_at,
            "totals": {
                "tp": self.tp, "fp": self.fp, "fn": self.fn,
                "precision": round(self.precision, 4),
                "recall": round(self.recall, 4),
                "f1": round(self.f1, 4),
                "graded_cases": len(self.graded_cases),
                "coverage_gap_cases": len(self.gap_cases),
            },
            "cases": [c.to_dict() for c in self.graded_cases],
            "coverage_gaps": [c.to_dict() for c in self.gap_cases],
        }
