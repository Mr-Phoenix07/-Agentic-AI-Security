"""Adaptive evaluation loop — the closed-loop assessment engine.

Implements the twelve-step cycle from the platform specification:

    1. receive objectives          7. estimate confidence
    2. plan a strategy             8. identify knowledge gaps
    3. generate initial probes     9. generate targeted follow-ups
    4. execute                    10. refine strategy
    5. collect responses          11. repeat until coverage/confidence met
    6. analyze observations       12. hand off findings + recommendations

The loop is *adaptive*: each round it inspects coverage and per-dimension
confidence, then biases the next round's transforms toward under-covered or
low-confidence dimensions — further weighted by historical priors from
:class:`~aegis.core.memory.Memory`. Scoring of any individual probe is fixed and
deterministic, so adaptivity never compromises reproducibility.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from ..core.config import LoopConfig
from ..core.memory import Memory
from ..core.types import Observation, TargetKind
from ..mutation.engine import MutationEngine, Seed
from ..targets.base import Target
from . import metrics
from .behavioral import Analyzer, ProbePair, default_analyzers
from .longcontext import default_longcontext_analyzers
from .rag import default_rag_analyzers

# Which transforms most directly exercise each behavioural dimension. Used to
# turn "this dimension is under-covered" into "run these transforms next".
DIMENSION_TRANSFORMS: dict[str, list[str]] = {
    "response_stability": ["identity", "format_shift", "style_change",
                           "persona_change"],
    "robustness_formatting": ["homoglyph_substitution", "zero_width_injection",
                              "cyrillic_mixed_script", "bidi_edge_case",
                              "unicode_normalization", "ocr_like", "format_shift"],
    "long_context_retention": ["long_context_reference"],
    "confidence_calibration": ["long_context_reference"],
    "instruction_following": ["instruction_hierarchy", "ambiguity_injection"],
    "reasoning_consistency": ["multi_document", "taxonomy_organization",
                              "nested_document"],
    "multilingual_behavior": ["mixed_language"],
    "hallucination_grounding": ["fictional_scenario", "academic_framing"],
    "context_management": ["conversation_restart", "long_context_reference"],
    "structured_output": ["format_shift", "table_heavy"],
}

ProgressCb = Callable[[str, dict], None]


@dataclass
class RoundLog:
    index: int
    probes: int
    new_observations: int
    coverage: float
    mean_confidence: float
    gaps: list[str]


@dataclass
class EvaluationReport:
    target_id: str
    observations: list[Observation] = field(default_factory=list)
    metrics: dict = field(default_factory=dict)
    coverage: float = 0.0
    dimension_confidence: dict = field(default_factory=dict)
    rounds: list[RoundLog] = field(default_factory=list)
    probes_executed: int = 0
    stop_reason: str = ""


class AdaptiveEvaluator:
    def __init__(
        self,
        target: Target,
        engine: MutationEngine | None = None,
        analyzers: list[Analyzer] | None = None,
        memory: Memory | None = None,
        config: LoopConfig | None = None,
        on_probe: Callable[[object, object], None] | None = None,
        on_observation: Callable[[Observation], None] | None = None,
        progress: ProgressCb | None = None,
    ) -> None:
        self.target = target
        self.engine = engine or MutationEngine(seed=(config or LoopConfig()).seed)
        self.analyzers = analyzers or self._analyzers_for(target)
        self.memory = memory
        self.config = config or LoopConfig()
        self.on_probe = on_probe
        self.on_observation = on_observation
        self.progress = progress or (lambda *_: None)

    def _analyzers_for(self, target: Target) -> list[Analyzer]:
        analyzers = list(default_analyzers()) + list(default_longcontext_analyzers())
        if target.kind == TargetKind.RAG:
            analyzers += default_rag_analyzers()
        return analyzers

    @property
    def applicable_dimensions(self) -> set[str]:
        """Dimensions this analyzer set can actually measure for this target.

        Coverage is scored against this set — not all ten canonical dimensions —
        so a plain LLM target is not penalised for RAG-only dimensions. This is
        an honest denominator: "of what we *can* assess, how much have we?".
        """
        return {a.dimension for a in self.analyzers}

    # -- main loop ---------------------------------------------------------- #
    def run(self, seeds: list[Seed]) -> EvaluationReport:
        report = EvaluationReport(target_id=self.target.id)
        # Probe pool accumulates across rounds so sample sizes (and thus
        # confidence) grow; each round re-analyzes the *full* pool.
        pool: dict[str, list[ProbePair]] = {}
        covered: dict[str, Observation] = {}
        strategy = self._initial_strategy()

        for r in range(self.config.max_rounds):
            self.progress("round.start", {"round": r, "strategy_dims": list(strategy)})
            probes = self._probes_for_round(seeds, strategy, salt=r)
            for probe in probes:
                result = self.target.send(probe)
                report.probes_executed += 1
                if self.on_probe:
                    self.on_probe(probe, result)
                pool.setdefault(probe.seed_id, []).append(ProbePair(probe, result))

            observations = self._analyze(pool)
            covered = {o.dimension: o for o in observations}   # latest per dimension
            for o in observations:
                if self.on_observation:
                    self.on_observation(o)
            if self.memory:
                for o in observations:
                    informative = self._is_informative(o)
                    for t in o.context.get("transforms", []):
                        self.memory.record_variant_signal(t, informative)

            coverage = metrics.coverage_fraction(set(covered), self.applicable_dimensions)
            dim_conf = {d: o.confidence.value for d, o in covered.items()}
            mean_conf = (sum(dim_conf.values()) / len(dim_conf)) if dim_conf else 0.0
            gaps = self._gaps(set(covered), dim_conf)

            report.rounds.append(RoundLog(r, len(probes), len(observations),
                                          round(coverage, 3), round(mean_conf, 3), gaps))
            self.progress("round.end", {"round": r, "coverage": coverage,
                                        "mean_confidence": mean_conf, "gaps": gaps})

            if self._should_stop(r, coverage, mean_conf):
                report.stop_reason = self._stop_reason(r, coverage, mean_conf)
                strategy = None  # type: ignore
                break
            strategy = self._refine_strategy(gaps)

        final_obs = list(covered.values())
        report.observations = final_obs
        report.coverage = metrics.coverage_fraction(set(covered), self.applicable_dimensions)
        report.dimension_confidence = {d: round(o.confidence.value, 4)
                                       for d, o in covered.items()}
        report.metrics = self._roll_up_metrics(final_obs)
        if not report.stop_reason:
            report.stop_reason = "max_rounds_reached"
        return report

    # -- strategy ----------------------------------------------------------- #
    def _initial_strategy(self) -> dict[str, list[str]]:
        return {dim: list(ts) for dim, ts in DIMENSION_TRANSFORMS.items()}

    def _refine_strategy(self, gaps: list[str]) -> dict[str, list[str]]:
        """Focus the next round on gap dimensions, re-ordered by memory priors."""
        strategy: dict[str, list[str]] = {}
        for dim in gaps or list(DIMENSION_TRANSFORMS):
            ts = list(DIMENSION_TRANSFORMS.get(dim, []))
            if self.memory:
                priors = self.memory.transform_priors(ts)
                ts.sort(key=lambda t: priors.get(t, 0.5), reverse=True)
            strategy[dim] = ts
        return strategy

    def _probes_for_round(self, seeds, strategy, salt: int = 0) -> list:
        chains: list[list[str]] = [["identity"]]   # control baseline first
        for ts in strategy.values():
            for t in ts:
                chains.append([t])
        # De-dup while preserving order and cap per round.
        seen, uniq = set(), []
        for c in chains:
            key = tuple(c)
            if key in seen:
                continue
            seen.add(key)
            uniq.append(c)
        uniq = uniq[: self.config.probes_per_round]
        probes = []
        for seed in seeds:
            probes += self.engine.build(seed, uniq, salt=salt)
        return probes

    # -- analysis ----------------------------------------------------------- #
    def _analyze(self, pairs_by_seed) -> list[Observation]:
        out: list[Observation] = []
        for seed_id, pairs in pairs_by_seed.items():
            transforms = sorted({t for p in pairs for t in p.probe.provenance})
            for analyzer in self.analyzers:
                for obs in analyzer.analyze(seed_id, pairs, self.target.id):
                    obs.context.setdefault("transforms", transforms)
                    out.append(obs)
        return out

    def _gaps(self, covered, dim_conf) -> list[str]:
        gaps = [d for d in self.applicable_dimensions if d not in covered]
        gaps += [d for d, c in dim_conf.items() if c < self.config.confidence_target]
        # Preserve order, dedup.
        seen, out = set(), []
        for g in gaps:
            if g not in seen:
                seen.add(g)
                out.append(g)
        return out

    def _is_informative(self, o: Observation) -> bool:
        """An observation is 'informative' when it indicates weaker-than-ideal
        behaviour (worth prioritising the producing transforms in future)."""
        good = o.value if o.direction == "higher_is_better" else (1 - o.value)
        return good < 0.85

    def _roll_up_metrics(self, observations) -> dict:
        agg: dict[str, list[float]] = {}
        for o in observations:
            agg.setdefault(f"{o.dimension}.{o.metric}", []).append(o.value)
        return {k: round(sum(v) / len(v), 4) for k, v in agg.items()}

    # -- stopping conditions ------------------------------------------------ #
    def _should_stop(self, r, coverage, mean_conf) -> bool:
        if r + 1 < self.config.min_rounds:
            return False
        if coverage >= self.config.coverage_target and \
           mean_conf >= self.config.confidence_target:
            return True
        return r + 1 >= self.config.max_rounds

    def _stop_reason(self, r, coverage, mean_conf) -> str:
        if coverage >= self.config.coverage_target and \
           mean_conf >= self.config.confidence_target:
            return "coverage_and_confidence_targets_met"
        return "max_rounds_reached"
