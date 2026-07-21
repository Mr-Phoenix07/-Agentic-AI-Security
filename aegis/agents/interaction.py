"""Interaction agents: mutation, optimization, conversation, long-context, and the
core adaptive evaluation driver."""

from __future__ import annotations

from ..core.confidence import Confidence, measurement_confidence
from ..core.types import (
    FindingCategory,
    Observation,
    Probe,
    TargetKind,
)
from ..evaluation.loop import DIMENSION_TRANSFORMS, AdaptiveEvaluator
from ..mutation.engine import MutationEngine, Seed
from ..mutation.transforms import default_transforms
from .base import BaseAgent

_MODEL_KINDS = {TargetKind.LOCAL_LLM, TargetKind.API_LLM, TargetKind.RAG,
                TargetKind.COPILOT, TargetKind.MULTI_AGENT, TargetKind.AI_GATEWAY}


class PromptMutationAgent(BaseAgent):
    name = "prompt_mutation"
    responsibilities = ("Own the transform catalog and expose reproducible probe "
                        "generation to the evaluation loop.")
    inputs = ["seeds"]
    outputs = ["plan"]

    def should_run(self, state):
        return any(t.kind in _MODEL_KINDS for t in state.targets)

    def _run(self, state):
        transforms = default_transforms()
        state.plan["mutation"] = {
            "transform_count": len(transforms),
            "transforms": [{"name": t.name, "category": t.category, "probes": t.probes}
                           for t in transforms],
        }
        return state


class PromptOptimizationAgent(BaseAgent):
    name = "prompt_optimization"
    responsibilities = ("Prioritise transforms per target using historical signal "
                        "(bandit-style priors) to focus the evaluation budget.")
    inputs = ["plan"]
    outputs = ["strategy"]

    def should_run(self, state):
        return any(t.kind in _MODEL_KINDS for t in state.targets)

    def _run(self, state):
        for t in state.targets:
            if t.kind not in _MODEL_KINDS:
                continue
            mem = state.mem_for(t)
            optimized = {}
            for dim, ts in DIMENSION_TRANSFORMS.items():
                priors = mem.transform_priors(ts)
                optimized[dim] = sorted(ts, key=lambda x: priors.get(x, 0.5),
                                        reverse=True)
            state.strategy[t.id] = optimized
        return state


class ConversationAgent(BaseAgent):
    name = "conversation"
    responsibilities = ("Exercise multi-turn context management: establish a fact, "
                        "distract, then require recall.")
    inputs = ["targets"]
    outputs = ["observations"]

    def should_run(self, state):
        return any(t.kind in _MODEL_KINDS for t in state.targets)

    def _run(self, state):
        for t in state.targets:
            if t.kind not in _MODEL_KINDS:
                continue
            hits = 0
            trials = 6
            evidence_ids = []
            for i in range(trials):
                token = f"KV-{4200 + i}"
                messages = [
                    {"role": "user", "content": f"Please remember this value: {token}."},
                    {"role": "assistant", "content": "Noted."},
                    {"role": "user", "content": "Briefly, what is 2+2?"},
                    {"role": "assistant", "content": "4."},
                    {"role": "user", "content": "What value did I ask you to remember? "
                                                "Restate it exactly."},
                ]
                probe = Probe(objective="multiturn_recall",
                              category=FindingCategory.LONG_CONTEXT,
                              payload={"messages": messages}, provenance=["identity"],
                              expectation={"mutation_notes":
                                           {"long_context_reference": {"anchor": token}}})
                res = t.send(probe)
                state.db.save_probe(state.assessment_id, probe)
                state.db.save_result(state.assessment_id, res)
                evidence_ids += [e.id for e in res.evidence]
                if token in res.text:
                    hits += 1
            rate = hits / trials
            obs = Observation(
                dimension="context_management", metric="multiturn_recall_rate",
                value=round(rate, 4), direction="higher_is_better",
                confidence=measurement_confidence(rate, trials,
                                                  dimension="context_management"),
                evidence_ids=evidence_ids,
                context={"target_id": t.id, "n": trials, "transforms": ["identity"]})
            state.observations.append(obs)
            state.db.save_observation(state.assessment_id, obs)
        state.db.commit()
        return state


class LongContextAgent(BaseAgent):
    name = "long_context"
    responsibilities = ("Systematic long-context sweep across fixed distances to "
                        "build a recall-vs-distance degradation curve.")
    inputs = ["targets", "seeds"]
    outputs = ["explanations"]

    def should_run(self, state):
        return any(t.kind in _MODEL_KINDS for t in state.targets)

    def _run(self, state):
        from ..mutation.transforms import LongContextReference

        seed = state.seeds[0] if state.seeds else Seed(text="Define defense in depth.")
        distances = [4, 10, 16, 22]
        for t in state.targets:
            if t.kind not in _MODEL_KINDS:
                continue
            curve = []
            for d in distances:
                lc = LongContextReference(filler_paragraphs=d)
                # Deterministic per (target, distance).
                import random as _r
                res_hits, trials = 0, 3
                for k in range(trials):
                    rng = _r.Random(hash((t.id, d, k)) & 0xFFFFFFFF)
                    mut = lc.apply(seed.text, rng)
                    probe = Probe(objective="long_context_curve",
                                  category=FindingCategory.LONG_CONTEXT,
                                  payload={"prompt": mut.text}, provenance=["long_context_reference"])
                    res = t.send(probe)
                    state.db.save_probe(state.assessment_id, probe)
                    state.db.save_result(state.assessment_id, res)
                    if mut.notes["anchor"] in res.text:
                        res_hits += 1
                curve.append({"distance": d, "recall": round(res_hits / trials, 3),
                              "n": trials})
            state.explanations.setdefault(t.id, {})["long_context_curve"] = curve
        state.db.commit()
        return state


class AdaptiveEvaluationAgent(BaseAgent):
    name = "adaptive_evaluation"
    responsibilities = ("Run the closed-loop adaptive evaluator per model/RAG "
                        "target; persist probes, responses, and observations.")
    inputs = ["targets", "seeds", "strategy"]
    outputs = ["evaluations", "observations", "metrics", "coverage"]

    def should_run(self, state):
        return any(t.kind in _MODEL_KINDS for t in state.targets)

    def confidence(self, state):
        covs = [e.coverage for e in state.evaluations.values()]
        if not covs:
            return Confidence(0.3, "no evaluations completed")
        return Confidence(sum(covs) / len(covs), "mean coverage across targets")

    def _run(self, state):
        aid = state.assessment_id
        for t in state.targets:
            if t.kind not in _MODEL_KINDS:
                continue
            mem = state.mem_for(t)
            engine = MutationEngine(seed=state.config.loop.seed)

            from ..evaluation.behavioral import ProbePair
            state.pairs.setdefault(t.id, [])

            def on_probe(probe, result, _tid=t.id):
                state.db.save_probe(aid, probe)
                state.db.save_result(aid, result)
                state.pairs[_tid].append(ProbePair(probe, result))

            evaluator = AdaptiveEvaluator(
                t, engine=engine, memory=mem, config=state.config.loop,
                on_probe=on_probe,
                progress=lambda k, d, _tid=t.id: state.bus.emit(
                    f"eval.{k}", "adaptive_evaluation", target=_tid,
                    **{kk: d.get(kk) for kk in ("round", "coverage")}))
            report = evaluator.run(state.seeds)
            state.evaluations[t.id] = report
            # Persist only the final, deduplicated observations (one per dimension).
            for obs in report.observations:
                obs.context.setdefault("target_id", t.id)
                state.observations.append(obs)
                state.db.save_observation(aid, obs)
            for name, val in report.metrics.items():
                state.db.save_metric(aid, name, val, t.id)
            # Seed baselines on first observation of this target family.
            mem.learn_baselines([o for o in report.observations])
        state.db.commit()
        self._merge_metrics(state)
        return state

    def _merge_metrics(self, state):
        # Roll up metrics + coverage across targets for the report.
        all_metrics: dict[str, list[float]] = {}
        covs, dim_conf = [], {}
        for rep in state.evaluations.values():
            for k, v in rep.metrics.items():
                all_metrics.setdefault(k, []).append(v)
            covs.append(rep.coverage)
            dim_conf.update(rep.dimension_confidence)
        state.metrics.update({k: round(sum(v) / len(v), 4)
                              for k, v in all_metrics.items()})
        state.coverage = {"mean": round(sum(covs) / len(covs), 4) if covs else 0.0,
                          "dimension_confidence": dim_conf}
