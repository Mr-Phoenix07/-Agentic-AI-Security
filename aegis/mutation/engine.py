"""Mutation engine — turns seed requests into reproducible probe variants.

The engine composes :class:`~aegis.mutation.transforms.Transform` objects into
pipelines, tracks the full provenance lineage of every variant, and deduplicates
by content hash so a robustness sweep is reproducible and auditable.

It is deliberately deterministic: given the same seeds, transforms, and RNG seed,
it emits the same probe set — a hard requirement for regression testing.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field

from ..core.types import FindingCategory, Probe, new_id, stable_hash
from .transforms import Transform, default_transforms


@dataclass
class Seed:
    """A benign, authorized seed request the sweep is built around."""

    id: str = field(default_factory=lambda: new_id("seed"))
    text: str = ""
    objective: str = ""                    # what behavioural dimension it targets
    category: FindingCategory = FindingCategory.ROBUSTNESS
    expectation: dict = field(default_factory=dict)


@dataclass
class Variant:
    text: str
    lineage: list[str]                     # ordered transform names applied
    notes: dict = field(default_factory=dict)
    seed_id: str = ""


class MutationEngine:
    """Compose transforms into reproducible, deduplicated probe variants."""

    def __init__(self, transforms: list[Transform] | None = None,
                 seed: int = 1337) -> None:
        self.transforms = transforms or default_transforms()
        self._by_name = {t.name: t for t in self.transforms}
        self.base_seed = seed

    # -- single & chained application -------------------------------------- #
    def _rng_for(self, *keys) -> random.Random:
        """A child RNG deterministically derived from base seed + keys."""
        h = stable_hash(self.base_seed, *keys)
        return random.Random(int(h, 16))

    def apply_chain(self, seed: Seed, names: list[str], salt: int = 0) -> Variant:
        """Apply a chain of transforms. ``salt`` yields fresh-but-reproducible
        draws (used by the adaptive loop to sample new variants each round).

        Unknown names (notably the ``"identity"`` control) are recorded in the
        lineage as pass-throughs, leaving the text unchanged.
        """
        text, lineage, notes = seed.text, [], {}
        for name in names:
            t = self._by_name.get(name)
            if t is None:                      # identity / pass-through control
                lineage.append(name)
                continue
            rng = self._rng_for(seed.id, name, len(lineage), salt)
            res = t.apply(text, rng)
            text = res.text
            lineage.append(name)
            if res.notes:
                notes[name] = res.notes
        return Variant(text=text, lineage=lineage, notes=notes, seed_id=seed.id)

    # -- sweep generation --------------------------------------------------- #
    def generate(
        self,
        seeds: list[Seed],
        *,
        max_depth: int = 2,
        per_seed: int = 12,
        include_identity: bool = True,
    ) -> list[Probe]:
        """Generate a deduplicated probe set from seeds.

        ``max_depth`` bounds how many transforms may be chained (composition
        depth). ``per_seed`` caps variants per seed. The identity (untouched)
        variant is included as a control baseline.
        """
        probes: list[Probe] = []
        seen: set[str] = set()

        for seed in seeds:
            # Control baseline first (measures native behaviour).
            if include_identity:
                probes.append(self._to_probe(seed, Variant(seed.text, ["identity"],
                                                            {}, seed.id)))
            # Deterministic ordering of candidate transform chains.
            rng = self._rng_for("plan", seed.id)
            chains = self._candidate_chains(rng, max_depth)
            count = 0
            for chain in chains:
                if count >= per_seed:
                    break
                variant = self.apply_chain(seed, chain)
                probe = self._to_probe(seed, variant)
                if probe.content_hash in seen:
                    continue
                seen.add(probe.content_hash)
                probes.append(probe)
                count += 1
        return probes

    def _candidate_chains(self, rng: random.Random, max_depth: int) -> list[list[str]]:
        names = [t.name for t in self.transforms]
        chains: list[list[str]] = [[n] for n in names]        # all singletons
        # A spread of reproducible multi-transform compositions.
        for _ in range(len(names)):
            depth = rng.randint(2, max(2, max_depth))
            chains.append([rng.choice(names) for _ in range(depth)])
        rng.shuffle(chains)
        return chains

    def build(self, seed: Seed, chains: list[list[str]], salt: int = 0) -> list[Probe]:
        """Build probes for an explicit list of transform chains (targeted mode).

        Used by the adaptive loop to focus follow-up rounds on specific
        behavioural dimensions, as opposed to the broad :meth:`generate` sweep.
        ``salt`` (e.g. the round index) draws fresh reproducible variants.
        """
        return [self._to_probe(seed, self.apply_chain(seed, chain, salt=salt))
                for chain in chains]

    def _to_probe(self, seed: Seed, variant: Variant) -> Probe:
        # Mutation notes (e.g. the injected long-context anchor) travel in
        # ``expectation`` so analyzers have ground truth, while ``content_hash``
        # stays a function of the *visible* payload only (dedup stability).
        return Probe(
            objective=seed.objective or "robustness/consistency measurement",
            category=seed.category,
            payload={"prompt": variant.text},
            provenance=variant.lineage,
            seed_id=seed.id,
            expectation={**dict(seed.expectation), "mutation_notes": variant.notes,
                         "seed_text": seed.text},
            tags=["mutation", *variant.lineage],
        )

    # -- reproducibility ---------------------------------------------------- #
    def coverage(self, probes: list[Probe]) -> dict[str, int]:
        """How many probes exercised each transform (transform coverage map)."""
        cov: dict[str, int] = {t.name: 0 for t in self.transforms}
        cov["identity"] = 0
        for p in probes:
            for name in p.provenance:
                cov[name] = cov.get(name, 0) + 1
        return cov
