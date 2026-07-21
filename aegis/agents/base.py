"""Base agent contract.

Every AEGIS agent declares — per the platform specification — its
responsibilities, inputs, outputs, communication protocol, confidence estimation,
and stopping conditions. :class:`BaseAgent` encodes those as a uniform lifecycle:

    should_run(state) -> gate (stopping condition)
    _run(state)       -> the work (agent-specific)
    confidence(state) -> self-assessed confidence in this run's output
    run(state)        -> wraps the above with tracing, logging, and bus events

Agents communicate two ways: directly, by reading/writing declared keys on the
shared :class:`~aegis.graph.state.AssessmentState`; and indirectly, by publishing
:class:`~aegis.core.events.Message` events on the bus (audit + loose coupling).
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from ..core.confidence import Confidence
from ..core.events import Message
from ..graph.state import AssessmentState


class BaseAgent(ABC):
    #: unique agent id / bus sender name
    name: str = "agent"
    #: one-line description of what this agent is responsible for
    responsibilities: str = ""
    #: state keys read / written (documentation + scheduler hints)
    inputs: list[str] = []
    outputs: list[str] = []

    def should_run(self, state: AssessmentState) -> bool:
        """Stopping / gating condition. Default: always run."""
        return True

    @abstractmethod
    def _run(self, state: AssessmentState) -> AssessmentState: ...

    def confidence(self, state: AssessmentState) -> Confidence:
        """Self-assessed confidence in this agent's output. Override as needed."""
        return Confidence(0.7, f"{self.name} completed nominally")

    # -- lifecycle ---------------------------------------------------------- #
    def run(self, state: AssessmentState) -> AssessmentState:
        log = state.logger.bind(agent=self.name)
        if not self.should_run(state):
            log.info("agent.skip", f"{self.name} gated out")
            state.bus.publish(Message(f"agent.{self.name}.skipped", self.name))
            return state
        state.bus.publish(Message(f"agent.{self.name}.start", self.name))
        with state.tracer.span(f"agent:{self.name}"):
            try:
                state = self._run(state)
                conf = self.confidence(state)
                state.trail.append(self.name)
                log.info("agent.done", f"{self.name} done",
                         confidence=round(conf.value, 3))
                state.bus.publish(Message(f"agent.{self.name}.done", self.name,
                                          {"confidence": conf.value}))
            except Exception as e:  # keep the pipeline resilient; record + continue
                state.errors.append({"agent": self.name, "error": f"{type(e).__name__}: {e}"})
                log.error("agent.error", f"{self.name} failed: {e}")
                state.bus.publish(Message(f"agent.{self.name}.error", self.name,
                                          {"error": str(e)}))
        return state
