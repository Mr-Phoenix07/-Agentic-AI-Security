"""In-process message bus and agent communication protocol.

Agents in AEGIS collaborate by exchanging typed :class:`Message` objects over a
lightweight, synchronous, topic-based :class:`MessageBus`. This keeps the
reference implementation dependency-free and deterministic (important for
reproducibility) while mirroring the semantics of a real broker (subjects,
correlation ids, blackboard reads). Swapping in Redis/NATS/Kafka later only
requires reimplementing :class:`MessageBus`.
"""

from __future__ import annotations

import fnmatch
from collections import defaultdict, deque
from collections.abc import Callable
from dataclasses import dataclass, field

from .types import new_id, now_ts


@dataclass
class Message:
    """The unit of inter-agent communication.

    Subjects use dotted namespaces, e.g. ``plan.created``, ``probe.result``,
    ``finding.raised``. Subscribers may use glob patterns (``probe.*``).
    """

    subject: str
    sender: str = "system"
    payload: dict = field(default_factory=dict)
    id: str = field(default_factory=lambda: new_id("msg"))
    correlation_id: str | None = None    # ties a request to its responses
    ts: float = field(default_factory=now_ts)


Handler = Callable[[Message], None]


class MessageBus:
    """Synchronous publish/subscribe bus with a durable event log.

    The event log doubles as an audit trail and as a shared *blackboard* that
    late-joining agents can replay.
    """

    def __init__(self, keep_log: int = 5000) -> None:
        self._subs: dict[str, list[Handler]] = defaultdict(list)
        self._log: deque[Message] = deque(maxlen=keep_log)

    def subscribe(self, subject_glob: str, handler: Handler) -> None:
        self._subs[subject_glob].append(handler)

    def publish(self, message: Message) -> None:
        self._log.append(message)
        for pattern, handlers in list(self._subs.items()):
            if fnmatch.fnmatch(message.subject, pattern):
                for h in handlers:
                    h(message)

    def emit(self, subject: str, sender: str = "system", **payload) -> Message:
        msg = Message(subject=subject, sender=sender, payload=payload)
        self.publish(msg)
        return msg

    def history(self, subject_glob: str = "*", limit: int = 200) -> list[Message]:
        out = [m for m in self._log if fnmatch.fnmatch(m.subject, subject_glob)]
        return out[-limit:]
