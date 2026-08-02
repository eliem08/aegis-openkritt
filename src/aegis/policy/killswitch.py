"""Kill switch (Master Prompt §8, §13).

A pause/stop signal, a failed target health check, or a latency/error spike
overrides any in-progress plan. When the switch is fired the engine denies
*every* action until it is explicitly reset by a human/control-plane action.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class KillSwitchState:
    fired: bool = False
    reason: str | None = None
    fired_at: datetime | None = None
    source: str | None = None


class KillSwitch:
    """Thread-safe latch. Once fired it stays fired until ``reset``."""

    def __init__(self) -> None:
        self._state = KillSwitchState()
        self._lock = threading.Lock()

    def fire(self, reason: str, source: str = "control-plane") -> None:
        with self._lock:
            if not self._state.fired:
                self._state = KillSwitchState(
                    fired=True, reason=reason, fired_at=_utcnow(), source=source
                )

    def reset(self, source: str = "control-plane") -> None:
        """Clear the latch. Should only ever be called by a human / control plane."""
        with self._lock:
            self._state = KillSwitchState()

    @property
    def is_active(self) -> bool:
        return self._state.fired

    @property
    def state(self) -> KillSwitchState:
        return self._state
