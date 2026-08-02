"""Kill switch (Master Prompt §8, §13).

A pause/stop signal, a failed target health check, or a latency/error spike
overrides any in-progress plan. When the switch is fired the engine denies
*every* action until it is explicitly reset by a human/control-plane action.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class KillSwitchState:
    fired: bool = False
    reason: str | None = None
    fired_at: datetime | None = None
    source: str | None = None


class KillSwitch:
    """Thread-safe latch. Once fired it stays fired until ``reset``.

    ``on_change`` is a generic callback (state) fired after a change — the store
    wires it to persist the state so a fired switch survives a restart. Policy
    stays free of any persistence dependency.
    """

    def __init__(self, on_change: Callable[[KillSwitchState], None] | None = None) -> None:
        self._state = KillSwitchState()
        self._lock = threading.Lock()
        self._on_change = on_change

    def fire(self, reason: str, source: str = "control-plane") -> None:
        changed = False
        with self._lock:
            if not self._state.fired:
                self._state = KillSwitchState(
                    fired=True, reason=reason, fired_at=_utcnow(), source=source
                )
                changed = True
        if changed and self._on_change is not None:
            self._on_change(self._state)

    def reset(self, source: str = "control-plane") -> None:
        """Clear the latch. Should only ever be called by a human / control plane."""
        with self._lock:
            self._state = KillSwitchState()
        if self._on_change is not None:
            self._on_change(self._state)

    def restore(self, state: KillSwitchState) -> None:
        """Rehydrate persisted state (used by the store on load)."""
        with self._lock:
            self._state = state

    @property
    def is_active(self) -> bool:
        return self._state.fired

    @property
    def state(self) -> KillSwitchState:
        return self._state
