"""Session-loss monitoring (Phase 4 §Session-loss monitoring).

Authenticated coverage is only meaningful while the session holds. This monitor
captures baseline discriminators during preflight, re-checks them before dispatch
and periodically during long scans, and — when a session is lost — cancels pending
work **for that origin only**, marks its coverage incomplete, and refuses to keep
scanning the login page it now redirects to. Unrelated origins are never touched.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

DEFAULT_LOGIN_MARKERS = (
    "/login", "/signin", "/sign-in", "please sign in", "please log in",
    "session expired", "your session has ended", "log in to continue", "sign in to continue",
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class SessionBaseline:
    origin: str
    status: int
    authenticated_markers: tuple[str, ...]   # substrings present while authenticated
    captured_at: datetime


@dataclass(frozen=True)
class SessionCheck:
    origin: str
    lost: bool
    reason: str = ""


class SessionLossMonitor:
    def __init__(self, *, login_markers: tuple[str, ...] = DEFAULT_LOGIN_MARKERS) -> None:
        self._login_markers = tuple(m.lower() for m in login_markers)
        self._baselines: dict[str, SessionBaseline] = {}
        self._lost: dict[str, str] = {}                  # origin -> reason
        self._pending: dict[str, set[str]] = {}          # origin -> task ids

    # -- preflight ----------------------------------------------------------

    def capture(self, origin: str, *, status: int, body: str = "",
                marker_hints: tuple[str, ...] = ()) -> SessionBaseline:
        """Record what an authenticated response looks like for this origin."""
        body_l = (body or "").lower()
        markers = tuple(h for h in marker_hints if h and h.lower() in body_l)
        baseline = SessionBaseline(origin=origin, status=status,
                                   authenticated_markers=markers, captured_at=_now())
        self._baselines[origin] = baseline
        return baseline

    def register_pending(self, origin: str, task_id: str) -> None:
        self._pending.setdefault(origin, set()).add(task_id)

    # -- checks -------------------------------------------------------------

    def check(self, origin: str, *, status: int, body: str = "", location: str = "") -> SessionCheck:
        """Re-evaluate the session for one origin against its baseline."""
        if origin in self._lost:
            return SessionCheck(origin, True, self._lost[origin])   # stays lost

        haystack = f"{location} {body}".lower()
        reason = ""
        if status in (401, 403):
            reason = f"status {status}"
        elif any(m in haystack for m in self._login_markers):
            reason = "login page / auth redirect"
        else:
            baseline = self._baselines.get(origin)
            if baseline and baseline.authenticated_markers:
                body_l = (body or "").lower()
                if not all(m.lower() in body_l for m in baseline.authenticated_markers):
                    reason = "authenticated marker missing"

        if reason:
            self._mark_lost(origin, reason)
            return SessionCheck(origin, True, reason)
        return SessionCheck(origin, False)

    # -- state --------------------------------------------------------------

    def on_loss_cancel(self, origin: str) -> set[str]:
        """Pending task ids to cancel — only for a *lost* origin; others untouched."""
        if origin not in self._lost:
            return set()
        return set(self._pending.pop(origin, set()))

    def is_lost(self, origin: str) -> bool:
        return origin in self._lost

    def lost_origins(self) -> dict[str, str]:
        return dict(self._lost)

    def incomplete_coverage(self) -> set[str]:
        """Origins whose coverage is incomplete because their session was lost."""
        return set(self._lost)

    def _mark_lost(self, origin: str, reason: str) -> None:
        self._lost[origin] = reason
