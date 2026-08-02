"""Authentication-posture differential analysis (Phase 3 extension).

The single most common finding across real broken-access-control reports is *not*
"no auth anywhere" — it is **one sibling route left open while its twins enforce
auth**. The tell is in the status codes an unauthenticated probe gets back:

* ``401`` / ``403`` — an auth/authz gate is present and rejected us;
* ``400`` / ``422`` — the request reached business logic *without* an auth gate
  (the strongest "authentication was never evaluated" signal);
* ``200`` with a data body — the resource was served with no auth at all;
* ``404`` / ``410`` — genuinely absent.

This module classifies the postures of routes already probed during authorized
discovery and flags any whose posture is anomalous relative to their siblings in
the same API family — a candidate broken-access-control finding. Purely
analytical and read-only; it issues no traffic of its own, and a flag is a
candidate that still requires the detector's differential verification.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from aegis.detect.access_control import route_signature

# Path segments that make an unauthenticated 200 worth flagging on its own.
_SENSITIVE_SEGMENTS = (
    "account", "accounts", "order", "orders", "user", "users", "admin", "patient",
    "booking", "bookings", "invoice", "invoices", "payment", "payments", "profile",
    "customer", "customers", "subscriber", "directory", "record", "records", "kms",
    "driver", "drivers", "location", "gps", "nearby", "tracking", "guest", "guests",
    "lead", "leads", "quote", "quotes", "ticket", "tickets", "credential", "credentials",
    "secret", "secrets", "metrics", "identity", "student", "students", "traveller",
)
# Path families that are *expected* to be public and should not be flagged.
_PUBLIC_SEGMENTS = ("public", "health", "healthz", "status", "ping", "static", "assets", "docs")


class AuthPosture(str, Enum):
    ENFORCED = "enforced"                    # 401/403: an auth/authz gate rejected us
    UNAUTH_DATA = "unauth_data"              # 200 + body: served without auth
    UNAUTH_VALIDATION = "unauth_validation"  # 400/422: reached logic unauthenticated
    NOT_FOUND = "not_found"                  # 404/410
    UNKNOWN = "unknown"


def classify_posture(status: int, *, has_data: bool = True) -> AuthPosture:
    if status in (401, 403):
        return AuthPosture.ENFORCED
    if status in (400, 422):
        return AuthPosture.UNAUTH_VALIDATION
    if status in (404, 410):
        return AuthPosture.NOT_FOUND
    if 200 <= status < 300:
        return AuthPosture.UNAUTH_DATA if has_data else AuthPosture.UNKNOWN
    return AuthPosture.UNKNOWN


@dataclass(frozen=True)
class RouteAuthObservation:
    """An *unauthenticated* probe result for one route (from discovery)."""

    method: str
    path: str
    host: str
    status: int
    has_data: bool = True

    @property
    def posture(self) -> AuthPosture:
        return classify_posture(self.status, has_data=self.has_data)


@dataclass(frozen=True)
class AuthAnomaly:
    method: str
    path: str
    host: str
    posture: AuthPosture
    reason: str
    confidence: float
    siblings_enforcing: int


def analyze_auth_differential(observations) -> list[AuthAnomaly]:
    """Flag routes whose unauthenticated posture is anomalous vs. their siblings."""
    observations = list(observations)
    # Group into API families: same host + first path segment (e.g. all of /api/*).
    families: dict[tuple[str, str], list[RouteAuthObservation]] = {}
    for obs in observations:
        families.setdefault((obs.host, _family(obs.path)), []).append(obs)

    anomalies: list[AuthAnomaly] = []
    for members in families.values():
        enforcing = sum(1 for m in members if m.posture is AuthPosture.ENFORCED)
        for obs in members:
            anomaly = _assess(obs, enforcing)
            if anomaly is not None:
                anomalies.append(anomaly)
    anomalies.sort(key=lambda a: a.confidence, reverse=True)
    return anomalies


def _assess(obs: RouteAuthObservation, siblings_enforcing: int) -> AuthAnomaly | None:
    if _is_public(obs.path):
        return None
    posture = obs.posture
    if posture is AuthPosture.ENFORCED or posture in (AuthPosture.NOT_FOUND, AuthPosture.UNKNOWN):
        return None

    if siblings_enforcing > 0:
        # Siblings clearly enforce auth, but this one does not — the classic
        # "one route left open" pattern. A 400 (reached logic) is nearly as
        # damning as a 200 (served data): both prove no auth gate ran here.
        if posture is AuthPosture.UNAUTH_DATA:
            return AuthAnomaly(obs.method, obs.path, obs.host, posture,
                               "served data unauthenticated while sibling routes enforce auth",
                               0.85, siblings_enforcing)
        return AuthAnomaly(obs.method, obs.path, obs.host, posture,
                           "reached business logic unauthenticated (validation error, not 401) "
                           "while siblings enforce auth", 0.8, siblings_enforcing)

    # No enforcing siblings: only flag a standalone unauth 200 on a sensitive path.
    if posture is AuthPosture.UNAUTH_DATA and _is_sensitive(obs.path):
        return AuthAnomaly(obs.method, obs.path, obs.host, posture,
                           "sensitive resource served unauthenticated", 0.5, 0)
    return None


def _family(path: str) -> str:
    # Group by the first non-id path segment so sibling routes under the same API
    # root (/api/orders, /api/orders/{id}, /api/orders-feed) compare together, but
    # unrelated roots (/api/* vs /about) do not.
    sig = route_signature(path or "/")
    parts = [s for s in sig.split("/") if s and s != "*"]
    return parts[0] if parts else "/"


def _is_sensitive(path: str) -> bool:
    low = (path or "").lower()
    return any(seg in low for seg in _SENSITIVE_SEGMENTS)


def _is_public(path: str) -> bool:
    segs = [s.lower() for s in (path or "/").split("/") if s]
    return bool(segs) and segs[0] in _PUBLIC_SEGMENTS
