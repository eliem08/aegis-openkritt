"""Private OAST models (Phase 4 §Private Interactsh integration).

An OAST *session* belongs to exactly one tenant/engagement/scan/reservation and
carries only non-secret correlation material. Secret keys and tokens never live
here — they go to the secrets service, and the worker receives only an
``interaction_domain`` plus an opaque ``session_ref``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class Protocol(str, Enum):
    DNS = "dns"
    HTTPS = "https"
    HTTP = "http"
    SMTP = "smtp"        # disabled until separately threat-modeled + authorized
    LDAP = "ldap"
    SMB = "smb"


# Only these are on by default; the rest require explicit authorization.
DEFAULT_ALLOWED_PROTOCOLS = (Protocol.DNS.value, Protocol.HTTPS.value)


class QuarantineReason(str, Enum):
    FOREIGN_HOST = "foreign_host"                 # not under our OAST domain
    UNKNOWN_CORRELATION = "unknown_correlation"   # no session owns it
    SESSION_INACTIVE = "session_inactive"         # expired/deleted
    PROTOCOL_NOT_ALLOWED = "protocol_not_allowed"
    UNMATCHED_NO_PROBE = "unmatched_no_probe"      # no outstanding authorized probe


@dataclass
class OastSession:
    """Server-side session record. Secret material is referenced, never inlined."""

    session_id: str                # opaque session_ref handed to the worker
    tenant_id: str
    engagement_id: str
    scan_id: str
    reservation_id: str
    correlation_id: str            # label that routes interactions to this session
    interaction_domain: str        # the address the worker plants under
    nonce: str
    allowed_protocols: tuple[str, ...]
    secret_ref: str                # points into the secrets service; never a value
    created_at: datetime
    expires_at: datetime
    last_used_at: datetime | None = None
    deleted_at: datetime | None = None
    outstanding_probes: set[str] = field(default_factory=set)   # authorized probe hosts

    def is_active(self, now: datetime) -> bool:
        return self.deleted_at is None and now < self.expires_at


@dataclass(frozen=True)
class OastRegistration:
    """What the worker receives — an address and an opaque reference, no secrets."""

    session_ref: str
    interaction_domain: str
    correlation_id: str
    allowed_protocols: tuple[str, ...]
    expires_at: datetime


@dataclass(frozen=True)
class ProbeToken:
    """An outstanding authorized probe: a unique address the worker will inject."""

    probe_id: str
    address: str                   # full host the target should call back
    session_ref: str


@dataclass(frozen=True)
class Interaction:
    """A callback the OAST server observed (raw is encrypted before it rests)."""

    protocol: str
    host: str
    remote_address: str
    raw: str
    observed_at: datetime
    unique_id: str = ""


@dataclass(frozen=True)
class MatchedInteraction:
    interaction_id: str
    session_ref: str
    protocol: str
    host: str
    remote_address: str
    observed_at: datetime
    probe_id: str


@dataclass(frozen=True)
class QuarantinedInteraction:
    quarantine_id: str
    reason: str
    protocol: str
    host: str
    observed_at: datetime
