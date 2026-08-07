"""Private OAST service (Phase 4 §Private Interactsh integration).

The Aegis-side control plane for out-of-band interaction testing. It is *private*
by construction: in a production config the OAST domain may not be a known public
Interactsh server. Sessions are authenticated and tenant-bound; secret material
is held in a secrets service, never handed to the worker; interactions are stored
encrypted at rest and only become evidence once matched to an outstanding
authorized probe. Anything unmatched, cross-tenant, on a disabled protocol, or on
an inactive session is quarantined.
"""

from __future__ import annotations

import secrets as _secrets
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from aegis.api.crypto import Encryptor, NullEncryptor

from .models import (
    DEFAULT_ALLOWED_PROTOCOLS,
    Interaction,
    MatchedInteraction,
    OastRegistration,
    OastSession,
    ProbeToken,
    QuarantinedInteraction,
    QuarantineReason,
)

# Known public Interactsh-style servers; forbidden in a production config.
PUBLIC_OAST_SERVERS = frozenset({
    "oast.pro", "oast.live", "oast.site", "oast.fun", "oast.me", "oast.online",
    "interact.sh", "oastify.com", "oast.dev",
})


class OastError(RuntimeError):
    pass


class AuthenticationRequired(OastError):
    pass


class PublicOastRejected(OastError):
    pass


class SessionNotFound(OastError):
    pass


class SessionExpired(OastError):
    pass


class CrossTenantDenied(OastError):
    pass


class SecretsService:
    """A minimal stand-in for the real secrets manager (opaque ref -> value)."""

    def __init__(self) -> None:
        self._store: dict[str, dict] = {}

    def put(self, value: dict) -> str:
        ref = "vault://oast/" + uuid.uuid4().hex
        self._store[ref] = dict(value)
        return ref

    def get(self, ref: str) -> dict | None:
        return self._store.get(ref)

    def delete(self, ref: str) -> bool:
        return self._store.pop(ref, None) is not None


class PrivateOastConfig:
    def __init__(self, *, oast_domain: str, is_production: bool = True,
                 allowed_protocols: tuple[str, ...] = DEFAULT_ALLOWED_PROTOCOLS,
                 session_ttl_seconds: int = 3600, retention_seconds: int = 86400) -> None:
        self.oast_domain = oast_domain.strip().lower().rstrip(".")
        self.is_production = is_production
        self.allowed_protocols = tuple(allowed_protocols)
        self.session_ttl_seconds = session_ttl_seconds
        self.retention_seconds = retention_seconds

    def validate(self) -> None:
        if not self.oast_domain:
            raise PublicOastRejected("no private OAST domain configured")
        if self.is_production and _is_public(self.oast_domain):
            raise PublicOastRejected(
                f"{self.oast_domain!r} is a public OAST server; production requires a private one")


class PrivateOastService:
    def __init__(self, config: PrivateOastConfig, *, encryptor: Encryptor | None = None,
                 secrets: SecretsService | None = None,
                 clock: Callable[[], datetime] | None = None,
                 on_audit: Callable[[dict], None] | None = None) -> None:
        config.validate()                       # reject a public server up front
        self._config = config
        self._enc = encryptor or NullEncryptor()
        self._secrets = secrets or SecretsService()
        self._clock = clock or (lambda: datetime.now(UTC))
        self._on_audit = on_audit
        self._sessions: dict[str, OastSession] = {}      # session_ref -> session
        self._by_correlation: dict[str, str] = {}        # correlation_id -> session_ref
        self._matched: dict[str, list[tuple[MatchedInteraction, str]]] = {}  # ref -> [(m, ciphertext)]
        self._quarantined: list[QuarantinedInteraction] = []
        self._audit: list[dict] = []

    # -- registration -------------------------------------------------------

    def register(self, principal, *, engagement_id: str, scan_id: str, reservation_id: str,
                 allowed_protocols: tuple[str, ...] | None = None) -> OastRegistration:
        tenant = getattr(principal, "tenant_id", None)
        if not tenant:
            raise AuthenticationRequired("OAST registration requires an authenticated, tenant-bound principal")
        if not (engagement_id and scan_id and reservation_id):
            raise OastError("a session must be bound to an engagement, scan, and reservation")

        now = self._clock()
        correlation = _secrets.token_hex(10)          # unique per session
        nonce = _secrets.token_hex(16)                # unique nonce material
        # The interactsh session's secret/private key + token live in the secrets
        # service under an opaque ref — never in the session view or the worker.
        secret_ref = self._secrets.put({
            "secret_key": _secrets.token_hex(32), "token": _secrets.token_hex(24),
            "private_key": "-----BEGIN PRIVATE KEY-----(managed)-----END PRIVATE KEY-----",
        })
        protocols = tuple(allowed_protocols or self._config.allowed_protocols)
        # Only ever narrow to what the deployment allows.
        protocols = tuple(p for p in protocols if p in self._config.allowed_protocols)

        session = OastSession(
            session_id=uuid.uuid4().hex, tenant_id=tenant, engagement_id=engagement_id,
            scan_id=scan_id, reservation_id=reservation_id, correlation_id=correlation,
            interaction_domain=f"{correlation}.{self._config.oast_domain}", nonce=nonce,
            allowed_protocols=protocols, secret_ref=secret_ref, created_at=now,
            expires_at=now + timedelta(seconds=self._config.session_ttl_seconds),
        )
        self._sessions[session.session_id] = session
        self._by_correlation[correlation] = session.session_id
        self._matched[session.session_id] = []
        self._log("register", session_ref=session.session_id, tenant=tenant,
                  engagement=engagement_id, scan=scan_id)
        return OastRegistration(
            session_ref=session.session_id, interaction_domain=session.interaction_domain,
            correlation_id=correlation, allowed_protocols=protocols, expires_at=session.expires_at)

    def plant_probe(self, session_ref: str, principal) -> ProbeToken:
        """Register an outstanding authorized probe; return the callback address."""
        session = self._owned_active_session(session_ref, principal)
        token = _secrets.token_hex(8)
        address = f"{token}.{session.interaction_domain}"
        session.outstanding_probes.add(address)
        self._log("plant_probe", session_ref=session_ref, probe=address)
        return ProbeToken(probe_id=token, address=address, session_ref=session_ref)

    # -- ingestion ----------------------------------------------------------

    def ingest(self, interaction: Interaction) -> MatchedInteraction | QuarantinedInteraction:
        """Ingest a callback the OAST server saw. Stored encrypted either way."""
        now = self._clock()
        host = (interaction.host or "").strip().lower().rstrip(".")
        suffix = "." + self._config.oast_domain
        if not host.endswith(suffix):
            return self._quarantine(interaction, QuarantineReason.FOREIGN_HOST)

        correlation = host[: -len(suffix)].split(".")[-1]
        ref = self._by_correlation.get(correlation)
        session = self._sessions.get(ref) if ref else None
        if session is None:
            return self._quarantine(interaction, QuarantineReason.UNKNOWN_CORRELATION)
        if not session.is_active(now):
            return self._quarantine(interaction, QuarantineReason.SESSION_INACTIVE)
        if interaction.protocol not in session.allowed_protocols:
            return self._quarantine(interaction, QuarantineReason.PROTOCOL_NOT_ALLOWED)
        if host not in session.outstanding_probes:
            # Correlates to a real session, but no authorized probe planted it —
            # cannot become evidence.
            return self._quarantine(interaction, QuarantineReason.UNMATCHED_NO_PROBE)

        matched = MatchedInteraction(
            interaction_id=uuid.uuid4().hex, session_ref=session.session_id,
            protocol=interaction.protocol, host=host, remote_address=interaction.remote_address,
            observed_at=interaction.observed_at,
            probe_id=host[: -len("." + session.interaction_domain)],
        )
        ciphertext = self._enc.encrypt(interaction.raw)      # encrypted at rest
        self._matched[session.session_id].append((matched, ciphertext))
        session.last_used_at = now
        self._log("match", session_ref=session.session_id, protocol=interaction.protocol)
        return matched

    # -- polling ------------------------------------------------------------

    def poll(self, session_ref: str, principal) -> list[MatchedInteraction]:
        """Protected: only the owning tenant may poll its matched interactions."""
        session = self._owned_active_session(session_ref, principal)
        self._log("poll", session_ref=session_ref, count=len(self._matched[session.session_id]))
        return [m for m, _ct in self._matched[session.session_id]]

    def read_raw(self, session_ref: str, interaction_id: str, principal) -> str:
        """Decrypt one matched interaction for the owner (evidence assembly)."""
        session = self._owned_active_session(session_ref, principal)
        for matched, ciphertext in self._matched[session.session_id]:
            if matched.interaction_id == interaction_id:
                return self._enc.decrypt(ciphertext)
        raise SessionNotFound(interaction_id)

    def quarantined(self) -> list[QuarantinedInteraction]:
        """Operator-only view of quarantined interactions."""
        return list(self._quarantined)

    # -- lifecycle ----------------------------------------------------------

    def deregister(self, session_ref: str, principal) -> None:
        """Auditable deregistration: wipe secrets and mark the session deleted."""
        session = self._owned_session(session_ref, principal)
        self._secrets.delete(session.secret_ref)
        session.deleted_at = self._clock()
        session.outstanding_probes.clear()
        self._log("deregister", session_ref=session_ref, tenant=session.tenant_id)

    def purge_expired(self) -> int:
        """Drop sessions past their retention window (short retention)."""
        now = self._clock()
        cutoff = now - timedelta(seconds=self._config.retention_seconds)
        drop = [ref for ref, s in self._sessions.items()
                if s.expires_at < cutoff or (s.deleted_at and s.deleted_at < cutoff)]
        for ref in drop:
            session = self._sessions.pop(ref)
            self._by_correlation.pop(session.correlation_id, None)
            self._matched.pop(ref, None)
            self._secrets.delete(session.secret_ref)
        return len(drop)

    def audit_log(self) -> list[dict]:
        return list(self._audit)

    def session(self, session_ref: str) -> OastSession | None:
        return self._sessions.get(session_ref)

    # -- internals ----------------------------------------------------------

    def _owned_session(self, session_ref: str, principal) -> OastSession:
        session = self._sessions.get(session_ref)
        if session is None:
            raise SessionNotFound(session_ref)
        tenant = getattr(principal, "tenant_id", None)
        if not tenant:
            raise AuthenticationRequired("polling requires an authenticated principal")
        if tenant != session.tenant_id:
            raise CrossTenantDenied(f"principal tenant {tenant!r} may not access this session")
        return session

    def _owned_active_session(self, session_ref: str, principal) -> OastSession:
        session = self._owned_session(session_ref, principal)
        if not session.is_active(self._clock()):
            raise SessionExpired(session_ref)
        return session

    def _quarantine(self, interaction: Interaction, reason: QuarantineReason) -> QuarantinedInteraction:
        # Even quarantined callbacks rest encrypted; only metadata is exposed.
        self._enc.encrypt(interaction.raw)
        q = QuarantinedInteraction(
            quarantine_id=uuid.uuid4().hex, reason=reason.value, protocol=interaction.protocol,
            host=(interaction.host or "").lower(), observed_at=interaction.observed_at)
        self._quarantined.append(q)
        self._log("quarantine", reason=reason.value, host=q.host)
        return q

    def _log(self, action: str, **fields) -> None:
        event = {"action": action, "at": self._clock().isoformat(), **fields}
        self._audit.append(event)
        if self._on_audit is not None:
            self._on_audit(event)


def _is_public(domain: str) -> bool:
    domain = domain.lower().rstrip(".")
    return any(domain == pub or domain.endswith("." + pub) for pub in PUBLIC_OAST_SERVERS)
