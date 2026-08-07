"""Atomic policy reservations (Master Prompt §3 invariant; Phase 1 correction).

Fixes the authorize→commit overbooking race: instead of a non-mutating check
followed by a separate debit (two concurrent requests could both pass the check
and both debit), a reservation atomically claims spend + a concurrent session
slot against the authorization's caps in a single DB transaction. Finalization
records actual consumption and releases the remainder; it is idempotent and
happens at most once. Cancellation/expiration releases the claim.

Requires a durable repository (SQLite/Postgres). In-memory mode keeps the older
budget path (single-process, non-atomic) — production must use a database.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from .store import PolicyReservation


class ReservationError(RuntimeError):
    pass


class ReservationService:
    def __init__(self, repository) -> None:
        if repository is None:
            raise ReservationError("atomic reservations require a durable repository")
        self._repo = repository

    def reserve(
        self,
        engagement,
        *,
        spend: float = 0.0,
        sessions: int = 1,
        idempotency_key: str,
        ttl_seconds: int = 3600,
        consume_approval: tuple[str, str] | None = None,
    ) -> PolicyReservation | None:
        """Atomically reserve ``spend`` + ``sessions`` for the engagement.

        Returns the reservation, or ``None`` if it would exceed a cap. The same
        ``idempotency_key`` returns the existing reservation without double-charging.

        ``consume_approval`` is an ``(action, target)`` pair: when given, the claim
        also **burns a single-use approval** for that action/target inside the same
        transaction, and fails closed (returns ``None``) if none is consumable — so
        two concurrent reservations can never both spend one single-use token.
        """
        if spend < 0 or sessions < 0:
            raise ReservationError("spend and sessions must be >= 0")
        auth = engagement.authorization
        spend_cap = auth.spend_budget  # None == unlimited
        session_cap = auth.rate_limits.max_concurrent_sessions
        expires_at = datetime.now(UTC) + timedelta(seconds=ttl_seconds)
        if consume_approval is not None:
            from .store import _safe_host

            action, target = consume_approval
            consume_approval = (action, _safe_host(target))  # match how grants store the host
        return self._repo.reserve(
            engagement.id,
            spend=spend,
            sessions=sessions,
            spend_cap=spend_cap,
            session_cap=session_cap,
            idempotency_key=idempotency_key,
            expires_at=expires_at,
            consume_approval=consume_approval,
        )

    def finalize(self, reservation_id: str, actual_spend: float = 0.0) -> PolicyReservation | None:
        return self._repo.finalize(reservation_id, actual_spend)

    def release(self, reservation_id: str) -> PolicyReservation | None:
        return self._repo.release(reservation_id)

    def usage(self, engagement_id: str) -> tuple[float, int]:
        return self._repo.reservation_usage(engagement_id)
