"""Atomic in-process reservation semantics shared by durable budget backends."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from decimal import Decimal


class ModelBudgetError(RuntimeError):
    pass


@dataclass(frozen=True)
class CostReservation:
    reservation_id: str
    tenant_id: str
    cycle_id: str
    day: str
    reserved: Decimal
    actual: Decimal | None = None
    state: str = "reserved"


class AtomicModelBudget:
    """Reference implementation; production uses the same contract over Redis."""

    def __init__(
        self,
        *,
        cycle_limit: Decimal = Decimal(2),
        daily_limit: Decimal = Decimal(10),
    ) -> None:
        if cycle_limit < 0 or daily_limit < 0:
            raise ValueError("model budget limits cannot be negative")
        self._cycle_limit = cycle_limit
        self._daily_limit = daily_limit
        self._cycle: dict[tuple[str, str], Decimal] = {}
        self._daily: dict[tuple[str, str], Decimal] = {}
        self._reservations: dict[str, CostReservation] = {}
        self._lock = threading.Lock()

    def reserve(
        self,
        reservation_id: str,
        *,
        tenant_id: str,
        cycle_id: str,
        day: str,
        maximum: Decimal,
    ) -> CostReservation:
        if not reservation_id or maximum < 0:
            raise ValueError("invalid model cost reservation")
        with self._lock:
            existing = self._reservations.get(reservation_id)
            if existing is not None:
                if (
                    existing.tenant_id != tenant_id
                    or existing.cycle_id != cycle_id
                    or existing.day != day
                    or existing.reserved != maximum
                ):
                    raise ModelBudgetError("reservation_conflict")
                return existing
            cycle_key = (tenant_id, cycle_id)
            day_key = (tenant_id, day)
            if self._cycle.get(cycle_key, Decimal(0)) + maximum > self._cycle_limit:
                raise ModelBudgetError("cycle_budget_exhausted")
            if self._daily.get(day_key, Decimal(0)) + maximum > self._daily_limit:
                raise ModelBudgetError("daily_budget_exhausted")
            reservation = CostReservation(
                reservation_id, tenant_id, cycle_id, day, maximum,
            )
            self._reservations[reservation_id] = reservation
            self._cycle[cycle_key] = self._cycle.get(cycle_key, Decimal(0)) + maximum
            self._daily[day_key] = self._daily.get(day_key, Decimal(0)) + maximum
            return reservation

    def finalize(
        self, reservation_id: str, actual: Decimal, *, tenant_id: str | None = None,
    ) -> CostReservation:
        if actual < 0:
            raise ValueError("actual model cost cannot be negative")
        with self._lock:
            reservation = self._reservations.get(reservation_id)
            if reservation is None:
                raise ModelBudgetError("reservation_missing")
            if reservation.state == "finalized":
                if reservation.actual != actual:
                    raise ModelBudgetError("finalize_conflict")
                return reservation
            if actual > reservation.reserved:
                raise ModelBudgetError("actual_exceeds_reservation")
            release = reservation.reserved - actual
            cycle_key = (reservation.tenant_id, reservation.cycle_id)
            day_key = (reservation.tenant_id, reservation.day)
            self._cycle[cycle_key] -= release
            self._daily[day_key] -= release
            finalized = CostReservation(
                **{**reservation.__dict__, "actual": actual, "state": "finalized"}
            )
            self._reservations[reservation_id] = finalized
            return finalized

    def release(
        self, reservation_id: str, *, tenant_id: str | None = None,
    ) -> CostReservation:
        return self.finalize(reservation_id, Decimal(0), tenant_id=tenant_id)

    def spent(self, tenant_id: str, *, cycle_id: str | None = None, day: str | None = None):
        with self._lock:
            if cycle_id is not None:
                return self._cycle.get((tenant_id, cycle_id), Decimal(0))
            if day is not None:
                return self._daily.get((tenant_id, day), Decimal(0))
            raise ValueError("cycle_id or day is required")
