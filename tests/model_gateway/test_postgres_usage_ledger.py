from contextlib import nullcontext
from decimal import Decimal

import pytest

from aegis.model_gateway.budget import ModelBudgetError
from aegis.model_gateway.ledger import PostgresModelUsageLedger
from aegis.model_gateway.models import ModelUsage


class MemoryPostgres:
    """Contract fake preserving the INSERT/UPDATE conflict behavior used by the ledger."""

    def __init__(self):
        self.rows = {}
        self.result = None

    def connection(self):
        return nullcontext(self)

    def cursor(self):
        return nullcontext(self)

    def execute(self, sql, params=()):
        normalized = " ".join(sql.split())
        if normalized.startswith("CREATE TABLE"):
            return
        if normalized.startswith("INSERT INTO model_usage_reservations"):
            if params[0] not in self.rows:
                self.rows[params[0]] = [
                    params[0], params[1], params[2], params[3], params[4], params[5],
                    params[6], params[7], None, "reserved",
                ]
            return
        if normalized.startswith("SELECT reservation_id"):
            self.result = self.rows.get(params[0])
            return
        if normalized.startswith("UPDATE model_usage_reservations"):
            row = self.rows.get(params[6])
            if row is not None and row[9] == "reserved":
                row[8] = params[0]
                row[9] = "finalized"
            return
        raise AssertionError(f"unexpected SQL: {normalized}")

    def fetchone(self):
        return self.result


def reserve(ledger, reservation_id="r", tenant="tenant", maximum=Decimal("0.8")):
    return ledger.reserve(
        reservation_id, tenant_id=tenant, engagement_id="engagement", cycle_id="cycle",
        day="2026-08-03", model="deepseek-v4-flash", price_version="2026-08-03",
        maximum=maximum,
    )


def test_postgres_usage_reservation_and_finalize_are_idempotent():
    ledger = PostgresModelUsageLedger(MemoryPostgres())
    assert reserve(ledger) == reserve(ledger)
    usage = ModelUsage(prompt_tokens=100, completion_tokens=10, total_tokens=110)
    first = ledger.finalize(
        "r", Decimal("0.2"), usage=usage, provider_request_id="provider-request",
    )
    second = ledger.finalize(
        "r", Decimal("0.2"), usage=usage, provider_request_id="provider-request",
    )
    assert first == second
    assert first.state == "finalized"
    assert first.actual == Decimal("0.2")


def test_postgres_usage_reservation_and_finalize_conflicts_fail_closed():
    ledger = PostgresModelUsageLedger(MemoryPostgres())
    reserve(ledger)
    with pytest.raises(ModelBudgetError, match="usage_reservation_conflict"):
        reserve(ledger, tenant="other")
    usage = ModelUsage()
    ledger.finalize("r", Decimal("0.2"), usage=usage, provider_request_id="request")
    with pytest.raises(ModelBudgetError, match="usage_finalize_conflict"):
        ledger.finalize("r", Decimal("0.3"), usage=usage, provider_request_id="request")
