from __future__ import annotations

import pytest

from aegis.ai.jarvis.asset_capabilities import GRYPE, AssetKind
from aegis.ai.jarvis.asset_deep_capabilities import GHIDRA
from aegis.ai.jarvis.asset_execution_ticket import (
    AssetExecutionTicket,
    AssetExecutionTicketError,
    CapabilityAvailability,
    issue_offline_execution_ticket,
    verify_offline_execution_ticket,
)


def test_artifact_method_requires_authorized_artifact():
    with pytest.raises(AssetExecutionTicketError, match="authorized_artifact"):
        issue_offline_execution_ticket(
            asset_kind=AssetKind.EXECUTABLE,
            method=GRYPE,
            scope_digest="scope:1",
            availability=CapabilityAvailability(),
        )
    ticket = issue_offline_execution_ticket(
        asset_kind=AssetKind.EXECUTABLE,
        method=GRYPE,
        scope_digest="scope:1",
        availability=CapabilityAvailability(artifact_available=True),
    )
    assert ticket.requirements == ("authorized_artifact",)


def test_ghidra_requires_artifact_and_isolated_sandbox():
    with pytest.raises(AssetExecutionTicketError, match="isolated_sandbox"):
        issue_offline_execution_ticket(
            asset_kind=AssetKind.EXECUTABLE,
            method=GHIDRA,
            scope_digest="scope:1",
            availability=CapabilityAvailability(artifact_available=True),
        )
    ticket = issue_offline_execution_ticket(
        asset_kind=AssetKind.EXECUTABLE,
        method=GHIDRA,
        scope_digest="scope:1",
        availability=CapabilityAvailability(
            artifact_available=True,
            sandbox_available=True,
        ),
    )
    assert set(ticket.requirements) == {"authorized_artifact", "isolated_sandbox"}


def test_ticket_integrity_and_scope_are_checked():
    ticket = issue_offline_execution_ticket(
        asset_kind=AssetKind.EXECUTABLE,
        method=GRYPE,
        scope_digest="scope:1",
        availability=CapabilityAvailability(artifact_available=True),
    )
    verify_offline_execution_ticket(ticket, GRYPE, scope_digest="scope:1")
    with pytest.raises(AssetExecutionTicketError, match="scope digest mismatch"):
        verify_offline_execution_ticket(ticket, GRYPE, scope_digest="scope:2")

    tampered = AssetExecutionTicket(
        ticket_id=ticket.ticket_id,
        scope_digest=ticket.scope_digest,
        asset_kind=ticket.asset_kind,
        tool=ticket.tool,
        method=ticket.method,
        requirements=ticket.requirements + ("isolated_sandbox",),
        availability_digest=ticket.availability_digest,
        offline_only=ticket.offline_only,
    )
    with pytest.raises(AssetExecutionTicketError, match="integrity mismatch"):
        verify_offline_execution_ticket(tampered, GRYPE, scope_digest="scope:1")
