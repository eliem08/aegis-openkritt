"""Evidence-verified fixture resume selection.

Resume is an optimization only.  It never manufactures a coverage record and never treats an
unverified ledger row as execution evidence.
"""

from __future__ import annotations

from collections.abc import Iterable

from .models import (
    ArsenalCoverageState,
    CapabilityCoverageRecord,
    HistoricalExecution,
)


def resumable_record(
    records: Iterable[CapabilityCoverageRecord],
    history: Iterable[HistoricalExecution],
    *,
    capability_id: str,
    tool_version: str,
    adapter_version: str,
    fixture_version: str,
) -> CapabilityCoverageRecord | None:
    """Return the newest compatible record whose immutable evidence still verifies."""
    verified = {
        (item.capability_id, item.evidence_digest)
        for item in history
        if not item.historical_evidence_invalid
        and item.state in {
            ArsenalCoverageState.EXECUTED_PASS,
            ArsenalCoverageState.EXECUTED_FINDING,
        }
    }
    candidates = [
        item for item in records
        if item.capability_id == capability_id
        and item.executed
        and not item.historical_evidence_invalid
        and item.result in {
            ArsenalCoverageState.EXECUTED_PASS,
            ArsenalCoverageState.EXECUTED_FINDING,
        }
        and item.tool_version == tool_version
        and item.adapter_version == adapter_version
        and item.fixture_version == fixture_version
        and bool(item.evidence_digest)
        and (item.capability_id, str(item.evidence_digest)) in verified
    ]
    if not candidates:
        return None
    return max(candidates, key=lambda item: (
        str(item.execution_timestamp or ""), item.coverage_record_id,
    ))


__all__ = ["resumable_record"]
