"""Whole-document adapter compatibility and fail-closed behavior."""

from __future__ import annotations

import sys
from datetime import datetime, timezone

from aegis.adapters import (
    AdapterManifest,
    CapabilityTier,
    EventKind,
    JsonDocumentAdapter,
    SchemaMismatch,
)
from aegis.api.persistence import SqliteRepository
from aegis.api.reservations import ReservationService
from aegis.api.store import EngagementRecord
from aegis.scheduler import ScanConfig, ScanCoordinator, StageSpec, TaskSpec


class DocumentFixtureAdapter(JsonDocumentAdapter):
    manifest = AdapterManifest(
        name="document-fixture",
        version="1.0.0",
        executable_digest="fixture-digest",
        license="MIT",
        capability_tier=CapabilityTier.PASSIVE_DISCOVERY.value,
        input_schema_version=1,
        output_schema_version=1,
        network_profile="passive-provider",
    )

    def __init__(self, payload: str) -> None:
        super().__init__(allow_unpinned=True)
        self.payload = payload
        self.documents_seen = 0

    def build_command(self, envelope):
        return [sys.executable, "-c", f"print({self.payload!r})"]

    def map_document(self, root, envelope):
        self.documents_seen += 1
        if not isinstance(root, dict) or not isinstance(root.get("results"), list):
            raise SchemaMismatch("document results must be an array")
        return [
            (EventKind.FINDING, {"rule_id": item["rule_id"], "verified": False}, 0.5)
            for item in root["results"]
        ]


def _coordinator(tmp_path, adapter):
    repo = SqliteRepository(str(tmp_path / "document-adapter.db"))
    repo.save_engagement(EngagementRecord(
        id="eng-doc", authorization={"customer_id": "tenant-doc"}, status="active",
        created_at=datetime.now(timezone.utc),
    ))
    coord = ScanCoordinator(
        repository=repo,
        reservations=ReservationService(repo),
        adapters={adapter.manifest.name: adapter},
        config=ScanConfig(
            tenant_id="tenant-doc", engagement_id="eng-doc",
            scope_targets=("repo.example.test",), session_cap=1,
        ),
    )
    scan_id = coord.plan_scan(
        [StageSpec("source", "source-analysis")],
        [TaskSpec(adapter.manifest.name, "repo.example.test", "source")],
    )
    return repo, coord, scan_id


def test_document_adapter_parses_once_after_bounded_process_completion(tmp_path):
    adapter = DocumentFixtureAdapter('{\n  "results": [{"rule_id": "unsafe-call"}]\n}')
    repo, coord, scan_id = _coordinator(tmp_path, adapter)

    result = coord.run_next(scan_id)

    assert result is not None and result.outcome == "succeeded"
    assert result.events == 2  # finding plus coordinator-provided terminal event
    assert adapter.documents_seen == 1
    assert repo.tasks_for_scan(scan_id)[0].status == "succeeded"


def test_malformed_document_is_quarantined_without_raw_output(tmp_path):
    adapter = DocumentFixtureAdapter("not-json")
    repo, coord, scan_id = _coordinator(tmp_path, adapter)

    result = coord.run_next(scan_id)

    assert result is not None and result.outcome == "quarantined"
    assert "blocking parser diagnostic" in result.reason
    task = repo.tasks_for_scan(scan_id)[0]
    assert task.status == "quarantined"
    summary = task.result_summary
    assert "not-json" not in str(summary)
