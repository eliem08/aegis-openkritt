"""Opt-in live gate for immutable Gitleaks and secret-safe normalization."""

from __future__ import annotations

import json
import os

import pytest

from aegis.adapters import EventKind, ExecutionEnvelope
from aegis.adapters.repository_scanners import GitleaksDocumentAdapter
from aegis.process import HardenedDockerCommandBuilder, ProcessLimits, SafeProcessRunner


@pytest.mark.skipif(
    os.environ.get("AEGIS_TEST_SCANNER_IMAGES") != "1",
    reason="set AEGIS_TEST_SCANNER_IMAGES=1 after pulling approved digest images",
)
def test_live_pinned_gitleaks_detects_but_never_emits_secret_value(tmp_path):
    repos = tmp_path / "repos"
    target = repos / "owner" / "synthetic"
    target.mkdir(parents=True)
    # Construct a documented, nonfunctional test signature at runtime so this
    # test module itself does not become a permanent secret-scanner finding.
    synthetic = "cafebabe" + ":" + "deadbeef"
    (target / "bundle.env").write_text(
        "BUNDLE_ENTERPRISE__CONTRIBSYS__COM=" + synthetic + "\n",
        encoding="utf-8",
    )
    adapter = GitleaksDocumentAdapter(HardenedDockerCommandBuilder(str(repos)))
    envelope = ExecutionEnvelope.for_manifest(
        adapter.manifest,
        tenant_id="lab", engagement_id="lab", scan_id="lab", stage_id="lab",
        task_id="lab", target=str(target), scope_digest="lab", idempotency_key="lab",
    )

    result = SafeProcessRunner().run(
        adapter.build_command(envelope),
        limits=ProcessLimits(
            wall_seconds=60, max_stdout_bytes=2_000_000, max_events=50_000,
        ),
    )
    events = adapter.parse_document("\n".join(result.lines), envelope)

    assert adapter.result_succeeded(result)
    candidates = [event for event in events if event.kind == EventKind.SECRET_CANDIDATE]
    assert len(candidates) == 1
    serialized = json.dumps(candidates[0].data)
    assert candidates[0].data["redacted"] is True
    assert synthetic not in serialized
    assert "BUNDLE_ENTERPRISE" not in serialized
