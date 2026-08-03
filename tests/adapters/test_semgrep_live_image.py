"""Opt-in live gate for the immutable Semgrep image and Aegis-owned rules."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from aegis.adapters import EventKind, ExecutionEnvelope
from aegis.adapters.repository_scanners import SemgrepDocumentAdapter
from aegis.process import (
    HardenedDockerCommandBuilder,
    ProcessLimits,
    SafeProcessRunner,
    directory_sha256,
)


ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.skipif(
    os.environ.get("AEGIS_TEST_SCANNER_IMAGES") != "1",
    reason="set AEGIS_TEST_SCANNER_IMAGES=1 after pulling approved digest images",
)
def test_live_pinned_semgrep_finds_only_seeded_positive_controls():
    repo_root = ROOT / "tests" / "labs" / "repository_scanners"
    target = repo_root / "semgrep_target"
    approved_root = ROOT / "config" / "scanners" / "semgrep"
    rules = approved_root / "rules"
    adapter = SemgrepDocumentAdapter(
        HardenedDockerCommandBuilder(
            str(repo_root), approved_mount_roots=(str(approved_root),),
        ),
        rules_path=str(rules),
        rules_digest=directory_sha256(rules),
    )
    envelope = ExecutionEnvelope.for_manifest(
        adapter.manifest,
        tenant_id="lab", engagement_id="lab", scan_id="lab", stage_id="lab",
        task_id="lab", target=str(target), scope_digest="lab", idempotency_key="lab",
    )

    result = SafeProcessRunner().run(
        adapter.build_command(envelope),
        limits=ProcessLimits(
            wall_seconds=90, max_stdout_bytes=4_000_000, max_events=50_000,
        ),
    )
    events = adapter.parse_document("\n".join(result.lines), envelope)

    assert adapter.result_succeeded(result)
    assert not [event for event in events if event.kind == EventKind.DIAGNOSTIC]
    findings = {
        (event.data["rule_id"].removeprefix("rules."), event.data["path"])
        for event in events if event.kind == EventKind.FINDING
    }
    assert findings == {
        ("aegis.python.flask-command-injection", "vulnerable.py"),
        ("aegis.python.flask-ssrf", "vulnerable.py"),
        ("aegis.python.flask-sql-injection", "vulnerable.py"),
    }
