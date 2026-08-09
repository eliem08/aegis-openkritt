from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from aegis.ai.jarvis.asset_cli_executor import CliProcessResult
from aegis.ai.jarvis.firmware_execution import cleanup_safe_archive
from aegis.ai.jarvis.rootfs_followup import (
    ROOTFS_GRYPE,
    ROOTFS_SYFT,
    RootfsFollowupError,
    execute_rootfs_followup,
    issue_rootfs_followup_ticket,
)
from aegis.ai.jarvis.safe_archive import extract_safe_archive
from aegis.ai.tool_runtime import ToolRuntimeManager


def _extraction(tmp_path):
    archive = tmp_path / "firmware.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as bundle:
        bundle.writestr("etc/os-release", "NAME=DemoOS\nVERSION=1\n")
        bundle.writestr("usr/bin/demo", b"binary")
    return extract_safe_archive(archive, workspace_root=tmp_path / "rootfs-work")


def _manager(tmp_path, tool):
    binary = tmp_path / tool
    binary.write_bytes(tool.encode())
    return ToolRuntimeManager(
        resolver=lambda name: str(binary) if name == tool else None,
        runner=lambda argv, timeout: (0, f"{tool} 1.0", ""),
    ), binary


def test_grype_rootfs_ticket_runs_exact_derived_tree_and_normalizes_candidate(tmp_path):
    extraction = _extraction(tmp_path)
    manager, binary = _manager(tmp_path, "grype")
    payload = {
        "matches": [
            {
                "vulnerability": {
                    "id": "CVE-2099-1000",
                    "severity": "High",
                    "description": "demo package vulnerability",
                },
                "artifact": {
                    "name": "demo",
                    "version": "1",
                    "locations": [{"path": "/usr/bin/demo"}],
                },
            }
        ]
    }
    calls = []

    def runner(argv, workspace, timeout, env, maximum_output_bytes):
        calls.append(argv)
        return CliProcessResult(0, json.dumps(payload).encode(), b"")

    try:
        ticket = issue_rootfs_followup_ticket(
            extraction, ROOTFS_GRYPE, scope_digest="scope:rootfs"
        )
        outcome = execute_rootfs_followup(
            extraction,
            ROOTFS_GRYPE,
            ticket=ticket,
            scope_digest="scope:rootfs",
            runtime_manager=manager,
            pins={},
            runner=runner,
        )
        assert calls[0][0] == str(binary.resolve())
        assert calls[0][1] == f"dir:{Path(extraction.root).resolve()}"
        assert len(outcome.candidates) == 1
        assert outcome.candidates[0]["validation_status"] == "unverified"
        assert outcome.provenance["execution_ticket"] == ticket.ticket_id
        assert outcome.provenance["derived_rootfs_digest"] == ticket.availability_digest
        assert outcome.provenance["source_archive_sha256"] == extraction.archive_sha256
    finally:
        cleanup_safe_archive(extraction)


def test_syft_rootfs_followup_is_inventory_observation_not_vulnerability(tmp_path):
    extraction = _extraction(tmp_path)
    manager, _binary = _manager(tmp_path, "syft")
    payload = {"artifacts": [{"name": "demo"}], "source": {"type": "directory"}}

    try:
        ticket = issue_rootfs_followup_ticket(
            extraction, ROOTFS_SYFT, scope_digest="scope:rootfs"
        )
        outcome = execute_rootfs_followup(
            extraction,
            ROOTFS_SYFT,
            ticket=ticket,
            scope_digest="scope:rootfs",
            runtime_manager=manager,
            pins={},
            runner=lambda argv, workspace, timeout, env, maximum_output_bytes: CliProcessResult(
                0, json.dumps(payload).encode(), b""
            ),
        )
        assert outcome.candidates == ()
        assert outcome.observations[0].kind == "sbom_inventory"
        assert outcome.observations[0].data["packages"] == 1
    finally:
        cleanup_safe_archive(extraction)


def test_rootfs_ticket_cannot_be_reused_for_a_different_scanner(tmp_path):
    extraction = _extraction(tmp_path)
    try:
        ticket = issue_rootfs_followup_ticket(
            extraction, ROOTFS_GRYPE, scope_digest="scope:rootfs"
        )
        with pytest.raises(RootfsFollowupError, match="method mismatch"):
            execute_rootfs_followup(
                extraction,
                ROOTFS_SYFT,
                ticket=ticket,
                scope_digest="scope:rootfs",
            )
    finally:
        cleanup_safe_archive(extraction)


def test_file_mutation_after_ticket_issuance_blocks_before_runner(tmp_path):
    extraction = _extraction(tmp_path)
    manager, _binary = _manager(tmp_path, "grype")
    calls = []
    try:
        ticket = issue_rootfs_followup_ticket(
            extraction, ROOTFS_GRYPE, scope_digest="scope:rootfs"
        )
        (Path(extraction.root) / "etc/os-release").write_text("tampered", encoding="utf-8")
        with pytest.raises(RootfsFollowupError, match="integrity changed"):
            execute_rootfs_followup(
                extraction,
                ROOTFS_GRYPE,
                ticket=ticket,
                scope_digest="scope:rootfs",
                runtime_manager=manager,
                pins={},
                runner=lambda *args: calls.append(args) or CliProcessResult(0),
            )
        assert calls == []
    finally:
        cleanup_safe_archive(extraction)


def test_symlink_insertion_after_ticket_issuance_blocks_before_runner(tmp_path):
    extraction = _extraction(tmp_path)
    manager, _binary = _manager(tmp_path, "grype")
    calls = []
    try:
        ticket = issue_rootfs_followup_ticket(
            extraction, ROOTFS_GRYPE, scope_digest="scope:rootfs"
        )
        link = Path(extraction.root) / "etc/host-passwd"
        try:
            link.symlink_to("/etc/passwd")
        except OSError:
            pytest.skip("symlink creation unavailable on this platform")
        with pytest.raises(RootfsFollowupError, match="contains a symlink"):
            execute_rootfs_followup(
                extraction,
                ROOTFS_GRYPE,
                ticket=ticket,
                scope_digest="scope:rootfs",
                runtime_manager=manager,
                pins={},
                runner=lambda *args: calls.append(args) or CliProcessResult(0),
            )
        assert calls == []
    finally:
        cleanup_safe_archive(extraction)


def test_scope_mismatch_blocks_derived_rootfs_followup(tmp_path):
    extraction = _extraction(tmp_path)
    try:
        ticket = issue_rootfs_followup_ticket(
            extraction, ROOTFS_GRYPE, scope_digest="scope:one"
        )
        with pytest.raises(RootfsFollowupError, match="scope digest mismatch"):
            execute_rootfs_followup(
                extraction,
                ROOTFS_GRYPE,
                ticket=ticket,
                scope_digest="scope:two",
            )
    finally:
        cleanup_safe_archive(extraction)
