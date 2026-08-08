from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegis.ai.jarvis.asset_capabilities import AssetKind
from aegis.ai.jarvis.offline_asset_research import (
    OfflineAssetResearchError,
    run_offline_asset_research,
)


def test_ai_model_dispatch_never_deserializes_and_can_skip_modelscan(tmp_path):
    model = tmp_path / "model.pkl"
    model.write_bytes(b"\x80\x04payload-never-loaded")
    report = run_offline_asset_research(
        AssetKind.AI_MODEL,
        model,
        scope_digest="scope:offline",
        run_modelscan=False,
    )
    assert report.asset_kind == AssetKind.AI_MODEL.value
    assert report.details["pipeline"] == "ai_model"
    assert report.details["deserialized"] is False
    assert report.details["detected_format"] == "pickle_protocol"
    assert {stage.stage: stage.status for stage in report.stages} == {
        "provenance": "complete",
        "modelscan": "skipped",
    }
    assert report.candidates == []
    assert report.observations[0]["kind"] == "ai_model_provenance"
    assert report.observations[0]["data"]["deserialized"] is False


def test_raw_firmware_dispatch_stops_at_isolated_filesystem_backend(tmp_path):
    firmware = tmp_path / "rootfs.squashfs"
    firmware.write_bytes(b"hsqs" + b"\x00" * 8192)
    report = run_offline_asset_research(
        AssetKind.HARDWARE,
        firmware,
        scope_digest="scope:offline",
        workspace_root=tmp_path / "work",
    )
    assert report.details["pipeline"] == "firmware_offline"
    assert report.details["emulation_used"] is False
    assert report.details["needs_isolated_filesystem_backend"] is True
    assert report.candidates == []
    assert [(stage.stage, stage.status) for stage in report.stages][:2] == [
        ("metadata", "complete"),
        ("extract", "unsupported"),
    ]


def test_unsupported_asset_kind_never_widens_to_live_or_source_testing(tmp_path):
    source = tmp_path / "app.py"
    source.write_text("print('hello')", encoding="utf-8")
    with pytest.raises(OfflineAssetResearchError, match="no unified safe-offline pipeline"):
        run_offline_asset_research(
            AssetKind.SOURCE_CODE,
            source,
            scope_digest="scope:offline",
        )


def test_existing_local_artifact_and_scope_are_mandatory(tmp_path):
    with pytest.raises(OfflineAssetResearchError, match="existing local artifact"):
        run_offline_asset_research(
            AssetKind.AI_MODEL,
            tmp_path / "missing.pkl",
            scope_digest="scope:offline",
        )
    model = tmp_path / "model.pkl"
    model.write_bytes(b"\x80\x04payload")
    with pytest.raises(OfflineAssetResearchError, match="scope_digest"):
        run_offline_asset_research(AssetKind.AI_MODEL, model, scope_digest="")
