from __future__ import annotations

import json
from dataclasses import replace

import pytest

from aegis.production.operator_manifest import (
    ImmutableRunStore,
    OperatorRunError,
    OperatorRunManifest,
    RunBudgets,
    RunMode,
    RunStatus,
    document_digest,
)


def manifest(mode=RunMode.DRY_RUN):
    policy = {"retrieved_at": "2026-08-10T00:00:00Z", "rules": "read only"}
    scope = {"assets": ["api.example.test"], "out_of_scope": []}
    return OperatorRunManifest(
        1, "run-1", mode, "2026-08-10T00:00:00Z", "operator-7", "program-1",
        "operator-refreshed-feed", ("api.example.test",),
        "api.example.test" if mode is RunMode.LIVE_CANARY else None, (),
        policy, document_digest(policy), scope, document_digest(scope),
        {"program_selected": True, "asset_selected": True}, RunBudgets(20, 1.0, 1.5),
        {"authorization_id": "auth-1", "signature": "signed"},
    )


def test_create_and_resume_verifies_immutable_hash_chain(tmp_path):
    store = ImmutableRunStore(tmp_path)
    digest = store.create(manifest())
    event = store.append_event("run-1", "scope_refreshed", RunStatus.SCOPE_REFRESHED)
    state = store.verify("run-1")
    assert state["manifest_digest"] == digest
    assert state["events"] == 2 and state["last_event_digest"] == event.digest
    with pytest.raises(OperatorRunError, match="already exists"):
        store.create(manifest())


def test_tampering_is_detected(tmp_path):
    store = ImmutableRunStore(tmp_path)
    store.create(manifest())
    event_path = next((tmp_path / "run-1" / "events").glob("*.json"))
    value = json.loads(event_path.read_text())
    value["detail"]["mode"] = "live_canary"
    event_path.write_text(json.dumps(value))
    with pytest.raises(OperatorRunError, match="verification failed"):
        store.verify("run-1")


def test_live_canary_requires_one_explicit_selected_asset():
    valid = manifest(RunMode.LIVE_CANARY)
    assert valid.canary_asset == valid.selected_assets[0]
    with pytest.raises(ValueError, match="exactly one"):
        replace(valid, selected_assets=("a", "b"), canary_asset="a")
