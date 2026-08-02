"""Adapter contract + fake adapter, incl. an end-to-end run via SafeProcessRunner."""

import pytest

from aegis.adapters import (
    EnvelopeError,
    EnvelopeLimits,
    EventKind,
    ExecutionEnvelope,
    FakeDiscoveryAdapter,
)
from aegis.adapters.contract import validate_against_manifest
from aegis.process import SafeProcessRunner

adapter = FakeDiscoveryAdapter()
M = adapter.manifest


def full_envelope(**over) -> ExecutionEnvelope:
    base = dict(
        tenant_id="t", engagement_id="e", scan_id="s", stage_id="st", task_id="tk",
        target="api.example.test", scope_digest="digest",
        adapter_name=M.name, adapter_version=M.version, adapter_checksum=M.executable_digest,
        adapter_license=M.license, capability_tier=M.capability_tier, network_profile=M.network_profile,
        idempotency_key="k",
    )
    base.update(over)
    return ExecutionEnvelope(**base)


# --- envelope validation ---

def test_valid_envelope_passes():
    full_envelope().validate()  # no raise
    validate_against_manifest(full_envelope(), M)


def test_incomplete_envelope_rejected():
    with pytest.raises(EnvelopeError):
        full_envelope(target="").validate()


def test_credentials_must_be_references_not_values():
    with pytest.raises(EnvelopeError):
        full_envelope(credential_refs={"api": "plaintext-secret"}).validate()
    full_envelope(credential_refs={"api": "vault://secret/api"}).validate()  # ok


@pytest.mark.parametrize("field,value", [
    ("adapter_name", "other-tool"),
    ("adapter_version", "9.9.9"),
    ("adapter_checksum", "0" * 64),
    ("capability_tier", "authenticated_testing"),  # widening
    ("network_profile", "target-mutation"),
])
def test_manifest_mismatch_rejected(field, value):
    with pytest.raises(EnvelopeError):
        validate_against_manifest(full_envelope(**{field: value}), M)


# --- command construction ---

def test_build_command_puts_no_secrets_in_argv():
    env = full_envelope(credential_refs={"api": "vault://secret/api"})
    argv = adapter.build_command(env)
    assert "api.example.test" in argv
    assert not any("vault://" in a for a in argv)  # references never in argv


# --- line parsing ---

def test_parse_valid_event():
    env = full_envelope()
    e = adapter.parse_line('{"kind":"asset","identifier":"api.example.test","asset_type":"url"}', env)
    assert e.kind == EventKind.ASSET and e.data["identifier"] == "api.example.test"
    assert e.target == "api.example.test" and e.task_id == "tk" and e.source == "fake-discovery"


def test_parse_malformed_line_becomes_diagnostic():
    e = adapter.parse_line("not json {", full_envelope())
    assert e.kind == EventKind.DIAGNOSTIC and e.confidence == 0.0


def test_parse_unknown_kind_becomes_diagnostic():
    e = adapter.parse_line('{"kind":"weird","x":1}', full_envelope())
    assert e.kind == EventKind.DIAGNOSTIC


def test_parse_empty_line_is_none():
    assert adapter.parse_line("   ", full_envelope()) is None


# --- end to end through the process runner ---

def test_fake_adapter_runs_end_to_end():
    env = full_envelope(limits=EnvelopeLimits(wall_seconds=15))
    adapter.validate_envelope(env)
    argv = adapter.build_command(env)

    result = SafeProcessRunner().run(argv, limits=env.process_limits())
    assert result.ok

    events = [ev for line in result.lines if (ev := adapter.parse_line(line, env)) is not None]
    kinds = [e.kind for e in events]
    assert EventKind.ASSET in kinds and EventKind.TECHNOLOGY in kinds
    assert kinds.count(EventKind.ROUTE) == 2

    asset = next(e for e in events if e.kind == EventKind.ASSET)
    assert asset.data["identifier"] == "api.example.test"

    terminal = adapter.interpret_result(result, env)
    assert terminal.kind == EventKind.TERMINAL and terminal.data["status"] == "succeeded"
