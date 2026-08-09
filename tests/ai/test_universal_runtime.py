from __future__ import annotations

from aegis.ai.agentic_os import (
    AuthorizationEnvelope,
    Budget,
    mint_execution_grant,
    process_grant_verifier,
)
from aegis.ai.jarvis.asset_execution_ticket import CapabilityAvailability
from aegis.ai.jarvis.mission_capabilities import CapabilityDisposition
from aegis.ai.jarvis.mission_scheduler import MissionScheduler, TaskState
from aegis.ai.jarvis.state_store import JarvisStateStore
from aegis.ai.jarvis.universal_runtime import (
    UniversalMissionRuntime,
    opportunities_for_program,
)
from aegis.ingest.program import AssetType, ProgramRules, ScopeAsset


def _program(firmware_path: str) -> ProgramRules:
    return ProgramRules(
        handle="multi-asset",
        offers_bounties=True,
        in_scope=[
            ScopeAsset(identifier="https://github.com/acme/repo", asset_type=AssetType.SOURCE_CODE),
            ScopeAsset(identifier="https://api.acme.test/openapi.json", asset_type=AssetType.API),
            ScopeAsset(identifier="com.acme.app", asset_type=AssetType.ANDROID),
            ScopeAsset(
                identifier="router.bin",
                asset_type=AssetType.FIRMWARE,
                artifact_path=firmware_path,
                provenance=["authorized-upload"],
            ),
        ],
    )


def _envelope(scope_digest: str) -> tuple[AuthorizationEnvelope, object]:
    verifier = process_grant_verifier()
    budget = Budget(max_cost_usd=5.0, max_requests=20, max_human_minutes=10)
    grant = mint_execution_grant(
        type("AllowedPolicyDecision", (), {"allowed": True})(),
        scope_digest=scope_digest,
        budget=budget,
        verifier=verifier,
    )
    return AuthorizationEnvelope(scope_digest=scope_digest, budget=budget, grant=grant), verifier


def test_canonical_multi_asset_plan_and_real_offline_execution(tmp_path):
    firmware = tmp_path / "router.bin"
    firmware.write_bytes(b"\x7fELF" + b"\x00" * 128)
    opportunities = opportunities_for_program(
        _program(str(firmware)), scope_digest="scope:multi", authorization_id="auth:multi"
    )
    assert {item.asset_kind for item in opportunities} == {
        "source_code", "api", "android_play_store", "hardware"
    }
    assert all(item.estimated_payout_usd is None for item in opportunities)

    envelope, verifier = _envelope("scope:multi")
    with JarvisStateStore(tmp_path / "jarvis.db") as store:
        runtime = UniversalMissionRuntime(MissionScheduler(store), grant_verifier=verifier)
        waiting = runtime.prepare(
            next(item for item in opportunities if item.asset_kind == "android_play_store"),
            availability=CapabilityAvailability(),
        )
        assert waiting.tasks[0].state in {
            TaskState.WAITING_FOR_PREREQUISITE, TaskState.WAITING_FOR_APPROVAL,
            TaskState.UNAVAILABLE,
        }

        firmware_opportunity = next(
            item for item in opportunities if item.asset_kind == "hardware"
        )
        availability = CapabilityAvailability(
            artifact_available=True, firmware_available=True
        )
        mission = runtime.prepare(firmware_opportunity, availability=availability)
        assert mission.tasks[0].executor_capability == (
            "aegis-firmware-arch:firmware-architecture-detection"
        )
        result = runtime.execute_first(
            mission,
            authorization=envelope,
            availability=availability,
            artifact_path=firmware,
        )
        assert result.disposition is CapabilityDisposition.READY
        assert result.outcome is not None
        assert result.outcome.provenance["network_used"] is False
        assert result.plan.tasks[0].state is TaskState.COMPLETED
        assert runtime.scheduler.resume(mission.mission_id) == result.plan


def test_execution_fails_closed_without_signed_scope_bound_grant(tmp_path):
    firmware = tmp_path / "router.bin"
    firmware.write_bytes(b"firmware")
    opportunity = opportunities_for_program(
        _program(str(firmware)), scope_digest="scope:multi", authorization_id="auth:multi"
    )[-1]
    verifier = process_grant_verifier()
    availability = CapabilityAvailability(artifact_available=True, firmware_available=True)
    with JarvisStateStore(tmp_path / "jarvis.db") as store:
        runtime = UniversalMissionRuntime(MissionScheduler(store), grant_verifier=verifier)
        mission = runtime.prepare(opportunity, availability=availability)
        result = runtime.execute_first(
            mission,
            authorization=AuthorizationEnvelope(scope_digest="scope:multi"),
            availability=availability,
            artifact_path=firmware,
        )
        assert result.disposition is CapabilityDisposition.WAITING_FOR_APPROVAL
        assert result.outcome is None
        assert result.plan.tasks[0].state is TaskState.WAITING_FOR_APPROVAL


def test_unresolved_prerequisite_cannot_execute_even_with_valid_grant(tmp_path):
    firmware = tmp_path / "router.bin"
    firmware.write_bytes(b"firmware")
    opportunity = opportunities_for_program(
        _program(str(firmware)), scope_digest="scope:multi", authorization_id="auth:multi"
    )[-1]
    from dataclasses import replace

    opportunity = replace(opportunity, prerequisite_state="scope_confirmation_required")
    envelope, verifier = _envelope("scope:multi")
    availability = CapabilityAvailability(artifact_available=True, firmware_available=True)
    with JarvisStateStore(tmp_path / "jarvis.db") as store:
        runtime = UniversalMissionRuntime(MissionScheduler(store), grant_verifier=verifier)
        mission = runtime.prepare(opportunity, availability=availability)
        assert mission.tasks[0].state is TaskState.WAITING_FOR_PREREQUISITE
        result = runtime.execute_first(
            mission, authorization=envelope, availability=availability,
            artifact_path=firmware,
        )
        assert result.disposition is CapabilityDisposition.WAITING_FOR_PREREQUISITE
        assert result.outcome is None


def test_network_lane_is_unavailable_without_registered_dynamic_backend(tmp_path):
    program = ProgramRules(
        handle="network",
        in_scope=[ScopeAsset(identifier="10.0.0.0/24", asset_type=AssetType.CIDR)],
    )
    opportunity = opportunities_for_program(
        program, scope_digest="scope:network", authorization_id="auth:network"
    )[0]
    envelope, verifier = _envelope("scope:network")
    # Re-mint the grant with target-network authority.
    grant = mint_execution_grant(
        type("AllowedPolicyDecision", (), {"allowed": True})(),
        scope_digest="scope:network",
        budget=envelope.budget,
        verifier=verifier,
        network=True,
    )
    envelope = AuthorizationEnvelope(
        scope_digest="scope:network", budget=envelope.budget, grant=grant
    )
    with JarvisStateStore(tmp_path / "jarvis.db") as store:
        runtime = UniversalMissionRuntime(MissionScheduler(store), grant_verifier=verifier)
        mission = runtime.prepare(opportunity, availability=CapabilityAvailability())
        result = runtime.execute_first(
            mission, authorization=envelope, availability=CapabilityAvailability()
        )
        assert result.disposition is CapabilityDisposition.UNAVAILABLE
        assert "dynamic executor" in result.reason
        assert result.plan.tasks[0].state is TaskState.UNAVAILABLE
