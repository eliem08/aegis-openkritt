"""Stable, orthogonal data types for arsenal definitions and coverage."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Mapping


class ArsenalCoverageState(str, Enum):
    EXECUTED_PASS = "EXECUTED_PASS"
    EXECUTED_FINDING = "EXECUTED_FINDING"
    WAITING_FOR_PREREQUISITE = "WAITING_FOR_PREREQUISITE"
    UNAVAILABLE = "UNAVAILABLE"
    DENIED_BY_POLICY = "DENIED_BY_POLICY"
    DENIED_POLICY_AMBIGUOUS = "DENIED_POLICY_AMBIGUOUS"
    NOT_IMPLEMENTED = "NOT_IMPLEMENTED"
    BACKEND_UNHEALTHY = "BACKEND_UNHEALTHY"


class CapabilityMode(str, Enum):
    FIXTURE = "FIXTURE"
    AUTHORIZED_REAL = "AUTHORIZED_REAL"


class ExecutionProofKind(str, Enum):
    """Provenance class for an execution claim.

    Only REAL_BACKEND and REAL_BACKEND_SHARED_CAPABILITIES are eligible for
    actual runtime execution credit. MIGRATED_EQUIVALENT may count for capability semantic
    coverage but NOT as an independently executed backend.
    """

    REAL_BACKEND = "REAL_BACKEND"
    REAL_BACKEND_SHARED_CAPABILITIES = "REAL_BACKEND_SHARED_CAPABILITIES"
    MIGRATED_EQUIVALENT = "MIGRATED_EQUIVALENT"
    SIMULATED_INTEGRATION = "SIMULATED_INTEGRATION"
    INTEGRATION_SIMULATION = "INTEGRATION_SIMULATION"
    UNIT_MOCK = "UNIT_MOCK"
    PREREQUISITE_ONLY = "PREREQUISITE_ONLY"
    LEGACY_UNVERIFIED = "LEGACY_UNVERIFIED"


@dataclass(frozen=True, slots=True)
class CapabilityProvenance:
    field: str
    source_registry: str
    source_reference: str
    value_digest: str

    def document(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ConflictClaim:
    value: Any
    source_registry: str
    source_reference: str

    def document(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class CapabilityConflict:
    capability_id: str
    field: str
    claims: tuple[ConflictClaim, ...]
    severity: str
    blocks_execution: bool
    detected_at: str

    def document(self) -> dict[str, Any]:
        value = asdict(self)
        value["claims"] = [claim.document() for claim in self.claims]
        return value


@dataclass(frozen=True, slots=True)
class ToolBackend:
    backend_id: str
    tool_name: str
    binary: str
    expected_version: str = ""
    adapter_version: str = ""

    def document(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class CapabilityDefinition:
    capability_id: str
    schema_version: int
    technique_ids: tuple[str, ...]
    tool_backends: tuple[ToolBackend, ...]
    supported_asset_classes: tuple[str, ...]
    executor_provider: str | None
    fixture_provider: str | None
    source_registries: tuple[str, ...]
    implementation_paths: tuple[str, ...]
    provenance: tuple[CapabilityProvenance, ...]
    conflicts: tuple[CapabilityConflict, ...] = ()
    fixture_executable: bool = False

    def __post_init__(self) -> None:
        if not self.capability_id or self.schema_version < 1:
            raise ValueError("capability identity and positive schema version are required")

    def document(self) -> dict[str, Any]:
        value = asdict(self)
        value["tool_backends"] = [item.document() for item in self.tool_backends]
        value["provenance"] = [item.document() for item in self.provenance]
        value["conflicts"] = [item.document() for item in self.conflicts]
        return value


@dataclass(frozen=True, slots=True)
class CapabilityHealth:
    capability_id: str
    current_state: ArsenalCoverageState
    backend_healthy: bool
    checked_at: str
    tool_name: str = ""
    expected_version: str = ""
    installed_version: str = ""
    binary_path: str = ""
    binary_digest: str = ""
    reason: str = ""

    def document(self) -> dict[str, Any]:
        value = asdict(self)
        value["current_state"] = self.current_state.value
        return value


@dataclass(frozen=True, slots=True)
class HistoricalExecution:
    capability_id: str
    mode: CapabilityMode
    state: ArsenalCoverageState
    run_id: str
    mission_id: str
    task_id: str
    backend: str
    backend_version: str
    policy_snapshot_digest: str
    asset: str
    authorization_decision: str
    operator_approval_id: str | None
    execution_grant_id: str | None
    executed_at: str
    evidence_digest: str
    finding_ids: tuple[str, ...] = ()
    error_or_block_reason: str = ""
    historical_evidence_invalid: bool = False
    execution_proof_kind: ExecutionProofKind = ExecutionProofKind.REAL_BACKEND
    backend_kind: str = "EXTERNAL_TOOL"
    binary_path: str = ""

    def document(self) -> dict[str, Any]:
        value = asdict(self)
        value["mode"] = self.mode.value
        value["state"] = self.state.value
        value["execution_proof_kind"] = self.execution_proof_kind.value
        return value


@dataclass(frozen=True, slots=True)
class CapabilityCoverageRecord:
    coverage_record_id: str
    idempotency_key: str
    capability_id: str
    mode: CapabilityMode
    tool_name: str
    tool_version: str
    technique_id: str
    asset_classes: tuple[str, ...]
    implementation_path: str
    backend: str
    backend_version: str
    backend_health: str
    policy_snapshot_digest: str
    asset: str
    authorization_decision: str
    operator_approval_id: str | None
    execution_grant_id: str | None
    run_id: str
    mission_id: str
    task_id: str
    executed: bool
    execution_timestamp: str | None
    evidence_digest: str | None
    result: ArsenalCoverageState
    finding_ids: tuple[str, ...] = ()
    error_or_block_reason: str = ""
    execution_error_class: str | None = None
    negative_control_status: str = "NOT_APPLICABLE"
    historical_evidence_invalid: bool = False
    schema_version: int = 1
    backend_execution_id: str = ""
    binary_path: str = ""
    container_digest: str = ""
    adapter_version: str = ""
    capability_ids: tuple[str, ...] = ()
    fixture_version: str = ""
    positive_fixture_digest: str = ""
    negative_fixture_digest: str = ""
    execution_started_at: str = ""
    execution_completed_at: str = ""
    duration_ms: int = 0
    exit_code: int | None = None
    stdout_digest: str = ""
    stderr_digest: str = ""
    parsed_result_digest: str = ""
    positive_control_detected: bool | None = None
    negative_control_clean: bool | None = None
    supersedes_coverage_record_id: str | None = None
    execution_proof_kind: ExecutionProofKind = ExecutionProofKind.LEGACY_UNVERIFIED
    backend_kind: str = "EXTERNAL_TOOL"
    launcher_executable: str = ""
    launcher_sha256: str = ""
    backend_entrypoint: str = ""
    backend_package: str = ""
    backend_package_version: str = ""
    native_backend_binary: str = ""
    native_backend_binary_sha256: str = ""
    host_platform: str = ""
    host_architecture: str = ""

    def __post_init__(self) -> None:
        if not all((self.coverage_record_id, self.idempotency_key, self.capability_id)):
            raise ValueError("coverage identity and idempotency are required")
        if self.schema_version < 1:
            raise ValueError("coverage schema version must be positive")
        if self.result is ArsenalCoverageState.EXECUTED_FINDING and not self.finding_ids:
            raise ValueError("EXECUTED_FINDING requires canonical human-reviewed finding IDs")
        if self.executed and not all((self.execution_timestamp, self.evidence_digest)):
            raise ValueError("executed coverage requires timestamp and evidence digest")
        if self.schema_version >= 2 and self.executed:
            if not all((
                self.backend_execution_id,
                self.binary_path,
                self.adapter_version,
                self.capability_ids,
                self.fixture_version,
                self.positive_fixture_digest,
                self.negative_fixture_digest,
                self.execution_started_at,
                self.execution_completed_at,
                self.stdout_digest,
                self.stderr_digest,
                self.parsed_result_digest,
            )):
                raise ValueError("schema-v2 execution coverage requires complete backend evidence")
            if self.execution_proof_kind not in {
                ExecutionProofKind.REAL_BACKEND,
                ExecutionProofKind.REAL_BACKEND_SHARED_CAPABILITIES,
                ExecutionProofKind.MIGRATED_EQUIVALENT,
            }:
                raise ValueError("schema-v2 execution coverage requires valid REAL_BACKEND proof")
            if self.execution_proof_kind in {
                ExecutionProofKind.REAL_BACKEND,
                ExecutionProofKind.REAL_BACKEND_SHARED_CAPABILITIES,
            }:
                from pathlib import Path
                base_binary = Path(self.binary_path).stem.lower()
                if self.backend_kind == "EXTERNAL_TOOL" and base_binary in {"python", "python3", "pythonw"}:
                    if not (self.backend_package or self.backend_entrypoint):
                        raise ValueError(
                            f"BACKEND_IDENTITY_MISMATCH: external backend {self.backend!r} "
                            f"cannot resolve to generic python binary {self.binary_path!r} "
                            f"without package and entrypoint metadata"
                        )
                from aegis.arsenal.migrations import RUNTIME_MIGRATIONS
                if (
                    self.backend in {"class-dump", "firmadyne"}
                    or any(self.capability_id in m.capabilities_affected for m in RUNTIME_MIGRATIONS)
                ) and self.execution_proof_kind is ExecutionProofKind.REAL_BACKEND:
                    raise ValueError(
                        f"MIGRATION_CONFLICT: migrated backend {self.backend!r} cannot be "
                        f"credited as independent REAL_BACKEND execution"
                    )
        if self.result is ArsenalCoverageState.EXECUTED_PASS and self.schema_version >= 2:
            if self.positive_control_detected is not True:
                raise ValueError("EXECUTED_PASS requires a detected positive control")
            if self.negative_control_clean is not True:
                raise ValueError("EXECUTED_PASS requires a clean negative control")

    def document(self) -> dict[str, Any]:
        value = asdict(self)
        value["mode"] = self.mode.value
        value["result"] = self.result.value
        return value

    def execution_metadata(self) -> dict[str, Any]:
        return {
            "backend_execution_id": self.backend_execution_id,
            "binary_path": self.binary_path,
            "container_digest": self.container_digest,
            "adapter_version": self.adapter_version,
            "capability_ids": list(self.capability_ids),
            "fixture_version": self.fixture_version,
            "positive_fixture_digest": self.positive_fixture_digest,
            "negative_fixture_digest": self.negative_fixture_digest,
            "execution_started_at": self.execution_started_at,
            "execution_completed_at": self.execution_completed_at,
            "duration_ms": self.duration_ms,
            "exit_code": self.exit_code,
            "stdout_digest": self.stdout_digest,
            "stderr_digest": self.stderr_digest,
            "parsed_result_digest": self.parsed_result_digest,
            "positive_control_detected": self.positive_control_detected,
            "negative_control_clean": self.negative_control_clean,
            "supersedes_coverage_record_id": self.supersedes_coverage_record_id,
            "execution_proof_kind": self.execution_proof_kind.value,
            "backend_kind": self.backend_kind,
            "launcher_executable": self.launcher_executable,
            "launcher_sha256": self.launcher_sha256,
            "backend_entrypoint": self.backend_entrypoint,
            "backend_package": self.backend_package,
            "backend_package_version": self.backend_package_version,
            "native_backend_binary": self.native_backend_binary,
            "native_backend_binary_sha256": self.native_backend_binary_sha256,
            "host_platform": self.host_platform,
            "host_architecture": self.host_architecture,
        }


@dataclass(frozen=True, slots=True)
class ArsenalAuditReport:
    schema_version: int
    generated_at: str
    definitions: tuple[CapabilityDefinition, ...]
    health: tuple[CapabilityHealth, ...]
    history: tuple[HistoricalExecution, ...]
    historical_evidence_errors: tuple[Mapping[str, Any], ...] = field(default_factory=tuple)

    def document(self) -> dict[str, Any]:
        fixture_denominator = sum(item.fixture_executable for item in self.definitions)
        fixture_executed = len({
            item.capability_id for item in self.history
            if item.mode is CapabilityMode.FIXTURE
            and item.state in {ArsenalCoverageState.EXECUTED_PASS,
                               ArsenalCoverageState.EXECUTED_FINDING}
            and not item.historical_evidence_invalid
        })
        real_executed = len({
            item.capability_id for item in self.history
            if item.mode is CapabilityMode.AUTHORIZED_REAL
            and item.state in {ArsenalCoverageState.EXECUTED_PASS,
                               ArsenalCoverageState.EXECUTED_FINDING}
            and not item.historical_evidence_invalid
        })
        healthy = sum(item.backend_healthy for item in self.health)
        current_counts = {
            state: sum(item.current_state is state for item in self.health)
            for state in ArsenalCoverageState
        }
        verified_pass = sum(
            item.state is ArsenalCoverageState.EXECUTED_PASS
            and not item.historical_evidence_invalid for item in self.history
        )
        verified_finding = sum(
            item.state is ArsenalCoverageState.EXECUTED_FINDING
            and not item.historical_evidence_invalid for item in self.history
        )
        return {
            "schema_version": self.schema_version,
            "generated_at": self.generated_at,
            "metrics": {
                "implemented_capability_count": len(self.definitions),
                "backend_healthy_count": healthy,
                "fixture_executable_denominator": fixture_denominator,
                "fixture_executed_count": fixture_executed,
                "authorized_real_executed_count": real_executed,
                "fixture_execution_coverage": (
                    fixture_executed / fixture_denominator if fixture_denominator else None
                ),
                "authorized_real_execution_coverage": None,
                "authorized_real_eligible_denominator": None,
                "verified_pass_count": verified_pass,
                "verified_finding_count": verified_finding,
                "blocked_by_policy_count": current_counts[
                    ArsenalCoverageState.DENIED_BY_POLICY
                ] + current_counts[ArsenalCoverageState.DENIED_POLICY_AMBIGUOUS],
                "waiting_prerequisite_count": current_counts[
                    ArsenalCoverageState.WAITING_FOR_PREREQUISITE
                ],
                "unavailable_count": current_counts[ArsenalCoverageState.UNAVAILABLE],
                "not_implemented_count": current_counts[ArsenalCoverageState.NOT_IMPLEMENTED],
                "backend_unhealthy_count": current_counts[
                    ArsenalCoverageState.BACKEND_UNHEALTHY
                ],
            },
            "definitions": [item.document() for item in self.definitions],
            "health": [item.document() for item in self.health],
            "history": [item.document() for item in self.history],
            "historical_evidence_errors": list(self.historical_evidence_errors),
        }
