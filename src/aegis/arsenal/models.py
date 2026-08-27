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

    def document(self) -> dict[str, Any]:
        value = asdict(self)
        value["mode"] = self.mode.value
        value["state"] = self.state.value
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

    def __post_init__(self) -> None:
        if not all((self.coverage_record_id, self.idempotency_key, self.capability_id)):
            raise ValueError("coverage identity and idempotency are required")
        if self.schema_version < 1:
            raise ValueError("coverage schema version must be positive")
        if self.result is ArsenalCoverageState.EXECUTED_FINDING and not self.finding_ids:
            raise ValueError("EXECUTED_FINDING requires canonical human-reviewed finding IDs")
        if self.executed and not all((self.execution_timestamp, self.evidence_digest)):
            raise ValueError("executed coverage requires timestamp and evidence digest")

    def document(self) -> dict[str, Any]:
        value = asdict(self)
        value["mode"] = self.mode.value
        value["result"] = self.result.value
        return value


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
