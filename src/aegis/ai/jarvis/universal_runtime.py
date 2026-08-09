"""Canonical multi-asset planning and fail-closed execution runtime."""

from __future__ import annotations

from dataclasses import dataclass, replace
from decimal import Decimal
from hashlib import sha256
from pathlib import Path
from typing import Any, Callable

from aegis.ai.agentic_os import AuthorizationEnvelope
from aegis.ingest.program import AssetType, ProgramRules, ScopeAsset
from aegis.scheduler.profit import HuntOpportunity

from .asset_backend_registry import BackendKind, inventory_backends
from .asset_capabilities import AssetKind
from .asset_capability_extensions import capability_extensions
from .asset_capability_planner import plan_capability_scan
from .asset_deep_capabilities import ExtendedAssetKind, PlannedMethod, TargetAssetKind
from .asset_execution import OfflineAssetExecutionOutcome, execute_authorized_offline_method
from .asset_execution_ticket import CapabilityAvailability, issue_offline_execution_ticket
from .mission_capabilities import CapabilityDisposition, MissionWorkerRegistry
from .mission_scheduler import MissionPlan, MissionScheduler, MissionTask, TaskState
from .universal_mission import compile_opportunity_mission

_TYPE_TO_KIND: dict[AssetType, TargetAssetKind] = {
    AssetType.URL: AssetKind.DOMAIN,
    AssetType.WILDCARD: AssetKind.WILDCARD,
    AssetType.CIDR: AssetKind.CIDR,
    AssetType.IP: AssetKind.IP_ADDRESS,
    AssetType.ANDROID: AssetKind.ANDROID_APK,
    AssetType.IOS: AssetKind.IOS_IPA,
    AssetType.SOURCE_CODE: AssetKind.SOURCE_CODE,
    AssetType.EXECUTABLE: AssetKind.EXECUTABLE,
    AssetType.API: AssetKind.API,
    AssetType.SMART_CONTRACT: AssetKind.SMART_CONTRACT,
    AssetType.FIRMWARE: AssetKind.HARDWARE,
    AssetType.CONTAINER_IMAGE: ExtendedAssetKind.CONTAINER_IMAGE,
    AssetType.KUBERNETES_CLUSTER: ExtendedAssetKind.KUBERNETES_CLUSTER,
    AssetType.PACKAGE: ExtendedAssetKind.PACKAGE_REGISTRY,
    AssetType.CLOUD_ACCOUNT: AssetKind.AWS_ACCOUNT,
    AssetType.AI_MODEL: AssetKind.AI_MODEL,
    AssetType.UNRESOLVED: AssetKind.OTHER_ASSET,
    AssetType.OTHER: AssetKind.OTHER_ASSET,
}

_KIND_SURFACE_FAMILY: dict[str, tuple[str, str]] = {
    "source_code": ("source", "authorization-boundary"),
    "android_apk": ("mobile-static", "mobile-component-boundary"),
    "ios_ipa": ("mobile-static", "mobile-component-boundary"),
    "executable": ("native-binary", "memory-safety"),
    "smart_contract": ("contract-state", "state-transition-integrity"),
    "api": ("api-schema", "authorization-boundary"),
    "domain": ("web", "authorization-boundary"),
    "wildcard": ("web", "authorization-boundary"),
    "cidr": ("network", "service-exposure"),
    "ip_address": ("network", "service-exposure"),
    "hardware": ("firmware", "trust-boundary"),
    "container_image": ("container", "supply-chain-integrity"),
    "kubernetes_cluster": ("cloud-runtime", "authorization-boundary"),
    "package_registry": ("supply-chain", "supply-chain-integrity"),
    "aws_account": ("cloud", "authorization-boundary"),
    "azure_account": ("cloud", "authorization-boundary"),
    "ai_model": ("ai-model", "prompt-data-boundary"),
}


def canonical_asset_kind(asset: ScopeAsset) -> TargetAssetKind:
    """Map ingestion's canonical scope asset onto the existing capability registry."""
    kind = _TYPE_TO_KIND[asset.asset_type]
    raw = asset.raw_asset_type.casefold()
    if asset.asset_type is AssetType.ANDROID and not asset.artifact_path and "apk" not in raw:
        return AssetKind.ANDROID_PLAY_STORE
    if asset.asset_type is AssetType.IOS and not asset.artifact_path and "ipa" not in raw:
        return AssetKind.IOS_APP_STORE
    if asset.asset_type is AssetType.CLOUD_ACCOUNT and "azure" in raw:
        return AssetKind.AZURE_ACCOUNT
    return kind


def opportunity_for_asset(
    program: ProgramRules,
    asset: ScopeAsset,
    *,
    scope_digest: str,
    authorization_id: str,
    estimated_payout_usd: Decimal | None = None,
) -> HuntOpportunity:
    kind = canonical_asset_kind(asset)
    surface, family = _KIND_SURFACE_FAMILY.get(kind.value, ("unresolved", "unresolved"))
    asset_id = asset.asset_id or "asset:" + sha256(asset.identifier.encode()).hexdigest()[:16]
    opportunity_id = "opp:" + sha256(
        f"{program.handle}\x1f{asset_id}\x1f{surface}\x1f{family}".encode()
    ).hexdigest()[:20]
    return HuntOpportunity(
        opportunity_id,
        program_id=program.handle,
        program_handle=program.handle,
        asset_id=asset_id,
        asset_kind=kind.value,
        asset_locator=asset.identifier,
        scope_digest=asset.scope_digest or scope_digest,
        authorization_id=asset.authorization_id or authorization_id,
        attack_surface=surface,
        weakness_family=family,
        prerequisite_state="ready",
        estimated_payout_usd=estimated_payout_usd,
        p_find=0.25,
        p_valid=0.5,
        p_unique=0.5,
        p_accepted=0.5,
        p_reproducible=0.6,
        scanner_cost_usd=Decimal("0.01"),
        validation_cost_usd=Decimal("0.05"),
        provenance=tuple((*asset.provenance, "aegis.jarvis.universal_runtime")),
        metadata={"artifact_path": asset.artifact_path},
    )


def opportunities_for_program(
    program: ProgramRules,
    *,
    scope_digest: str,
    authorization_id: str,
) -> tuple[HuntOpportunity, ...]:
    return tuple(
        opportunity_for_asset(
            program, asset, scope_digest=scope_digest, authorization_id=authorization_id
        )
        for asset in program.in_scope
        if asset.eligible_for_submission
    )


@dataclass(frozen=True)
class MissionExecutionResult:
    plan: MissionPlan
    disposition: CapabilityDisposition
    reason: str
    outcome: OfflineAssetExecutionOutcome | None = None


DynamicExecutor = Callable[[PlannedMethod, MissionPlan, AuthorizationEnvelope], Any]
MissionTaskExecutor = Callable[[MissionTask, MissionPlan, AuthorizationEnvelope], Any]


class UniversalMissionRuntime:
    """Connect canonical missions to existing tickets, executors, and durable checkpoints."""

    def __init__(
        self,
        scheduler: MissionScheduler,
        *,
        grant_verifier,
        workers: MissionWorkerRegistry | None = None,
        dynamic_executor: DynamicExecutor | None = None,
        mission_task_executors: dict[str, MissionTaskExecutor] | None = None,
    ) -> None:
        self.scheduler = scheduler
        self.grant_verifier = grant_verifier
        self.workers = workers or MissionWorkerRegistry()
        self.dynamic_executor = dynamic_executor
        self.mission_task_executors = dict(mission_task_executors or {})

    @staticmethod
    def _method(
        asset_kind: TargetAssetKind,
        tool: str,
        method: str,
        availability: CapabilityAvailability,
    ) -> PlannedMethod | None:
        plan = plan_capability_scan(asset_kind, **availability.planner_kwargs())
        extensions = tuple(
            item.method
            for item in capability_extensions(
                asset_kind, firmware_available=availability.firmware_available
            )
        )
        return next(
            (item for item in (*plan.ready, *plan.blocked, *extensions)
             if item.tool.casefold() == tool.casefold()
             and item.method.casefold() == method.casefold()),
            None,
        )

    def prepare(
        self,
        opportunity: HuntOpportunity,
        *,
        availability: CapabilityAvailability,
    ) -> MissionPlan:
        plan = compile_opportunity_mission(opportunity)
        if plan.tasks[0].executor_capability.startswith("dynamic:"):
            # Higher-order hunter capabilities are already canonical MissionTasks.  Do not
            # replace them with a generic asset scanner selected solely from asset kind.
            return self.scheduler.create(plan)
        kind = canonical_kind_value(opportunity.asset_kind)
        inventory = inventory_backends(kind, **availability.planner_kwargs())
        if inventory.supported_ready:
            support = sorted(
                inventory.supported_ready,
                key=lambda item: (
                    item.backend is BackendKind.NETWORKLESS_CLI,
                    item.tool.casefold(),
                    item.method.casefold(),
                ),
            )[0]
            state = TaskState.PENDING
        elif inventory.semantic_blocked:
            support = inventory.semantic_blocked[0]
            state = TaskState.WAITING_FOR_PREREQUISITE
        elif inventory.unimplemented_ready:
            support = inventory.unimplemented_ready[0]
            state = (
                TaskState.WAITING_FOR_APPROVAL
                if support.backend is BackendKind.DYNAMIC_POLICY else TaskState.UNAVAILABLE
            )
        else:
            support = None
            state = TaskState.UNAVAILABLE
        first, *rest = plan.tasks
        if first.state in {TaskState.WAITING_FOR_PREREQUISITE, TaskState.UNAVAILABLE}:
            state = first.state
        capability = f"{support.tool}:{support.method}" if support else ""
        resolved = (
            self._method(kind, support.tool, support.method, availability) if support else None
        )
        risk = (
            "controlled_state_change"
            if resolved is not None and resolved.state_change_possible
            else "read_only" if resolved is not None and resolved.requires_network
            else "offline"
        )
        first = replace(
            first,
            executor_capability=capability,
            state=state,
            risk=risk,
            payload={**(first.payload or {}), "backend_reason": support.reason if support else
                     "no capability is registered for this asset kind"},
        )
        plan = replace(plan, tasks=(first, *rest))
        return self.scheduler.create(plan)

    def execute_first(
        self,
        plan: MissionPlan,
        *,
        authorization: AuthorizationEnvelope,
        availability: CapabilityAvailability,
        artifact_path: str | Path | None = None,
        **executor_kwargs: Any,
    ) -> MissionExecutionResult:
        task = plan.tasks[0]
        if task.state is TaskState.WAITING_FOR_PREREQUISITE:
            return MissionExecutionResult(
                plan, CapabilityDisposition.WAITING_FOR_PREREQUISITE,
                "mission prerequisite is unresolved; execution is not eligible",
            )
        if task.state is TaskState.UNAVAILABLE:
            return MissionExecutionResult(
                plan, CapabilityDisposition.UNAVAILABLE,
                "mission capability is explicitly unavailable",
            )
        match = self.workers.match(task, availability=availability)
        if match.disposition in {
            CapabilityDisposition.WAITING_FOR_PREREQUISITE,
            CapabilityDisposition.UNAVAILABLE,
        }:
            state = {
                CapabilityDisposition.WAITING_FOR_PREREQUISITE:
                    TaskState.WAITING_FOR_PREREQUISITE,
                CapabilityDisposition.UNAVAILABLE: TaskState.UNAVAILABLE,
            }[match.disposition]
            plan = self.scheduler.set_task_state(plan, task.task_id, state)
            return MissionExecutionResult(plan, match.disposition, match.reason)

        grant = authorization.grant
        if (
            grant is None
            or authorization.scope_digest != plan.scope_digest
            or grant.scope_digest != plan.scope_digest
            or not grant.verify(self.grant_verifier)
        ):
            plan = self.scheduler.set_task_state(
                plan, task.task_id, TaskState.WAITING_FOR_APPROVAL
            )
            return MissionExecutionResult(
                plan, CapabilityDisposition.WAITING_FOR_APPROVAL,
                "execution requires a verified PolicyEngine-derived grant bound to mission scope",
            )

        if task.executor_capability.startswith("dynamic:"):
            if not grant.network_allowed or not (
                grant.state_change_allowed and grant.human_approval
            ):
                plan = self.scheduler.set_task_state(
                    plan, task.task_id, TaskState.WAITING_FOR_APPROVAL
                )
                return MissionExecutionResult(
                    plan, CapabilityDisposition.WAITING_FOR_APPROVAL,
                    "signed grant does not authorize controlled differential execution",
                )
            executor = self.mission_task_executors.get(task.executor_capability)
            if executor is None:
                plan = self.scheduler.set_task_state(plan, task.task_id, TaskState.UNAVAILABLE)
                return MissionExecutionResult(
                    plan, CapabilityDisposition.UNAVAILABLE,
                    "no concrete executor is registered for the hunter capability",
                )
            plan = self.scheduler.set_task_state(plan, task.task_id, TaskState.RUNNING)
            try:
                executor(task, plan, authorization)
            except Exception as exc:
                plan = self.scheduler.set_task_state(
                    plan, task.task_id, TaskState.FAILED_RETRYABLE
                )
                return MissionExecutionResult(
                    plan, CapabilityDisposition.UNAVAILABLE,
                    f"concrete hunter executor failed closed: {type(exc).__name__}: {exc}",
                )
            plan = self.scheduler.set_task_state(plan, task.task_id, TaskState.COMPLETED)
            return MissionExecutionResult(
                plan, CapabilityDisposition.READY, "hunter capability completed"
            )

        kind = canonical_kind_value(task.asset_kind)
        method = self._method(kind, match.tool, match.method, availability)
        if method is None:
            plan = self.scheduler.set_task_state(plan, task.task_id, TaskState.UNAVAILABLE)
            return MissionExecutionResult(
                plan, CapabilityDisposition.UNAVAILABLE, "registered method could not be resolved"
            )
        if method.requires_network or method.state_change_possible:
            if not grant.network_allowed or (method.state_change_possible and not (
                grant.state_change_allowed and grant.human_approval
            )):
                plan = self.scheduler.set_task_state(
                    plan, task.task_id, TaskState.WAITING_FOR_APPROVAL
                )
                return MissionExecutionResult(
                    plan, CapabilityDisposition.WAITING_FOR_APPROVAL,
                    "signed grant does not authorize this scoped dynamic method",
                )
            if self.dynamic_executor is None:
                plan = self.scheduler.set_task_state(plan, task.task_id, TaskState.UNAVAILABLE)
                return MissionExecutionResult(
                    plan, CapabilityDisposition.UNAVAILABLE,
                    "no policy-controlled dynamic executor backend is registered",
                )
            self.dynamic_executor(method, plan, authorization)
            plan = self.scheduler.set_task_state(plan, task.task_id, TaskState.COMPLETED)
            return MissionExecutionResult(plan, CapabilityDisposition.READY, "dynamic task completed")

        ticket = issue_offline_execution_ticket(
            asset_kind=kind,
            method=method,
            scope_digest=plan.scope_digest,
            availability=availability,
        )
        plan = self.scheduler.set_task_state(plan, task.task_id, TaskState.RUNNING)
        try:
            outcome = execute_authorized_offline_method(
                method,
                ticket=ticket,
                scope_digest=plan.scope_digest,
                artifact_path=artifact_path,
                firmware_path=artifact_path,
                source_path=artifact_path,
                target_path=artifact_path,
                **executor_kwargs,
            )
        except Exception as exc:
            plan = self.scheduler.set_task_state(plan, task.task_id, TaskState.FAILED_RETRYABLE)
            return MissionExecutionResult(
                plan, CapabilityDisposition.UNAVAILABLE,
                f"concrete backend failed closed: {type(exc).__name__}: {exc}",
            )
        plan = self.scheduler.set_task_state(plan, task.task_id, TaskState.COMPLETED)
        return MissionExecutionResult(plan, CapabilityDisposition.READY, "offline task completed", outcome)


def canonical_kind_value(value: str) -> TargetAssetKind:
    try:
        return AssetKind(value)
    except ValueError:
        return ExtendedAssetKind(value)


__all__ = [
    "MissionExecutionResult",
    "UniversalMissionRuntime",
    "canonical_asset_kind",
    "opportunities_for_program",
    "opportunity_for_asset",
]
