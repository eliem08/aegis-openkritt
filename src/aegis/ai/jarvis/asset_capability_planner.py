"""Prerequisite-correct planner for base and deep Jarvis asset capabilities."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .asset_capabilities import AssetKind, Requirement, plan_asset_scan
from .asset_deep_capabilities import (
    ExtendedAssetKind,
    PlannedMethod,
    TargetAssetKind,
    _conditional_existing,
    _EXTENDED,
    _EXTRA_EXISTING,
)


class RuntimeRequirement(str, Enum):
    MOBILE_RUNTIME = "authorized_mobile_runtime"
    SANDBOX = "isolated_sandbox"
    CLUSTER_ACCESS = "authorized_cluster_access"
    REGISTRY_ACCESS = "authorized_registry_access"
    AUTH_SESSION = "authorized_authenticated_session"


CapabilityRequirement = Requirement | RuntimeRequirement


@dataclass(frozen=True)
class CapabilityScanPlan:
    asset_kind: TargetAssetKind
    ready: tuple[PlannedMethod, ...]
    blocked: tuple[PlannedMethod, ...]


_RUNTIME_REQUIREMENTS: dict[tuple[str, str], tuple[CapabilityRequirement, ...]] = {
    ("Frida", "android-runtime-instrumentation"): (RuntimeRequirement.MOBILE_RUNTIME,),
    ("objection", "android-runtime-exploration"): (RuntimeRequirement.MOBILE_RUNTIME,),
    ("Frida", "ios-runtime-instrumentation"): (RuntimeRequirement.MOBILE_RUNTIME,),
    ("objection", "ios-runtime-exploration"): (RuntimeRequirement.MOBILE_RUNTIME,),
    ("Ghidra", "headless-binary-analysis"): (RuntimeRequirement.SANDBOX,),
    ("angr", "binary-control-flow-analysis"): (RuntimeRequirement.SANDBOX,),
    ("Rizin", "binary-reverse-engineering"): (RuntimeRequirement.SANDBOX,),
    ("Echidna", "smart-contract-property-fuzzing"): (RuntimeRequirement.SANDBOX,),
    ("Foundry", "smart-contract-fuzz-and-invariant-tests"): (RuntimeRequirement.SANDBOX,),
    ("FirmAE", "firmware-emulation"): (RuntimeRequirement.SANDBOX,),
    ("Firmadyne", "firmware-emulation-fallback"): (RuntimeRequirement.SANDBOX,),
    ("Schemathesis", "schema-guided-api-testing"): (Requirement.ENDPOINT,),
    ("Playwright", "authenticated-browser-traffic-learning"): (RuntimeRequirement.AUTH_SESSION,),
    ("mitmproxy", "authorized-http-traffic-capture"): (RuntimeRequirement.AUTH_SESSION,),
    ("Kubescape", "kubernetes-posture-and-runtime-scan"): (RuntimeRequirement.CLUSTER_ACCESS,),
    ("skopeo", "container-registry-metadata"): (RuntimeRequirement.REGISTRY_ACCESS,),
    ("aegis-memory-poisoning", "agent-memory-poisoning-regression"): (
        RuntimeRequirement.AUTH_SESSION,
        RuntimeRequirement.SANDBOX,
    ),
}


def method_capability_requirements(method: PlannedMethod) -> tuple[CapabilityRequirement, ...]:
    """Return semantic prerequisites without overloading endpoint access."""
    requirements: list[CapabilityRequirement] = []
    if method.requirement != Requirement.NONE:
        requirements.append(method.requirement)
    requirements.extend(_RUNTIME_REQUIREMENTS.get((method.tool, method.method), ()))

    # The original deep registry used ENDPOINT as a placeholder for a few
    # isolated-runtime requirements.  Suppress that placeholder here when a
    # precise runtime requirement exists.
    if (method.tool, method.method) in _RUNTIME_REQUIREMENTS:
        runtime = _RUNTIME_REQUIREMENTS[(method.tool, method.method)]
        if Requirement.ENDPOINT not in runtime and Requirement.ENDPOINT in requirements:
            requirements = [item for item in requirements if item != Requirement.ENDPOINT]

    return tuple(dict.fromkeys(requirements))


def _availability(
    *,
    artifact_available: bool,
    credentials_available: bool,
    api_spec_available: bool,
    endpoint_available: bool,
    firmware_available: bool,
    mobile_runtime_available: bool,
    sandbox_available: bool,
    cluster_access_available: bool,
    registry_access_available: bool,
    auth_session_available: bool,
) -> dict[CapabilityRequirement, bool]:
    return {
        Requirement.ARTIFACT: artifact_available or firmware_available,
        Requirement.CREDENTIALS: credentials_available,
        Requirement.API_SPEC: api_spec_available,
        Requirement.ENDPOINT: endpoint_available,
        Requirement.FIRMWARE: firmware_available,
        RuntimeRequirement.MOBILE_RUNTIME: mobile_runtime_available,
        RuntimeRequirement.SANDBOX: sandbox_available,
        RuntimeRequirement.CLUSTER_ACCESS: cluster_access_available,
        RuntimeRequirement.REGISTRY_ACCESS: registry_access_available,
        RuntimeRequirement.AUTH_SESSION: auth_session_available,
    }


def plan_capability_scan(
    asset_kind: TargetAssetKind,
    *,
    artifact_available: bool = False,
    credentials_available: bool = False,
    api_spec_available: bool = False,
    endpoint_available: bool = False,
    firmware_available: bool = False,
    mobile_runtime_available: bool = False,
    sandbox_available: bool = False,
    cluster_access_available: bool = False,
    registry_access_available: bool = False,
    auth_session_available: bool = False,
    language_hints: tuple[str, ...] = (),
    platform_hint: str = "",
    service_hints: tuple[str, ...] = (),
) -> CapabilityScanPlan:
    """Plan all real scanner methods with explicit prerequisite conjunctions."""
    availability = _availability(
        artifact_available=artifact_available,
        credentials_available=credentials_available,
        api_spec_available=api_spec_available,
        endpoint_available=endpoint_available,
        firmware_available=firmware_available,
        mobile_runtime_available=mobile_runtime_available,
        sandbox_available=sandbox_available,
        cluster_access_available=cluster_access_available,
        registry_access_available=registry_access_available,
        auth_session_available=auth_session_available,
    )

    methods: list[PlannedMethod]
    if isinstance(asset_kind, AssetKind):
        base = plan_asset_scan(
            asset_kind,
            artifact_available=artifact_available,
            credentials_available=credentials_available,
            api_spec_available=api_spec_available,
            endpoint_available=endpoint_available,
            firmware_available=firmware_available,
        )
        methods = [*base.ready, *base.blocked, *_EXTRA_EXISTING.get(asset_kind, ())]
        methods.extend(
            _conditional_existing(
                asset_kind,
                language_hints=language_hints,
                platform_hint=platform_hint,
                service_hints=service_hints,
            )
        )
    else:
        methods = list(_EXTENDED[asset_kind])

    deduped: list[PlannedMethod] = []
    seen: set[tuple[str, str]] = set()
    for method in methods:
        key = (method.tool, method.method)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(method)

    def is_ready(method: PlannedMethod) -> bool:
        return all(availability.get(requirement, False) for requirement in method_capability_requirements(method))

    return CapabilityScanPlan(
        asset_kind=asset_kind,
        ready=tuple(method for method in deduped if is_ready(method)),
        blocked=tuple(method for method in deduped if not is_ready(method)),
    )


def missing_capability_requirements(
    method: PlannedMethod,
    *,
    artifact_available: bool = False,
    credentials_available: bool = False,
    api_spec_available: bool = False,
    endpoint_available: bool = False,
    firmware_available: bool = False,
    mobile_runtime_available: bool = False,
    sandbox_available: bool = False,
    cluster_access_available: bool = False,
    registry_access_available: bool = False,
    auth_session_available: bool = False,
) -> tuple[CapabilityRequirement, ...]:
    availability = _availability(
        artifact_available=artifact_available,
        credentials_available=credentials_available,
        api_spec_available=api_spec_available,
        endpoint_available=endpoint_available,
        firmware_available=firmware_available,
        mobile_runtime_available=mobile_runtime_available,
        sandbox_available=sandbox_available,
        cluster_access_available=cluster_access_available,
        registry_access_available=registry_access_available,
        auth_session_available=auth_session_available,
    )
    return tuple(
        requirement
        for requirement in method_capability_requirements(method)
        if not availability.get(requirement, False)
    )
