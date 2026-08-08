"""Planner-issued authorization tickets for autonomous offline asset execution.

An asset method may exist in the registry yet still be blocked because an authorized artifact,
firmware image, isolated sandbox, mobile runtime, or other semantic prerequisite is missing.
This module recomputes the authoritative capability plan and issues a ticket only for a method
that is actually in its READY set.

Tickets are an in-process control-plane invariant, not a cryptographic credential. Their digest
makes accidental mutation/drift detectable; repository/process trust is still enforced by Aegis'
normal code integrity and higher-level target authorization.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass

from .asset_capability_planner import (
    CapabilityRequirement,
    method_capability_requirements,
    plan_capability_scan,
)
from .asset_deep_capabilities import PlannedMethod, TargetAssetKind


class AssetExecutionTicketError(RuntimeError):
    pass


@dataclass(frozen=True)
class CapabilityAvailability:
    artifact_available: bool = False
    credentials_available: bool = False
    api_spec_available: bool = False
    endpoint_available: bool = False
    firmware_available: bool = False
    mobile_runtime_available: bool = False
    sandbox_available: bool = False
    cluster_access_available: bool = False
    registry_access_available: bool = False
    auth_session_available: bool = False
    language_hints: tuple[str, ...] = ()
    platform_hint: str = ""
    service_hints: tuple[str, ...] = ()

    def planner_kwargs(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class AssetExecutionTicket:
    ticket_id: str
    scope_digest: str
    asset_kind: str
    tool: str
    method: str
    requirements: tuple[str, ...]
    availability_digest: str
    offline_only: bool = True

    def as_dict(self) -> dict:
        return {
            "ticket_id": self.ticket_id,
            "scope_digest": self.scope_digest,
            "asset_kind": self.asset_kind,
            "tool": self.tool,
            "method": self.method,
            "requirements": list(self.requirements),
            "availability_digest": self.availability_digest,
            "offline_only": self.offline_only,
        }

    @classmethod
    def from_dict(cls, value: dict) -> "AssetExecutionTicket":
        if not isinstance(value, dict):
            raise AssetExecutionTicketError("execution ticket payload must be an object")
        try:
            ticket = cls(
                ticket_id=str(value["ticket_id"]),
                scope_digest=str(value["scope_digest"]),
                asset_kind=str(value["asset_kind"]),
                tool=str(value["tool"]),
                method=str(value["method"]),
                requirements=tuple(str(item) for item in value.get("requirements", ())),
                availability_digest=str(value["availability_digest"]),
                offline_only=bool(value.get("offline_only", True)),
            )
        except KeyError as exc:
            raise AssetExecutionTicketError(
                f"execution ticket payload is missing {exc.args[0]}"
            ) from exc
        return ticket


def _requirement_value(item: CapabilityRequirement) -> str:
    return str(item.value)


def _availability_digest(availability: CapabilityAvailability) -> str:
    payload = availability.planner_kwargs()
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(encoded).hexdigest()


def _ticket_id(material: dict) -> str:
    encoded = json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
    return "asset-ticket:v1:" + hashlib.sha256(encoded).hexdigest()


def issue_offline_execution_ticket(
    *,
    asset_kind: TargetAssetKind,
    method: PlannedMethod,
    scope_digest: str,
    availability: CapabilityAvailability,
) -> AssetExecutionTicket:
    """Issue a ticket only when the authoritative planner marks the method READY and offline."""
    scope = str(scope_digest or "").strip()
    if not scope:
        raise AssetExecutionTicketError("scope_digest is required")
    if bool(getattr(method, "requires_network", False)):
        raise AssetExecutionTicketError("network-capable methods cannot receive offline tickets")
    if bool(getattr(method, "state_change_possible", False)):
        raise AssetExecutionTicketError("state-changing methods cannot receive offline tickets")

    plan = plan_capability_scan(asset_kind, **availability.planner_kwargs())
    identity = (str(method.tool), str(method.method))
    ready = {(str(item.tool), str(item.method)): item for item in plan.ready}
    if identity not in ready:
        blocked = {(str(item.tool), str(item.method)): item for item in plan.blocked}
        if identity in blocked:
            requirements = ", ".join(
                _requirement_value(item)
                for item in method_capability_requirements(blocked[identity])
            ) or "unspecified prerequisite"
            raise AssetExecutionTicketError(
                f"method is blocked by authoritative capability plan: {requirements}"
            )
        raise AssetExecutionTicketError("method is not registered for this asset kind")

    canonical = ready[identity]
    requirements = tuple(
        _requirement_value(item) for item in method_capability_requirements(canonical)
    )
    availability_digest = _availability_digest(availability)
    material = {
        "scope_digest": scope,
        "asset_kind": str(asset_kind.value),
        "tool": identity[0],
        "method": identity[1],
        "requirements": requirements,
        "availability_digest": availability_digest,
        "offline_only": True,
    }
    return AssetExecutionTicket(
        ticket_id=_ticket_id(material),
        scope_digest=scope,
        asset_kind=str(asset_kind.value),
        tool=identity[0],
        method=identity[1],
        requirements=requirements,
        availability_digest=availability_digest,
        offline_only=True,
    )


def verify_offline_execution_ticket(
    ticket: AssetExecutionTicket,
    method: PlannedMethod,
    *,
    scope_digest: str,
) -> None:
    """Fail closed if a ticket does not exactly authorize this offline method and scope."""
    scope = str(scope_digest or "").strip()
    if not ticket.offline_only:
        raise AssetExecutionTicketError("ticket is not restricted to offline execution")
    if ticket.scope_digest != scope:
        raise AssetExecutionTicketError("execution ticket scope digest mismatch")
    if (ticket.tool, ticket.method) != (str(method.tool), str(method.method)):
        raise AssetExecutionTicketError("execution ticket method mismatch")
    material = {
        "scope_digest": ticket.scope_digest,
        "asset_kind": ticket.asset_kind,
        "tool": ticket.tool,
        "method": ticket.method,
        "requirements": ticket.requirements,
        "availability_digest": ticket.availability_digest,
        "offline_only": True,
    }
    if ticket.ticket_id != _ticket_id(material):
        raise AssetExecutionTicketError("execution ticket integrity mismatch")
