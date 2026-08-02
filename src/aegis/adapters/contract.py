"""Adapter contract (Master Prompt §core boundaries, execution envelope; Phase 1).

The stable interface between the scheduler and any tool. An ``AdapterManifest``
declares what a pinned tool is and may do; an immutable ``ExecutionEnvelope`` is
the per-task instruction (identifiers, target, signed-scope digest, adapter
identity, network profile, limits, **credential references — never values**,
hashes, deadline, idempotency). An ``Adapter`` only *translates*: it validates
the envelope against its manifest, builds a command, parses output lines into
typed :class:`AdapterEvent`s, and interprets the terminal result. Adapters
**never receive repository objects** and may reduce but never widen limits or
capabilities.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Protocol, runtime_checkable


def _now() -> datetime:
    return datetime.now(timezone.utc)


class CapabilityTier(str, Enum):
    PASSIVE_DISCOVERY = "passive_discovery"
    AUTHENTICATED_TESTING = "authenticated_testing"
    BENIGN_REQUEST_MUTATION = "benign_request_mutation"
    TEMPLATE_SCAN = "template_scan"
    XSS_REFLECTION = "xss_reflection"


class EventKind(str, Enum):
    ASSET = "asset"
    SERVICE = "service"
    ROUTE = "route"
    PARAMETER = "parameter"
    TECHNOLOGY = "technology"
    SECRET_CANDIDATE = "secret_candidate"
    FINDING = "finding"          # an active-testing candidate; not a verified finding
    DIAGNOSTIC = "diagnostic"
    PROGRESS = "progress"
    TERMINAL = "terminal"


class EnvelopeError(ValueError):
    pass


@dataclass(frozen=True)
class AdapterManifest:
    name: str
    version: str                 # semantic version
    executable_digest: str       # sha256 of the pinned binary/container
    license: str
    capability_tier: str         # CapabilityTier value
    input_schema_version: int
    output_schema_version: int
    network_profile: str         # NetworkProfile value


@dataclass(frozen=True)
class EnvelopeLimits:
    wall_seconds: float = 60.0
    output_bytes: int = 8 * 1024 * 1024
    max_events: int | None = None
    requests: int | None = None
    monetary: float | None = None


@dataclass(frozen=True)
class ExecutionEnvelope:
    tenant_id: str
    engagement_id: str
    scan_id: str
    stage_id: str
    task_id: str
    target: str
    scope_digest: str
    adapter_name: str
    adapter_version: str
    adapter_checksum: str
    adapter_license: str
    capability_tier: str
    network_profile: str
    idempotency_key: str
    config_hash: str = ""
    input_hash: str = ""
    approved_services: list[str] = field(default_factory=list)
    credential_refs: dict[str, str] = field(default_factory=dict)  # name -> vault ref, NEVER values
    limits: EnvelopeLimits = field(default_factory=EnvelopeLimits)
    deadline: datetime | None = None

    _REQUIRED = (
        "tenant_id", "engagement_id", "scan_id", "stage_id", "task_id", "target",
        "scope_digest", "adapter_name", "adapter_version", "adapter_checksum",
        "capability_tier", "network_profile", "idempotency_key",
    )

    def validate(self) -> None:
        """Workers reject incomplete envelopes (fail closed)."""
        missing = [f for f in self._REQUIRED if not getattr(self, f)]
        if missing:
            raise EnvelopeError(f"incomplete execution envelope; missing: {', '.join(missing)}")
        # Credential *values* must never travel in the envelope.
        for name, ref in self.credential_refs.items():
            if not isinstance(ref, str) or not ref.startswith(("vault://", "ref://", "env://")):
                raise EnvelopeError(f"credential {name!r} must be a reference, not a value")

    def process_limits(self):
        from aegis.process import ProcessLimits

        return ProcessLimits(
            wall_seconds=self.limits.wall_seconds,
            max_stdout_bytes=self.limits.output_bytes,
            max_events=self.limits.max_events,
        )

    @classmethod
    def for_manifest(
        cls, manifest: AdapterManifest, *, tenant_id, engagement_id, scan_id, stage_id, task_id,
        target, scope_digest, idempotency_key, **kwargs,
    ) -> "ExecutionEnvelope":
        """Build an envelope whose adapter fields are copied from the manifest."""
        return cls(
            tenant_id=tenant_id, engagement_id=engagement_id, scan_id=scan_id, stage_id=stage_id,
            task_id=task_id, target=target, scope_digest=scope_digest, idempotency_key=idempotency_key,
            adapter_name=manifest.name, adapter_version=manifest.version,
            adapter_checksum=manifest.executable_digest, adapter_license=manifest.license,
            capability_tier=manifest.capability_tier, network_profile=manifest.network_profile,
            **kwargs,
        )


@dataclass(frozen=True)
class AdapterEvent:
    """A typed, tagged event emitted by an adapter (a discriminated union keyed
    on ``kind``; ``data`` carries the kind-specific payload)."""

    kind: EventKind
    source: str
    observed_at: datetime
    target: str
    task_id: str
    adapter_version: str
    data: dict
    confidence: float = 1.0
    raw_ref: str | None = None


def event_from(
    kind: EventKind, envelope: ExecutionEnvelope, data: dict, *, source: str,
    confidence: float = 1.0, raw_ref: str | None = None,
) -> AdapterEvent:
    return AdapterEvent(
        kind=kind, source=source, observed_at=_now(), target=envelope.target,
        task_id=envelope.task_id, adapter_version=envelope.adapter_version,
        data=data, confidence=confidence, raw_ref=raw_ref,
    )


def validate_against_manifest(envelope: ExecutionEnvelope, manifest: AdapterManifest) -> None:
    """Envelope must be complete and consistent with the manifest; capabilities
    and identity cannot be widened."""
    envelope.validate()
    if envelope.adapter_name != manifest.name:
        raise EnvelopeError(f"adapter name mismatch: {envelope.adapter_name} != {manifest.name}")
    if envelope.adapter_version != manifest.version:
        raise EnvelopeError("adapter version mismatch")
    if envelope.adapter_checksum != manifest.executable_digest:
        raise EnvelopeError("adapter checksum mismatch")
    if envelope.capability_tier != manifest.capability_tier:
        raise EnvelopeError("capability tier cannot be widened beyond the manifest")
    if envelope.network_profile != manifest.network_profile:
        raise EnvelopeError("network profile mismatch")


@runtime_checkable
class Adapter(Protocol):
    manifest: AdapterManifest

    def validate_envelope(self, envelope: ExecutionEnvelope) -> None:
        ...

    def build_command(self, envelope: ExecutionEnvelope) -> list[str]:
        ...

    def parse_line(self, line: str, envelope: ExecutionEnvelope) -> AdapterEvent | None:
        ...

    def interpret_result(self, result, envelope: ExecutionEnvelope) -> AdapterEvent:
        ...
