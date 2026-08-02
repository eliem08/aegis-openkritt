"""Subfinder adapter — passive subdomain discovery (Phase 2 §Subfinder adapter).

Wraps a pinned, checksum-verified subfinder release. Provider credentials arrive
as secret *references* and are written to a task-scoped config file by the runner;
they never appear in argv.

The behaviors that matter for correctness are enforced here rather than trusted
from the tool: every result records the provider that found it, results are capped
globally and per provider, names outside the immutable parent domain are rejected,
and wildcard results are suppressed before anything downstream schedules a probe.
Provider failures are diagnostics — unless too few providers succeeded, in which
case coverage is reported as partial rather than complete.
"""

from __future__ import annotations

from dataclasses import dataclass

from .base import PROVIDER_ERROR, QUOTA_EXHAUSTED, JsonLinesAdapter, SchemaMismatch, in_parent_scope
from .contract import AdapterManifest, CapabilityTier, EventKind, ExecutionEnvelope

SUBFINDER_MANIFEST = AdapterManifest(
    name="subfinder",
    version="2.6.6",
    executable_digest="",          # pin the release digest before distribution
    license="MIT",
    capability_tier=CapabilityTier.PASSIVE_DISCOVERY.value,
    input_schema_version=1,
    output_schema_version=2,       # subfinder -json record shape
    network_profile="passive-provider",
)


@dataclass(frozen=True)
class SubfinderConfig:
    max_results: int = 1000
    max_results_per_provider: int = 250
    provider_timeout_seconds: int = 30
    min_provider_coverage: int = 1     # below this, coverage is partial
    sources: tuple[str, ...] = ()      # empty = the pinned default provider set


class SubfinderAdapter(JsonLinesAdapter):
    manifest = SUBFINDER_MANIFEST
    tool_name = "subfinder"

    def __init__(self, executable=None, *, config: SubfinderConfig | None = None, **kw) -> None:
        super().__init__(executable, **kw)
        self.config = config or SubfinderConfig()
        self._seen: set[str] = set()
        self._per_provider: dict[str, int] = {}
        self._succeeded_providers: set[str] = set()
        self._failed_providers: set[str] = set()

    def build_command(self, envelope: ExecutionEnvelope) -> list[str]:
        cfg = self.config
        argv = [
            self.resolve_executable(),
            "-domain", envelope.target,
            "-json", "-silent",
            "-max-time", str(cfg.provider_timeout_seconds),
            "-timeout", str(cfg.provider_timeout_seconds),
        ]
        if cfg.sources:
            argv += ["-sources", ",".join(cfg.sources)]
        # Credentials stay as references; the runner materializes them to a file.
        if envelope.credential_refs:
            argv += ["-provider-config", "provider-config.yaml"]
        return argv

    def map_record(self, record: dict, envelope: ExecutionEnvelope):
        # Diagnostics from the tool: a provider failed but the run continues.
        if "error" in record and "host" not in record:
            provider = str(record.get("source") or "unknown")
            self._failed_providers.add(provider)
            return (EventKind.DIAGNOSTIC,
                    {"code": PROVIDER_ERROR, "message": str(record["error"]),
                     "provider": provider, "blocking": False}, 0.0)

        host = record.get("host")
        if not host:
            raise SchemaMismatch("subfinder record has no 'host' field")
        provider = str(record.get("source") or "unknown")
        host = str(host).strip().lower().rstrip(".")

        # Immutable parent-domain scope: enumeration may never wander outside it.
        if not in_parent_scope(host, envelope.target):
            return (EventKind.DIAGNOSTIC,
                    {"code": "out_of_parent_scope", "message": f"{host} is outside {envelope.target}",
                     "provider": provider, "blocking": False}, 0.0)

        # Wildcard results are suppressed before any probe is scheduled.
        if host.startswith("*.") or record.get("wildcard") is True:
            return (EventKind.DIAGNOSTIC,
                    {"code": "wildcard_suppressed", "message": f"wildcard result {host}",
                     "provider": provider, "blocking": False}, 0.0)

        if len(self._seen) >= self.config.max_results:
            return (EventKind.DIAGNOSTIC,
                    {"code": QUOTA_EXHAUSTED, "message": "global result cap reached",
                     "provider": provider, "blocking": False}, 0.0)
        if self._per_provider.get(provider, 0) >= self.config.max_results_per_provider:
            return (EventKind.DIAGNOSTIC,
                    {"code": QUOTA_EXHAUSTED, "message": f"per-provider cap reached for {provider}",
                     "provider": provider, "blocking": False}, 0.0)

        self._succeeded_providers.add(provider)
        self._per_provider[provider] = self._per_provider.get(provider, 0) + 1
        if host in self._seen:
            return None  # already reported by another provider; dedup keeps provenance upstream
        self._seen.add(host)

        return (EventKind.ASSET,
                {"identifier": host, "asset_type": "domain", "provider": provider,
                 "parent_domain": envelope.target}, 1.0)

    def interpret_result(self, result, envelope: ExecutionEnvelope):
        event = super().interpret_result(result, envelope)
        # Partial provider success must never be reported as complete coverage.
        covered = len(self._succeeded_providers)
        complete = covered >= self.config.min_provider_coverage
        event.data.update({
            "providers_succeeded": sorted(self._succeeded_providers),
            "providers_failed": sorted(self._failed_providers),
            "results": len(self._seen),
            "coverage": "complete" if complete else "partial",
        })
        if not complete:
            event.data["status"] = "partial"
        return event
