"""Production dispatch adapters for existing deterministic hunter intelligence."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import Mapping

from .execution_errors import MissionPrerequisiteError
from .exploit_chain_intelligence import EvidenceCapability, ExploitChainAgentV2
from .hunter_techniques import HunterTechnique
from .javascript_intelligence import JavaScriptIntelligenceAgent
from .recon_intelligence import CertificateRecord, ReconCorrelationAgent


class DeterministicHunterExecutorProvider:
    """Adapt analysis-only agents to exact canonical runtime capabilities."""

    JS_ROUTE = "jarvis:research:javascript_route_recovery"
    SOURCE_MAP = "jarvis:research:source_map_recovery"
    PUBLIC_IDENTIFIERS = "jarvis:research:correlate_public_identifiers"
    CERTIFICATE_CLUSTER = "jarvis:research:correlate_certificate_cluster"
    EXPLOIT_CHAIN = "jarvis:research:exploit-capability-chain"

    def __init__(self, *, grant_verifier) -> None:
        self.grant_verifier = grant_verifier
        self.javascript = JavaScriptIntelligenceAgent()
        self.recon = ReconCorrelationAgent()
        self.chains = ExploitChainAgentV2()

    def runtime_executors(self) -> dict[str, object]:
        return {
            self.JS_ROUTE: self._javascript_routes,
            self.SOURCE_MAP: self._source_maps,
            self.PUBLIC_IDENTIFIERS: self._public_identifiers,
            self.CERTIFICATE_CLUSTER: self._certificate_clusters,
            self.EXPLOIT_CHAIN: self._exploit_chains,
        }

    def _authorize(self, task, plan, authorization):
        grant = authorization.grant
        if (
            task.executor_capability not in self.runtime_executors()
            or task.risk not in {"offline", "read_only"}
            or grant is None or authorization.scope_digest != plan.scope_digest
            or grant.scope_digest != plan.scope_digest or not grant.verify(self.grant_verifier)
            or not grant.human_approval
        ):
            raise PermissionError("deterministic hunter execution requires an exact verified grant")
        evidence = tuple(str(item) for item in (task.payload or {}).get("provenance_evidence") or ())
        if not evidence:
            raise MissionPrerequisiteError("deterministic hunter input requires provenance evidence")
        return evidence

    def _js_inputs(self, task):
        payload = task.payload or {}
        bundles = payload.get("bundles") or {}
        maps = payload.get("source_maps") or {}
        if not isinstance(bundles, Mapping) or not bundles:
            raise MissionPrerequisiteError("authorized JavaScript bundle content is required")
        if not isinstance(maps, Mapping):
            raise MissionPrerequisiteError("source_maps must be a mapping")
        if sum(len(str(value).encode()) for value in bundles.values()) > 16_777_216:
            raise MissionPrerequisiteError("JavaScript artifact budget exceeded")
        return (
            {str(key): str(value) for key, value in bundles.items()},
            dict(maps),
            {str(item) for item in payload.get("scope_hosts") or ()},
        )

    def _javascript_routes(self, task, plan, authorization):
        self._authorize(task, plan, authorization)
        bundles, maps, scope = self._js_inputs(task)
        return tuple(
            row for row in self.javascript.analyze(
                bundles, source_maps=maps, scope_hosts=scope,
            ) if row.technique is HunterTechnique.JS_ROUTE_RECOVERY
        )

    def _source_maps(self, task, plan, authorization):
        self._authorize(task, plan, authorization)
        bundles, maps, scope = self._js_inputs(task)
        if not maps:
            raise MissionPrerequisiteError("authorized source-map artifact is required")
        return tuple(
            row for row in self.javascript.analyze(
                bundles, source_maps=maps, scope_hosts=scope,
            ) if row.technique is HunterTechnique.JS_SOURCE_MAP_RECOVERY
        )

    def _public_identifiers(self, task, plan, authorization):
        self._authorize(task, plan, authorization)
        bundles, maps, scope = self._js_inputs(task)
        discoveries = self.javascript.analyze(bundles, source_maps=maps, scope_hosts=scope)
        return tuple(
            row for row in self.recon.correlate(
                javascript=discoveries, authorized_hosts=scope,
            ) if row.technique is HunterTechnique.RECON_ANALYTICS_CORRELATION
        )

    def _certificate_clusters(self, task, plan, authorization):
        self._authorize(task, plan, authorization)
        payload = task.payload or {}
        rows = payload.get("certificates") or ()
        if not rows:
            raise MissionPrerequisiteError("certificate snapshot records are required")
        try:
            certificates = tuple(CertificateRecord(
                fingerprint=str(row["fingerprint"]),
                sans=tuple(str(item) for item in row["sans"]),
                issuer=str(row["issuer"]), subject=str(row["subject"]), serial=str(row["serial"]),
                not_before=datetime.fromisoformat(str(row["not_before"])),
                not_after=datetime.fromisoformat(str(row["not_after"])),
                observed_at=datetime.fromisoformat(str(row["observed_at"])),
                source=str(row.get("source") or "certificate_transparency"),
            ) for row in rows)
        except (KeyError, TypeError, ValueError) as exc:
            raise MissionPrerequisiteError("certificate snapshot record is invalid") from exc
        scope = {str(item) for item in payload.get("scope_hosts") or ()}
        return tuple(
            row for row in self.recon.correlate(
                certificates=certificates, authorized_hosts=scope,
            ) if row.technique is HunterTechnique.RECON_CT_CLUSTERING
        )

    def _exploit_chains(self, task, plan, authorization):
        self._authorize(task, plan, authorization)
        payload = task.payload or {}
        try:
            capabilities = tuple(EvidenceCapability(
                capability_id=str(row["capability_id"]), technique=str(row["technique"]),
                requires=tuple(str(item) for item in row.get("requires") or ()),
                produces=tuple(str(item) for item in row.get("produces") or ()),
                confidence=float(row["confidence"]),
                validation_cost_usd=Decimal(str(row.get("validation_cost_usd") or 0)),
                expected_payout_usd=(Decimal(str(row["expected_payout_usd"]))
                                     if row.get("expected_payout_usd") is not None else None),
                evidence=tuple(str(item) for item in row.get("evidence") or ()),
                authorized=bool(row.get("authorized")),
                prerequisite_state=str(row.get("prerequisite_state") or "ready"),
            ) for row in payload["capabilities"])
        except (KeyError, TypeError, ValueError) as exc:
            raise MissionPrerequisiteError("evidence capabilities are invalid") from exc
        if not capabilities or any(not row.evidence for row in capabilities):
            raise MissionPrerequisiteError("exploit chaining requires evidence-backed capabilities")
        return self.chains.build(
            capabilities,
            initial_capabilities=tuple(str(item) for item in payload.get("initial_capabilities") or ()),
            max_depth=int(payload.get("max_depth") or 4),
        )


__all__ = ["DeterministicHunterExecutorProvider"]
