"""Universal vulnerability-family catalog and profit-aware hunt planning.

Severity is an economic signal, never a hard filter. Informational, low, and
medium hypotheses remain eligible when they are novel, cheap to validate,
chainable, or otherwise have positive expected net value.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from enum import Enum
from typing import Iterable

from aegis.scheduler.profit import HuntOpportunity


class SeverityTier(str, Enum):
    INFO = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class WeaknessFamily:
    family_id: str
    title: str
    cwes: tuple[str, ...]
    surfaces: tuple[str, ...]
    evidence_sources: tuple[str, ...]
    specialist_roles: tuple[str, ...]
    default_validation_mode: str
    baseline_severity: SeverityTier
    chain_tags: tuple[str, ...] = ()


@dataclass(frozen=True)
class HuntCandidate:
    family: WeaknessFamily
    surface: str
    severity: SeverityTier
    expected_payout_usd: float | None
    p_valid: float
    p_accepted: float
    p_unique: float
    p_reproducible: float
    validation_cost_usd: float
    human_review_cost_usd: float = 0.0
    novelty_score: float = 0.0
    chainability: float = 0.0
    coverage_gap: float = 0.0
    p_find: float = 1.0
    compute_cost_usd: float = 0.0
    model_cost_usd: float = 0.0
    scanner_cost_usd: float = 0.0

    @property
    def expected_net_usd(self) -> float:
        return self.to_opportunity(opportunity_id="candidate:economics").expected_value()

    def to_opportunity(self, *, opportunity_id: str, program_id: str = "",
                       program_handle: str = "", asset_id: str = "",
                       asset_kind: str = "unresolved", asset_locator: str = "",
                       scope_digest: str = "", authorization_id: str = "",
                       prerequisite_state: str = "ready",
                       provenance: tuple[str, ...] = ()) -> HuntOpportunity:
        """Adapt the legacy candidate shape into the canonical opportunity."""
        payout = None if self.expected_payout_usd is None else Decimal(str(self.expected_payout_usd))
        return HuntOpportunity(
            opportunity_id=opportunity_id,
            program_id=program_id,
            program_handle=program_handle,
            asset_id=asset_id,
            asset_kind=asset_kind,
            asset_locator=asset_locator,
            scope_digest=scope_digest,
            authorization_id=authorization_id,
            attack_surface=self.surface,
            weakness_family=self.family.family_id,
            prerequisite_state=prerequisite_state,
            coverage_score=max(0.0, min(1.0, self.coverage_gap)),
            estimated_payout_usd=payout,
            p_find=max(0.0, min(1.0, self.p_find)),
            p_valid=max(0.0, min(1.0, self.p_valid)),
            p_unique=max(0.0, min(1.0, self.p_unique)),
            p_accepted=max(0.0, min(1.0, self.p_accepted)),
            p_reproducible=max(0.0, min(1.0, self.p_reproducible)),
            compute_cost_usd=max(0.0, self.compute_cost_usd),
            model_cost_usd=max(0.0, self.model_cost_usd),
            scanner_cost_usd=max(0.0, self.scanner_cost_usd),
            validation_cost_usd=max(0.0, self.validation_cost_usd),
            human_cost_usd=max(0.0, self.human_review_cost_usd),
            information_gain=max(0.0, min(1.0, self.novelty_score)),
            uncertainty=max(0.0, min(1.0, 1.0 - self.p_valid)),
            provenance=provenance or ("aegis.ai.jarvis.HuntCandidate",),
        )

    @property
    def priority_score(self) -> float:
        severity_bonus = {
            SeverityTier.INFO: 0.00,
            SeverityTier.LOW: 0.05,
            SeverityTier.MEDIUM: 0.12,
            SeverityTier.HIGH: 0.20,
            SeverityTier.CRITICAL: 0.28,
        }[self.severity]
        economic = self.expected_net_usd / max(self.validation_cost_usd + 1.0, 1.0)
        return (
            economic
            + severity_bonus
            + 0.55 * max(0.0, min(1.0, self.novelty_score))
            + 0.60 * max(0.0, min(1.0, self.chainability))
            + 0.45 * max(0.0, min(1.0, self.coverage_gap))
        )


UNIVERSAL_FAMILIES: tuple[WeaknessFamily, ...] = (
    WeaknessFamily("authn", "Authentication and session flaws", ("CWE-287", "CWE-384"), ("web", "api", "mobile", "websocket"), ("source", "traffic", "session-state"), ("authentication", "business_logic"), "local-differential", SeverityTier.HIGH, ("account-takeover", "session")),
    WeaknessFamily("oauth", "OAuth, OIDC, SAML and account-recovery trust flaws", ("CWE-287", "CWE-601"), ("web", "api", "mobile", "sso"), ("redirect-state", "token-validation", "source"), ("authentication", "business_logic"), "local-identity-provider", SeverityTier.MEDIUM, ("session", "account-takeover")),
    WeaknessFamily("authz", "Authorization, IDOR, BOLA and tenancy", ("CWE-639", "CWE-862", "CWE-863"), ("web", "api", "graphql", "websocket", "jobs"), ("source", "identity-differential", "database-state"), ("authorization", "business_logic"), "local-multi-identity", SeverityTier.HIGH, ("data-exposure", "privilege-escalation", "authz")),
    WeaknessFamily("workflow", "Business-logic and workflow violations", ("CWE-840",), ("web", "api", "jobs", "payments", "entitlements"), ("state-machine", "source", "runtime-state"), ("business_logic", "invariant"), "local-state-machine", SeverityTier.MEDIUM, ("authorization", "race", "workflow")),
    WeaknessFamily("race", "Race conditions and atomicity flaws", ("CWE-362",), ("api", "jobs", "payments", "quotas"), ("source", "transaction-boundaries", "runtime-state"), ("business_logic", "reproduction"), "bounded-local-concurrency", SeverityTier.MEDIUM, ("workflow", "financial-impact", "race")),
    WeaknessFamily("injection", "SQL, NoSQL, command, template and interpreter injection", ("CWE-78", "CWE-89", "CWE-943", "CWE-94", "CWE-1336"), ("web", "api", "jobs"), ("taint-path", "source", "runtime-oracle"), ("static_analysis", "dataflow", "reproduction"), "local-synthetic-input", SeverityTier.HIGH),
    WeaknessFamily("ssrf", "Server-side request forgery", ("CWE-918",), ("web", "api", "imports", "webhooks", "image-processing"), ("taint-path", "network-call", "oast-or-local-sink"), ("dataflow", "reproduction"), "local-controlled-endpoint", SeverityTier.HIGH, ("cloud", "metadata", "ssrf")),
    WeaknessFamily("file", "File upload, traversal and archive handling", ("CWE-22", "CWE-434", "CWE-73"), ("web", "api", "imports", "archives"), ("source", "filesystem-effects", "mime-parser"), ("static_analysis", "reproduction"), "local-temp-filesystem", SeverityTier.MEDIUM, ("code-execution", "data-exposure", "file")),
    WeaknessFamily("xml", "XML, entity and document-parser weaknesses", ("CWE-611", "CWE-827"), ("api", "imports", "documents"), ("parser-config", "source", "local-document-result"), ("dataflow", "reproduction"), "local-parser-fixture", SeverityTier.MEDIUM, ("ssrf", "file")),
    WeaknessFamily("deserialize", "Unsafe deserialization and parser confusion", ("CWE-502", "CWE-444"), ("api", "queues", "imports", "proxies"), ("parser-boundaries", "source", "runtime-differential"), ("dataflow", "business_logic"), "local-parser-differential", SeverityTier.HIGH, ("parser",)),
    WeaknessFamily("binding", "Mass assignment, object binding and over-posting", ("CWE-915",), ("web", "api", "graphql"), ("schema", "model-fields", "identity-differential"), ("api", "authorization", "business_logic"), "local-object-differential", SeverityTier.MEDIUM, ("authz", "privilege-escalation")),
    WeaknessFamily("prototype", "Prototype pollution and unsafe object merging", ("CWE-1321",), ("web", "api", "spa", "jobs"), ("source", "object-flow", "local-state"), ("static_analysis", "dataflow"), "local-object-fixture", SeverityTier.MEDIUM, ("client", "workflow")),
    WeaknessFamily("client", "Client-side injection and trust-boundary flaws", ("CWE-79", "CWE-601"), ("web", "spa", "browser", "mobile"), ("dom-flow", "browser-trace", "source"), ("client", "reproduction"), "local-browser", SeverityTier.MEDIUM, ("client", "session")),
    WeaknessFamily("csrf_cors", "CSRF, CORS and cross-origin trust mistakes", ("CWE-352", "CWE-942"), ("web", "api", "browser"), ("headers", "browser-state", "source"), ("client", "authentication"), "local-browser-origin", SeverityTier.LOW, ("session", "authz")),
    WeaknessFamily("redirect", "Open redirect, deep-link and navigation trust flaws", ("CWE-601",), ("web", "mobile", "browser"), ("source", "navigation-result", "allowlist"), ("client", "authentication"), "local-navigation", SeverityTier.LOW, ("oauth", "client")),
    WeaknessFamily("api", "API, GraphQL and WebSocket protocol flaws", ("CWE-285", "CWE-770"), ("api", "graphql", "websocket"), ("schema", "traffic", "stateful-sequence"), ("api", "authorization"), "bounded-local-sequence", SeverityTier.MEDIUM, ("authz",)),
    WeaknessFamily("proxy", "Proxy, cache, host-header and HTTP interpretation inconsistencies", ("CWE-444", "CWE-441"), ("web", "proxy", "cdn"), ("request-boundaries", "cache-key", "host-routing", "local-differential"), ("attack_surface", "business_logic"), "local-proxy-differential", SeverityTier.MEDIUM, ("cache", "parser", "privacy")),
    WeaknessFamily("crypto", "Cryptography, token and key-management weaknesses", ("CWE-327", "CWE-347", "CWE-798"), ("source", "api", "ci", "config"), ("source", "configuration", "token-validation"), ("static_analysis", "authentication"), "offline-analysis", SeverityTier.MEDIUM, ("session",)),
    WeaknessFamily("supply", "Dependency and supply-chain exposure", ("CWE-1104", "CWE-1395"), ("dependencies", "build", "ci"), ("lockfile", "call-reachability", "provenance"), ("dependency", "repository_intelligence"), "offline-reachability", SeverityTier.MEDIUM),
    WeaknessFamily("cicd", "CI/CD trust, artifact and permission mistakes", ("CWE-269", "CWE-732"), ("ci", "build"), ("workflow-config", "permission-graph", "artifact-provenance"), ("repository_intelligence", "cloud"), "offline-workflow-analysis", SeverityTier.MEDIUM, ("supply-chain", "secrets")),
    WeaknessFamily("cloud", "Cloud, IaC and permission-boundary weaknesses", ("CWE-284", "CWE-732"), ("iac", "cloud-config", "ci"), ("source", "policy-graph", "config"), ("cloud", "attack_surface"), "offline-config-analysis", SeverityTier.HIGH, ("cloud",)),
    WeaknessFamily("webhook", "Webhook and callback trust-boundary weaknesses", ("CWE-345", "CWE-918"), ("webhooks", "api"), ("signature-validation", "source", "callback-state"), ("authentication", "business_logic"), "local-signed-callback", SeverityTier.MEDIUM, ("ssrf", "workflow")),
    WeaknessFamily("resource", "Resource, quota and algorithmic abuse paths", ("CWE-400", "CWE-770"), ("api", "jobs", "uploads", "search"), ("source", "limits", "complexity", "local-bounds"), ("business_logic", "static_analysis"), "offline-or-bounded-local", SeverityTier.LOW, ("workflow",)),
    WeaknessFamily("privacy", "Information disclosure and privacy leakage", ("CWE-200", "CWE-209"), ("web", "api", "logs", "errors"), ("responses", "logs", "source"), ("evidence", "business_logic"), "local-response-differential", SeverityTier.LOW, ("authz", "privacy")),
    WeaknessFamily("headers", "Security headers, cookie and cache-control flaws", ("CWE-614", "CWE-525"), ("web", "cdn", "proxy"), ("headers", "browser-state", "cache-behavior"), ("client", "attack_surface"), "read-only-local", SeverityTier.LOW, ("session", "privacy", "cache")),
    WeaknessFamily("misconfig", "Security-relevant misconfiguration", ("CWE-16",), ("web", "api", "cloud-config", "ci", "containers", "config"), ("configuration", "runtime-metadata", "source"), ("cloud", "repository_intelligence"), "offline-config-analysis", SeverityTier.LOW),
    WeaknessFamily("debug", "Debug, version and internal metadata exposure", ("CWE-200",), ("web", "api", "errors", "logs"), ("responses", "configuration", "source"), ("attack_surface", "evidence"), "read-only-local", SeverityTier.INFO, ("privacy", "version-intel")),
)


def families_for_surface(surface: str) -> tuple[WeaknessFamily, ...]:
    normalized = surface.strip().lower()
    return tuple(family for family in UNIVERSAL_FAMILIES if normalized in family.surfaces)


def rank_candidates(candidates: Iterable[HuntCandidate], *, minimum_net_usd: float = 0.0) -> tuple[HuntCandidate, ...]:
    eligible = [candidate for candidate in candidates if candidate.expected_net_usd >= minimum_net_usd]
    return tuple(
        sorted(
            eligible,
            key=lambda candidate: (
                candidate.priority_score,
                candidate.expected_net_usd,
                candidate.novelty_score,
                candidate.family.family_id,
            ),
            reverse=True,
        )
    )
