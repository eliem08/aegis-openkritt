"""Universal vulnerability-family catalog and profit-aware hunt planning.

Severity is an economic signal, never a hard filter. Low- and medium-severity
hypotheses remain eligible when they are novel, cheap to validate, chainable,
or otherwise have positive expected net value.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable


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
    expected_payout_usd: float
    p_valid: float
    p_accepted: float
    p_unique: float
    p_reproducible: float
    validation_cost_usd: float
    human_review_cost_usd: float = 0.0
    novelty_score: float = 0.0
    chainability: float = 0.0
    coverage_gap: float = 0.0

    @property
    def expected_net_usd(self) -> float:
        probability = 1.0
        for value in (self.p_valid, self.p_accepted, self.p_unique, self.p_reproducible):
            probability *= max(0.0, min(1.0, value))
        return self.expected_payout_usd * probability - (
            max(0.0, self.validation_cost_usd) + max(0.0, self.human_review_cost_usd)
        )

    @property
    def priority_score(self) -> float:
        # Severity does not gate eligibility. It contributes only a modest prior.
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
    WeaknessFamily("authn", "Authentication and session flaws", ("CWE-287", "CWE-384"), ("web", "api", "mobile", "websocket"), ("source", "traffic", "session-state"), ("authentication", "business_logic"), "local-differential", SeverityTier.HIGH, ("account-takeover",)),
    WeaknessFamily("authz", "Authorization, IDOR, BOLA, tenancy", ("CWE-639", "CWE-862", "CWE-863"), ("web", "api", "graphql", "websocket", "jobs"), ("source", "identity-differential", "database-state"), ("authorization", "business_logic"), "local-multi-identity", SeverityTier.HIGH, ("data-exposure", "privilege-escalation")),
    WeaknessFamily("workflow", "Business-logic and workflow violations", ("CWE-840",), ("web", "api", "jobs", "payments", "entitlements"), ("state-machine", "source", "runtime-state"), ("business_logic", "invariant"), "local-state-machine", SeverityTier.MEDIUM, ("authorization", "race")),
    WeaknessFamily("race", "Race conditions and atomicity flaws", ("CWE-362",), ("api", "jobs", "payments", "quotas"), ("source", "transaction-boundaries", "runtime-state"), ("business_logic", "reproduction"), "bounded-local-concurrency", SeverityTier.MEDIUM, ("workflow", "financial-impact")),
    WeaknessFamily("injection", "SQL, command, template and interpreter injection", ("CWE-78", "CWE-89", "CWE-94", "CWE-1336"), ("web", "api", "jobs"), ("taint-path", "source", "runtime-oracle"), ("static_analysis", "dataflow", "reproduction"), "local-synthetic-input", SeverityTier.HIGH),
    WeaknessFamily("ssrf", "Server-side request forgery", ("CWE-918",), ("web", "api", "imports", "webhooks", "image-processing"), ("taint-path", "network-call", "oast-or-local-sink"), ("dataflow", "reproduction"), "local-controlled-endpoint", SeverityTier.HIGH, ("cloud", "metadata")),
    WeaknessFamily("file", "File upload, traversal and archive handling", ("CWE-22", "CWE-434", "CWE-73"), ("web", "api", "imports", "archives"), ("source", "filesystem-effects", "mime-parser"), ("static_analysis", "reproduction"), "local-temp-filesystem", SeverityTier.MEDIUM, ("code-execution", "data-exposure")),
    WeaknessFamily("deserialize", "Unsafe deserialization and parser confusion", ("CWE-502", "CWE-444"), ("api", "queues", "imports", "proxies"), ("parser-boundaries", "source", "runtime-differential"), ("dataflow", "business_logic"), "local-parser-differential", SeverityTier.HIGH),
    WeaknessFamily("client", "Client-side injection and trust-boundary flaws", ("CWE-79", "CWE-601", "CWE-352"), ("web", "spa", "browser"), ("dom-flow", "browser-trace", "source"), ("client", "reproduction"), "local-browser", SeverityTier.MEDIUM),
    WeaknessFamily("api", "API, GraphQL and WebSocket protocol flaws", ("CWE-285", "CWE-770"), ("api", "graphql", "websocket"), ("schema", "traffic", "stateful-sequence"), ("api", "authorization"), "bounded-local-sequence", SeverityTier.MEDIUM, ("authz", "dos-avoided")),
    WeaknessFamily("crypto", "Cryptography, token and key-management weaknesses", ("CWE-327", "CWE-347", "CWE-798"), ("source", "api", "ci", "config"), ("source", "configuration", "token-validation"), ("static_analysis", "authentication"), "offline-analysis", SeverityTier.MEDIUM),
    WeaknessFamily("supply", "Dependency and supply-chain exposure", ("CWE-1104", "CWE-1395"), ("dependencies", "build", "ci"), ("lockfile", "call-reachability", "provenance"), ("dependency", "repository_intelligence"), "offline-reachability", SeverityTier.MEDIUM),
    WeaknessFamily("cloud", "Cloud, IaC and permission-boundary weaknesses", ("CWE-284", "CWE-732"), ("iac", "cloud-config", "ci"), ("source", "policy-graph", "config"), ("cloud", "attack_surface"), "offline-config-analysis", SeverityTier.HIGH),
    WeaknessFamily("privacy", "Information disclosure and privacy leakage", ("CWE-200", "CWE-209"), ("web", "api", "logs", "errors"), ("responses", "logs", "source"), ("evidence", "business_logic"), "local-response-differential", SeverityTier.LOW, ("authz", "privacy")),
    WeaknessFamily("headers", "Security headers, cookie and cache-control flaws", ("CWE-614", "CWE-525"), ("web", "cdn", "proxy"), ("headers", "browser-state", "cache-behavior"), ("client", "attack_surface"), "read-only-local", SeverityTier.LOW, ("session", "privacy")),
    WeaknessFamily("misconfig", "Security-relevant misconfiguration", ("CWE-16",), ("web", "api", "cloud", "ci", "containers"), ("configuration", "runtime-metadata", "source"), ("cloud", "repository_intelligence"), "offline-config-analysis", SeverityTier.LOW),
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
