"""Registry for higher-order hunter techniques compiled into canonical missions."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from ..agentic_os import RiskClass


class HunterTechnique(str, Enum):
    RECON_ANALYTICS_CORRELATION = "recon_analytics_correlation"
    RECON_CT_CLUSTERING = "recon_ct_clustering"
    RECON_VHOST_INFERENCE = "recon_vhost_inference"
    JS_ROUTE_RECOVERY = "js_route_recovery"
    JS_SOURCE_MAP_RECOVERY = "js_source_map_recovery"


@dataclass(frozen=True)
class TechniqueDefinition:
    technique: HunterTechnique
    required_observations: tuple[str, ...]
    compatible_asset_types: tuple[str, ...]
    required_prerequisites: tuple[str, ...]
    risk_class: RiskClass
    worker_capability: str
    evidence_requirements: tuple[str, ...]


TECHNIQUES: dict[HunterTechnique, TechniqueDefinition] = {
    HunterTechnique.RECON_ANALYTICS_CORRELATION: TechniqueDefinition(
        HunterTechnique.RECON_ANALYTICS_CORRELATION,
        ("public_tracking_identifier",),
        ("domain", "wildcard"),
        ("scope_confirmation_for_inferred_asset",),
        RiskClass.OFFLINE,
        "jarvis:research:correlate_public_identifiers",
        ("identifier_digest", "two_distinct_source_assets", "timestamp"),
    ),
    HunterTechnique.RECON_CT_CLUSTERING: TechniqueDefinition(
        HunterTechnique.RECON_CT_CLUSTERING,
        ("certificate_san", "certificate_fingerprint"),
        ("domain", "wildcard", "ip_address"),
        ("scope_confirmation_for_inferred_asset",),
        RiskClass.OFFLINE,
        "jarvis:research:correlate_certificate_cluster",
        ("certificate_fingerprint", "san", "observation_timestamp"),
    ),
    HunterTechnique.RECON_VHOST_INFERENCE: TechniqueDefinition(
        HunterTechnique.RECON_VHOST_INFERENCE,
        ("authorized_ip", "evidence_derived_hostname"),
        ("ip_address", "cidr"),
        ("authorized_ip", "scope_confirmed_hostname", "network_execution_grant"),
        RiskClass.READ_ONLY,
        "dynamic:vhost-routing-differential",
        ("known_hostname_source", "bounded_candidate_set", "response_digest"),
    ),
    HunterTechnique.JS_ROUTE_RECOVERY: TechniqueDefinition(
        HunterTechnique.JS_ROUTE_RECOVERY,
        ("authorized_javascript_artifact",),
        ("domain", "api", "source_code", "android_apk", "ios_ipa"),
        ("authorized_artifact",),
        RiskClass.OFFLINE,
        "jarvis:research:javascript_route_recovery",
        ("bundle_digest", "exact_source", "line"),
    ),
    HunterTechnique.JS_SOURCE_MAP_RECOVERY: TechniqueDefinition(
        HunterTechnique.JS_SOURCE_MAP_RECOVERY,
        ("authorized_javascript_artifact", "public_source_map"),
        ("domain", "source_code"),
        ("authorized_artifact",),
        RiskClass.OFFLINE,
        "jarvis:research:source_map_recovery",
        ("bundle_digest", "source_map_digest", "original_filename"),
    ),
}


def technique_definition(technique: HunterTechnique) -> TechniqueDefinition:
    return TECHNIQUES[technique]


__all__ = [
    "HunterTechnique",
    "TECHNIQUES",
    "TechniqueDefinition",
    "technique_definition",
]
