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
    AUTH_OBJECT_DIFFERENTIAL = "auth_object_differential"
    AUTH_ROLE_DIFFERENTIAL = "auth_role_differential"
    AUTH_TENANT_DIFFERENTIAL = "auth_tenant_differential"
    BUSINESS_STATE_COMBINATION = "business_state_combination"
    POST_ERROR_STATE_CHECK = "post_error_state_check"
    PARTIAL_COMMIT_VERIFICATION = "partial_commit_verification"
    SSRF_URL_CONSUMER = "ssrf_url_consumer"
    SSRF_ASYNC_CALLBACK = "ssrf_async_callback"
    SSRF_REDIRECT_DNS_BEHAVIOR = "ssrf_redirect_dns_behavior"


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
    HunterTechnique.AUTH_OBJECT_DIFFERENTIAL: TechniqueDefinition(
        HunterTechnique.AUTH_OBJECT_DIFFERENTIAL,
        ("controlled_owner", "controlled_non_owner", "synthetic_object"),
        ("api", "domain", "source_code"),
        ("two_controlled_identities", "explicit_expected_policy", "signed_execution_grant"),
        RiskClass.CONTROLLED_STATE_CHANGE,
        "dynamic:identity-object-differential",
        ("owner_control", "non_owner_probe", "unique_canary", "response_digest"),
    ),
    HunterTechnique.AUTH_ROLE_DIFFERENTIAL: TechniqueDefinition(
        HunterTechnique.AUTH_ROLE_DIFFERENTIAL,
        ("controlled_low_role", "controlled_high_role", "privileged_operation"),
        ("api", "domain"),
        ("two_controlled_roles", "explicit_expected_policy", "signed_execution_grant"),
        RiskClass.CONTROLLED_STATE_CHANGE,
        "dynamic:identity-role-differential",
        ("allowed_role_control", "lower_role_probe", "response_digest", "state_digest"),
    ),
    HunterTechnique.AUTH_TENANT_DIFFERENTIAL: TechniqueDefinition(
        HunterTechnique.AUTH_TENANT_DIFFERENTIAL,
        ("controlled_tenant_a", "controlled_tenant_b", "synthetic_object"),
        ("api", "domain"),
        ("two_controlled_tenants", "explicit_expected_policy", "signed_execution_grant"),
        RiskClass.CONTROLLED_STATE_CHANGE,
        "dynamic:identity-tenant-differential",
        ("same_tenant_control", "cross_tenant_probe", "unique_canary", "state_digest"),
    ),
    HunterTechnique.BUSINESS_STATE_COMBINATION: TechniqueDefinition(
        HunterTechnique.BUSINESS_STATE_COMBINATION,
        ("observed_lifecycle_states", "explicit_transition_expectation"),
        ("api", "domain", "smart_contract"),
        ("synthetic_resource", "bounded_transition_set", "signed_execution_grant"),
        RiskClass.CONTROLLED_STATE_CHANGE,
        "dynamic:lifecycle-state-differential",
        ("pre_state", "attempted_transition", "post_state", "negative_control"),
    ),
    HunterTechnique.POST_ERROR_STATE_CHECK: TechniqueDefinition(
        HunterTechnique.POST_ERROR_STATE_CHECK,
        ("error_or_timeout", "pre_state", "post_state"),
        ("api", "domain", "smart_contract"),
        ("synthetic_resource", "state_readback", "signed_execution_grant"),
        RiskClass.CONTROLLED_STATE_CHANGE,
        "dynamic:post-error-state-verifier",
        ("operation_response", "pre_state_digest", "post_state_digest", "correlation_id"),
    ),
    HunterTechnique.PARTIAL_COMMIT_VERIFICATION: TechniqueDefinition(
        HunterTechnique.PARTIAL_COMMIT_VERIFICATION,
        ("expected_atomic_effects", "observed_effects", "state_readback"),
        ("api", "domain", "smart_contract"),
        ("synthetic_resource", "explicit_expected_effects", "signed_execution_grant"),
        RiskClass.CONTROLLED_STATE_CHANGE,
        "dynamic:partial-commit-verifier",
        ("before_snapshot", "after_snapshot", "effect_set", "negative_control"),
    ),
    HunterTechnique.SSRF_URL_CONSUMER: TechniqueDefinition(
        HunterTechnique.SSRF_URL_CONSUMER,
        ("discovered_url_input", "exact_private_oast_callback"),
        ("api", "domain"),
        ("authorized_route", "private_oast_session", "signed_execution_grant"),
        RiskClass.CONTROLLED_STATE_CHANGE,
        "dynamic:server-url-consumer",
        ("route", "parameter", "probe_address", "matched_interaction", "negative_control"),
    ),
    HunterTechnique.SSRF_ASYNC_CALLBACK: TechniqueDefinition(
        HunterTechnique.SSRF_ASYNC_CALLBACK,
        ("queued_url_input", "delayed_private_oast_callback"),
        ("api", "domain"),
        ("authorized_route", "durable_oast_polling", "signed_execution_grant"),
        RiskClass.CONTROLLED_STATE_CHANGE,
        "dynamic:async-url-consumer",
        ("job_correlation", "probe_address", "callback_delay", "matched_interaction"),
    ),
    HunterTechnique.SSRF_REDIRECT_DNS_BEHAVIOR: TechniqueDefinition(
        HunterTechnique.SSRF_REDIRECT_DNS_BEHAVIOR,
        ("url_consumer_probe", "redirect_or_dns_observations"),
        ("api", "domain"),
        ("private_oast_session", "controlled_redirector", "signed_execution_grant"),
        RiskClass.CONTROLLED_STATE_CHANGE,
        "dynamic:url-consumer-behavior-classifier",
        ("redirect_chain", "dns_resolution_sequence", "exact_probe_correlation"),
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
