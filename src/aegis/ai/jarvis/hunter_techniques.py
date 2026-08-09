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
    CACHE_KEY_DIFFERENTIAL = "cache_key_differential"
    CACHE_PRIVATE_SHARED = "cache_private_shared"
    WEB_CACHE_DECEPTION = "web_cache_deception"
    RACE_SYNCHRONIZED_DIFFERENTIAL = "race_synchronized_differential"
    IDEMPOTENCY_KEY_DIFFERENTIAL = "idempotency_key_differential"
    RETRY_STATE_VERIFICATION = "retry_state_verification"
    OAUTH_TRUST_DIFFERENTIAL = "oauth_trust_differential"
    POSTMESSAGE_TRUST_ANALYSIS = "postmessage_trust_analysis"
    RECOVERY_STATE_DIFFERENTIAL = "recovery_state_differential"
    SESSION_INVALIDATION_DIFFERENTIAL = "session_invalidation_differential"
    UPLOAD_WORKFLOW_DIFFERENTIAL = "upload_workflow_differential"
    MOBILE_BACKEND_CORRELATION = "mobile_backend_correlation"
    GRAPHQL_AUTHORIZATION_DIFFERENTIAL = "graphql_authorization_differential"
    WEBSOCKET_STATE_DIFFERENTIAL = "websocket_state_differential"
    GRPC_AUTHORIZATION_DIFFERENTIAL = "grpc_authorization_differential"
    DEEP_LINK_TRUST_DIFFERENTIAL = "deep_link_trust_differential"


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
    HunterTechnique.CACHE_KEY_DIFFERENTIAL: TechniqueDefinition(
        HunterTechnique.CACHE_KEY_DIFFERENTIAL,
        ("controlled_prime", "cross-client_fetch", "negative_control"),
        ("domain", "api"),
        ("authorized_cache_experiment", "synthetic_marker", "signed_execution_grant"),
        RiskClass.CONTROLLED_STATE_CHANGE,
        "dynamic:cache-key-differential",
        ("prime_capture", "victim_capture", "negative_control", "cache_headers"),
    ),
    HunterTechnique.CACHE_PRIVATE_SHARED: TechniqueDefinition(
        HunterTechnique.CACHE_PRIVATE_SHARED,
        ("authenticated_canary_response", "distinct_client_fetch"),
        ("domain", "api"),
        ("two_controlled_clients", "synthetic_private_marker", "signed_execution_grant"),
        RiskClass.CONTROLLED_STATE_CHANGE,
        "dynamic:private-shared-cache-differential",
        ("identity_a_capture", "identity_b_capture", "private_canary", "age_or_cache_status"),
    ),
    HunterTechnique.WEB_CACHE_DECEPTION: TechniqueDefinition(
        HunterTechnique.WEB_CACHE_DECEPTION,
        ("authenticated_dynamic_route", "static_suffix_variant"),
        ("domain", "api"),
        ("synthetic_account", "bounded_path_variant", "signed_execution_grant"),
        RiskClass.CONTROLLED_STATE_CHANGE,
        "dynamic:web-cache-deception",
        ("canonical_route", "variant_route", "cacheability", "cross-client_negative_control"),
    ),
    HunterTechnique.RACE_SYNCHRONIZED_DIFFERENTIAL: TechniqueDefinition(
        HunterTechnique.RACE_SYNCHRONIZED_DIFFERENTIAL,
        ("synthetic_resource", "synchronized_attempts", "post_state_readback"),
        ("api", "domain", "smart_contract"),
        ("bounded_concurrency", "signed_execution_grant", "explicit_invariant"),
        RiskClass.CONTROLLED_STATE_CHANGE,
        "dynamic:bounded-race-harness",
        ("barrier_timestamp", "attempt_results", "before_state", "after_state"),
    ),
    HunterTechnique.IDEMPOTENCY_KEY_DIFFERENTIAL: TechniqueDefinition(
        HunterTechnique.IDEMPOTENCY_KEY_DIFFERENTIAL,
        ("shared_idempotency_key", "multiple_attempts", "effect_readback"),
        ("api", "domain"),
        ("synthetic_resource", "signed_execution_grant", "bounded_retries"),
        RiskClass.CONTROLLED_STATE_CHANGE,
        "dynamic:idempotency-key-differential",
        ("idempotency_key_digest", "attempt_results", "unique_effect_ids"),
    ),
    HunterTechnique.RETRY_STATE_VERIFICATION: TechniqueDefinition(
        HunterTechnique.RETRY_STATE_VERIFICATION,
        ("timeout_or_5xx", "bounded_retry", "state_readback"),
        ("api", "domain"),
        ("synthetic_resource", "signed_execution_grant", "retry_budget"),
        RiskClass.CONTROLLED_STATE_CHANGE,
        "dynamic:retry-state-verifier",
        ("first_attempt", "retry_attempt", "post_state", "effect_ids"),
    ),
    HunterTechnique.OAUTH_TRUST_DIFFERENTIAL: TechniqueDefinition(
        HunterTechnique.OAUTH_TRUST_DIFFERENTIAL,
        ("registered_client_config", "controlled_authorization_flow"),
        ("domain", "api", "android_apk", "ios_ipa"),
        ("controlled_client", "synthetic_account", "signed_execution_grant"),
        RiskClass.CONTROLLED_STATE_CHANGE,
        "dynamic:oauth-trust-differential",
        ("redirect_uri", "state", "nonce", "pkce", "authorization_result"),
    ),
    HunterTechnique.POSTMESSAGE_TRUST_ANALYSIS: TechniqueDefinition(
        HunterTechnique.POSTMESSAGE_TRUST_ANALYSIS,
        ("oauth_message_handler", "sender_origin", "target_origin"),
        ("domain", "source_code", "android_apk", "ios_ipa"),
        ("authorized_artifact_or_browser_flow",),
        RiskClass.READ_ONLY,
        "dynamic:postmessage-trust-differential",
        ("handler_source", "origin_check", "message_shape", "negative_control"),
    ),
    HunterTechnique.RECOVERY_STATE_DIFFERENTIAL: TechniqueDefinition(
        HunterTechnique.RECOVERY_STATE_DIFFERENTIAL,
        ("synthetic_recovery_token", "first_use", "reuse_attempt"),
        ("domain", "api"),
        ("synthetic_account", "signed_execution_grant"),
        RiskClass.CONTROLLED_STATE_CHANGE,
        "dynamic:recovery-state-differential",
        ("token_digest", "first_use", "reuse_result", "session_state"),
    ),
    HunterTechnique.SESSION_INVALIDATION_DIFFERENTIAL: TechniqueDefinition(
        HunterTechnique.SESSION_INVALIDATION_DIFFERENTIAL,
        ("synthetic_session", "invalidation_event", "post_event_probe"),
        ("domain", "api", "android_apk", "ios_ipa"),
        ("synthetic_account", "signed_execution_grant"),
        RiskClass.CONTROLLED_STATE_CHANGE,
        "dynamic:session-invalidation-differential",
        ("session_digest", "event_capture", "post_event_result", "negative_control"),
    ),
    HunterTechnique.UPLOAD_WORKFLOW_DIFFERENTIAL: TechniqueDefinition(
        HunterTechnique.UPLOAD_WORKFLOW_DIFFERENTIAL,
        ("upload_stage", "processing_stage", "retrieval_stage"), ("domain", "api"),
        ("synthetic_file", "bounded_workflow", "signed_execution_grant"),
        RiskClass.CONTROLLED_STATE_CHANGE, "dynamic:upload-workflow-differential",
        ("upload_capture", "processor_result", "retrieval_capture", "synthetic_marker"),
    ),
    HunterTechnique.MOBILE_BACKEND_CORRELATION: TechniqueDefinition(
        HunterTechnique.MOBILE_BACKEND_CORRELATION,
        ("mobile_route", "backend_operation"), ("android_apk", "ios_ipa", "api"),
        ("authorized_artifact", "scope_confirmed_backend"), RiskClass.OFFLINE,
        "jarvis:research:mobile-backend-correlation",
        ("artifact_digest", "mobile_callsite", "backend_route", "scope_status"),
    ),
    HunterTechnique.GRAPHQL_AUTHORIZATION_DIFFERENTIAL: TechniqueDefinition(
        HunterTechnique.GRAPHQL_AUTHORIZATION_DIFFERENTIAL,
        ("controlled_query", "cross_identity_query"), ("api", "domain"),
        ("two_controlled_identities", "signed_execution_grant"),
        RiskClass.CONTROLLED_STATE_CHANGE, "dynamic:graphql-auth-differential",
        ("operation", "field_path", "owner_canary", "negative_control"),
    ),
    HunterTechnique.WEBSOCKET_STATE_DIFFERENTIAL: TechniqueDefinition(
        HunterTechnique.WEBSOCKET_STATE_DIFFERENTIAL,
        ("authorized_socket", "cross_identity_subscription"), ("api", "domain"),
        ("two_controlled_identities", "signed_execution_grant"),
        RiskClass.CONTROLLED_STATE_CHANGE, "dynamic:websocket-state-differential",
        ("handshake", "subscription", "message_canary", "disconnect_state"),
    ),
    HunterTechnique.GRPC_AUTHORIZATION_DIFFERENTIAL: TechniqueDefinition(
        HunterTechnique.GRPC_AUTHORIZATION_DIFFERENTIAL,
        ("grpc_method", "cross_identity_call"), ("api", "domain"),
        ("two_controlled_identities", "signed_execution_grant"),
        RiskClass.CONTROLLED_STATE_CHANGE, "dynamic:grpc-auth-differential",
        ("service_method", "metadata_identity", "owner_canary", "status"),
    ),
    HunterTechnique.DEEP_LINK_TRUST_DIFFERENTIAL: TechniqueDefinition(
        HunterTechnique.DEEP_LINK_TRUST_DIFFERENTIAL,
        ("declared_deep_link", "controlled_sensitive_action"), ("android_apk", "ios_ipa"),
        ("authorized_test_app", "synthetic_account", "signed_execution_grant"),
        RiskClass.CONTROLLED_STATE_CHANGE, "dynamic:deep-link-trust-differential",
        ("link", "handler", "identity_state", "user_confirmation", "result"),
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
