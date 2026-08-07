"""Strategy routing for universal vulnerability families.

Routes hypotheses into safe analysis/validation lanes. Lanes describe evidence
work and local/disposable validation, not unrestricted live exploitation.
"""

from __future__ import annotations

from dataclasses import dataclass

from .weakness_catalog import WeaknessFamily


@dataclass(frozen=True)
class HuntLane:
    lane_id: str
    analysis_steps: tuple[str, ...]
    evidence_required: tuple[str, ...]
    local_validation: bool
    state_change_possible: bool = False


_LANES = {
    "offline-analysis": HuntLane(
        "offline-analysis",
        ("source_review", "configuration_review", "independent_judge"),
        ("source_path", "configuration_evidence"),
        False,
    ),
    "offline-config-analysis": HuntLane(
        "offline-config-analysis",
        ("config_graph", "policy_review", "independent_judge"),
        ("configuration_evidence", "trust_boundary"),
        False,
    ),
    "offline-workflow-analysis": HuntLane(
        "offline-workflow-analysis",
        ("workflow_graph", "permission_graph", "artifact_provenance", "independent_judge"),
        ("workflow_evidence", "permission_evidence"),
        False,
    ),
    "offline-reachability": HuntLane(
        "offline-reachability",
        ("dependency_match", "call_reachability", "entrypoint_reachability", "independent_judge"),
        ("affected_version", "reachable_call_path"),
        False,
    ),
    "local-differential": HuntLane(
        "local-differential",
        ("source_review", "identity_or_session_setup", "negative_control", "local_differential", "independent_judge"),
        ("source_path", "control_result", "differential_result"),
        True,
    ),
    "local-multi-identity": HuntLane(
        "local-multi-identity",
        ("source_review", "two_identity_fixture", "owner_control", "cross_identity_control", "independent_judge"),
        ("ownership_invariant", "control_result", "cross_identity_result"),
        True,
    ),
    "local-state-machine": HuntLane(
        "local-state-machine",
        ("state_model", "invariant_definition", "valid_transition_control", "bounded_invalid_transition", "independent_judge"),
        ("state_invariant", "control_result", "state_difference"),
        True,
        True,
    ),
    "bounded-local-concurrency": HuntLane(
        "bounded-local-concurrency",
        ("transaction_review", "invariant_definition", "single_request_control", "bounded_concurrency_fixture", "independent_judge"),
        ("transaction_boundary", "control_result", "state_difference"),
        True,
        True,
    ),
    "local-synthetic-input": HuntLane(
        "local-synthetic-input",
        ("taint_path", "sanitizer_review", "negative_control", "synthetic_local_input", "independent_judge"),
        ("source_to_sink_path", "negative_control", "runtime_oracle"),
        True,
    ),
    "local-controlled-endpoint": HuntLane(
        "local-controlled-endpoint",
        ("taint_path", "destination_validation", "local_controlled_service", "negative_control", "independent_judge"),
        ("source_to_sink_path", "controlled_endpoint_result", "negative_control"),
        True,
    ),
    "local-temp-filesystem": HuntLane(
        "local-temp-filesystem",
        ("filesystem_path_review", "temporary_fixture", "negative_control", "filesystem_effect_check", "independent_judge"),
        ("filesystem_path", "temporary_effect", "negative_control"),
        True,
        True,
    ),
    "local-parser-fixture": HuntLane(
        "local-parser-fixture",
        ("parser_configuration", "safe_document_fixture", "negative_control", "parser_result", "independent_judge"),
        ("parser_configuration", "fixture_result", "negative_control"),
        True,
    ),
    "local-parser-differential": HuntLane(
        "local-parser-differential",
        ("parser_boundary_map", "normalization_control", "local_differential_fixture", "independent_judge"),
        ("parser_boundary", "control_result", "differential_result"),
        True,
    ),
    "local-object-differential": HuntLane(
        "local-object-differential",
        ("schema_review", "allowed_field_control", "extra_field_fixture", "identity_control", "independent_judge"),
        ("object_schema", "control_result", "field_effect"),
        True,
        True,
    ),
    "local-object-fixture": HuntLane(
        "local-object-fixture",
        ("object_flow", "merge_boundary", "safe_fixture", "state_check", "independent_judge"),
        ("object_flow", "fixture_result", "state_difference"),
        True,
        True,
    ),
    "local-browser": HuntLane(
        "local-browser",
        ("dom_flow", "browser_fixture", "negative_control", "browser_trace", "independent_judge"),
        ("dom_flow", "browser_trace", "negative_control"),
        True,
    ),
    "local-browser-origin": HuntLane(
        "local-browser-origin",
        ("origin_policy_review", "browser_origin_fixture", "negative_control", "independent_judge"),
        ("origin_policy", "browser_result", "negative_control"),
        True,
    ),
    "local-navigation": HuntLane(
        "local-navigation",
        ("navigation_source_review", "allowlist_review", "local_navigation_fixture", "negative_control", "independent_judge"),
        ("navigation_path", "fixture_result", "negative_control"),
        True,
    ),
    "bounded-local-sequence": HuntLane(
        "bounded-local-sequence",
        ("schema_map", "producer_consumer_plan", "bounded_sequence", "negative_control", "independent_judge"),
        ("request_sequence", "response_evidence", "negative_control"),
        True,
        True,
    ),
    "local-proxy-differential": HuntLane(
        "local-proxy-differential",
        ("proxy_chain_map", "normal_request_control", "local_interpretation_differential", "cache_key_check", "independent_judge"),
        ("proxy_chain", "control_result", "interpretation_difference"),
        True,
    ),
    "local-identity-provider": HuntLane(
        "local-identity-provider",
        ("trust_flow_map", "local_identity_provider", "state_and_redirect_controls", "negative_control", "independent_judge"),
        ("trust_flow", "token_or_state_validation", "negative_control"),
        True,
    ),
    "local-signed-callback": HuntLane(
        "local-signed-callback",
        ("signature_path", "valid_callback_control", "invalid_callback_control", "state_check", "independent_judge"),
        ("signature_validation", "control_result", "state_difference"),
        True,
        True,
    ),
    "offline-or-bounded-local": HuntLane(
        "offline-or-bounded-local",
        ("limit_review", "complexity_estimate", "small_bounded_fixture", "resource_measurement", "independent_judge"),
        ("configured_limits", "bounded_measurement"),
        True,
    ),
    "read-only-local": HuntLane(
        "read-only-local",
        ("configuration_review", "local_read_only_check", "independent_judge"),
        ("configuration_evidence", "observed_result"),
        True,
    ),
}


def lane_for_family(family: WeaknessFamily) -> HuntLane:
    lane = _LANES.get(family.default_validation_mode)
    if lane is not None:
        return lane
    return HuntLane(
        family.default_validation_mode,
        ("source_review", "negative_control", "independent_judge"),
        tuple(family.evidence_sources),
        family.default_validation_mode.startswith("local"),
    )
