"""Guarded active testing (Phase 3).

Clean-room implementations of high-value active-testing behaviors — no copied
AGPL/GPL source, wordlists, or datasets. Each engine is transport-agnostic and
carries a fixed capability it cannot widen at runtime.
"""

from .auth_posture import (
    AuthAnomaly,
    AuthPosture,
    RouteAuthObservation,
    analyze_auth_differential,
    classify_posture,
)
from .client_analysis import ClientFinding, ClientIssue, analyze_client_script
from .contract_props import ContractFinding, ContractProperty, analyze_solidity
from .detectors import (
    DETECTOR_ACTIONS,
    BflaEndpoint,
    DetectorPlan,
    DetectorTask,
    Route,
    Seed,
    classify_candidate,
    is_differential,
    passes_report_gate,
    plan_detectors,
    reserve_plan,
    routes_from_assets,
)
from .enumeration import IdentifierKind, IdentifierProfile, analyze_identifiers
from .graphql import GraphqlFinding, GraphqlIssue, GraphqlResponse, analyze_graphql
from .http_desync import (
    DesyncCandidate,
    DesyncFamily,
    DesyncObservation,
    analyze_desync_observations,
    candidate_routes,
)
from .http_hardening import HardeningFinding, HardeningIssue, analyze_response_hardening
from .js_secrets import HIGH_VALUE_CATEGORIES, JsSecretFinding, analyze_javascript_secrets
from .parameters import (
    FORM,
    JSON,
    XML,
    DiscoveryConfig,
    DiscoveryResult,
    ParameterDiscovery,
    ParameterFinding,
    ProbeResponse,
    UnsupportedMethod,
)
from .path_bypass import PathBypassFinding, analyze_path_normalization, normalization_variants
from .routes import (
    EnumConfig,
    EnumerationResult,
    HostHealth,
    RouteEnumerator,
    RouteField,
    RouteObservation,
    RouteRisk,
    RouteSchema,
    RouteSource,
    RouteSpec,
)
from .ssrf import SSRF_PARAM_HINTS, SsrfFinding, candidate_ssrf_params, run_ssrf_probes
from .surface import surface_candidates
from .wiring import GatewayProbe, TransportResponse, run_parameter_stage, run_route_stage

__all__ = [
    "DETECTOR_ACTIONS",
    "FORM",
    "HIGH_VALUE_CATEGORIES",
    "JSON",
    "SSRF_PARAM_HINTS",
    "XML",
    "AuthAnomaly",
    "AuthPosture",
    "BflaEndpoint",
    "ClientFinding",
    "ClientIssue",
    "ContractFinding",
    "ContractProperty",
    "DesyncCandidate",
    "DesyncFamily",
    "DesyncObservation",
    "DetectorPlan",
    "DetectorTask",
    "DiscoveryConfig",
    "DiscoveryResult",
    "EnumConfig",
    "EnumerationResult",
    "GatewayProbe",
    "GraphqlFinding",
    "GraphqlIssue",
    "GraphqlResponse",
    "HardeningFinding",
    "HardeningIssue",
    "HostHealth",
    "IdentifierKind",
    "IdentifierProfile",
    "JsSecretFinding",
    "ParameterDiscovery",
    "ParameterFinding",
    "PathBypassFinding",
    "ProbeResponse",
    "Route",
    "RouteAuthObservation",
    "RouteEnumerator",
    "RouteField",
    "RouteObservation",
    "RouteRisk",
    "RouteSchema",
    "RouteSource",
    "RouteSpec",
    "Seed",
    "SsrfFinding",
    "TransportResponse",
    "UnsupportedMethod",
    "analyze_auth_differential",
    "analyze_client_script",
    "analyze_desync_observations",
    "analyze_graphql",
    "analyze_identifiers",
    "analyze_javascript_secrets",
    "analyze_path_normalization",
    "analyze_response_hardening",
    "analyze_solidity",
    "candidate_routes",
    "candidate_ssrf_params",
    "classify_candidate",
    "classify_posture",
    "is_differential",
    "normalization_variants",
    "passes_report_gate",
    "plan_detectors",
    "reserve_plan",
    "routes_from_assets",
    "run_parameter_stage",
    "run_route_stage",
    "run_ssrf_probes",
    "surface_candidates",
]
