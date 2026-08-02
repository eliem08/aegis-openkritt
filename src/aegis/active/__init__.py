"""Guarded active testing (Phase 3).

Clean-room implementations of high-value active-testing behaviors — no copied
AGPL/GPL source, wordlists, or datasets. Each engine is transport-agnostic and
carries a fixed capability it cannot widen at runtime.
"""

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
from .auth_posture import (
    AuthAnomaly,
    AuthPosture,
    RouteAuthObservation,
    analyze_auth_differential,
    classify_posture,
)
from .enumeration import IdentifierKind, IdentifierProfile, analyze_identifiers
from .http_hardening import HardeningFinding, HardeningIssue, analyze_response_hardening
from .js_secrets import HIGH_VALUE_CATEGORIES, JsSecretFinding, analyze_javascript_secrets
from .ssrf import SSRF_PARAM_HINTS, SsrfFinding, candidate_ssrf_params, run_ssrf_probes
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
from .wiring import (
    GatewayProbe,
    TransportResponse,
    run_parameter_stage,
    run_route_stage,
)

__all__ = [
    "ParameterDiscovery",
    "DiscoveryConfig",
    "DiscoveryResult",
    "ParameterFinding",
    "ProbeResponse",
    "UnsupportedMethod",
    "FORM",
    "JSON",
    "XML",
    "RouteSchema",
    "RouteSpec",
    "RouteField",
    "RouteSource",
    "RouteRisk",
    "RouteEnumerator",
    "EnumConfig",
    "EnumerationResult",
    "RouteObservation",
    "HostHealth",
    "plan_detectors",
    "routes_from_assets",
    "reserve_plan",
    "classify_candidate",
    "is_differential",
    "passes_report_gate",
    "DetectorPlan",
    "DetectorTask",
    "Route",
    "Seed",
    "BflaEndpoint",
    "DETECTOR_ACTIONS",
    "GatewayProbe",
    "TransportResponse",
    "run_parameter_stage",
    "run_route_stage",
    "analyze_identifiers",
    "IdentifierProfile",
    "IdentifierKind",
    "analyze_auth_differential",
    "classify_posture",
    "AuthPosture",
    "AuthAnomaly",
    "RouteAuthObservation",
    "run_ssrf_probes",
    "candidate_ssrf_params",
    "SsrfFinding",
    "SSRF_PARAM_HINTS",
    "analyze_javascript_secrets",
    "JsSecretFinding",
    "HIGH_VALUE_CATEGORIES",
    "analyze_response_hardening",
    "HardeningFinding",
    "HardeningIssue",
]
