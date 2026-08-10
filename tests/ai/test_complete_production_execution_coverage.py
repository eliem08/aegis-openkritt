from aegis.ai.jarvis.cache_executor import CacheDifferentialExecutor
from aegis.ai.jarvis.controlled_browser_executor import ControlledBrowserWorkflowExecutor
from aegis.ai.jarvis.deterministic_hunter_executors import DeterministicHunterExecutorProvider
from aegis.ai.jarvis.graphql_identity_executor import GraphQLAuthorizationDifferentialExecutor
from aegis.ai.jarvis.grpc_identity_executor import GrpcAuthorizationDifferentialExecutor
from aegis.ai.jarvis.http_identity_executor import HttpIdentityDifferentialExecutor
from aegis.ai.jarvis.lifecycle_executor import ScopedLifecycleStateExecutor
from aegis.ai.jarvis.mobile_backend_executor import (
    ControlledDeepLinkExecutor,
    MobileBackendCorrelationExecutor,
)
from aegis.ai.jarvis.production_dispatcher import (
    compose_production_executors,
    production_execution_coverage,
)
from aegis.ai.jarvis.race_executor import ScopedRaceIdempotencyExecutor
from aegis.ai.jarvis.upload_executor import ScopedUploadWorkflowExecutor
from aegis.ai.jarvis.url_consumer_executor import ScopedURLConsumerExecutor
from aegis.ai.jarvis.vhost_executor import ScopedVHostRoutingExecutor
from aegis.ai.jarvis.websocket_executor import WebSocketIdentityDifferentialExecutor


def test_all_32_hunter_techniques_have_exact_production_executor_contracts():
    dependency = object()
    verifier = object()
    credentials = lambda _ref: {}
    providers = (
        HttpIdentityDifferentialExecutor(
            dependency, fixture_sets={}, credential_resolver=credentials,
            grant_verifier=verifier,
        ),
        GraphQLAuthorizationDifferentialExecutor(
            dependency, fixture_sets={}, credential_resolver=credentials,
            grant_verifier=verifier,
        ),
        CacheDifferentialExecutor(
            dependency, fixture_sets={}, credential_resolver=credentials,
            grant_verifier=verifier,
        ),
        ScopedRaceIdempotencyExecutor(
            dependency, fixture_sets={}, credential_resolver=credentials,
            grant_verifier=verifier,
        ),
        ScopedURLConsumerExecutor(
            dependency, fixture_sets={}, credential_resolver=credentials,
            grant_verifier=verifier, oast_service=dependency, oast_principal=dependency,
        ),
        WebSocketIdentityDifferentialExecutor(
            dependency, fixture_sets={}, credential_resolver=credentials,
            grant_verifier=verifier,
        ),
        GrpcAuthorizationDifferentialExecutor(
            dependency, fixture_sets={}, method_registry={}, credential_resolver=credentials,
            grant_verifier=verifier,
        ),
        ControlledBrowserWorkflowExecutor(
            dependency, experiments={}, grant_verifier=verifier,
        ),
        ScopedLifecycleStateExecutor(
            dependency, fixture_sets={}, credential_resolver=credentials,
            grant_verifier=verifier,
        ),
        ScopedUploadWorkflowExecutor(
            dependency, fixture_sets={}, credential_resolver=credentials,
            grant_verifier=verifier, oast_service=dependency, oast_principal=dependency,
        ),
        MobileBackendCorrelationExecutor(surfaces={}, grant_verifier=verifier),
        ControlledDeepLinkExecutor(
            dependency, experiments={}, grant_verifier=verifier,
        ),
        DeterministicHunterExecutorProvider(grant_verifier=verifier),
        ScopedVHostRoutingExecutor(
            dependency, experiments={}, grant_verifier=verifier,
        ),
    )
    executors = compose_production_executors(providers)
    coverage = production_execution_coverage(executors)
    assert len(coverage) == 32
    assert {row.status for row in coverage} == {"REAL"}
    assert len(executors) == 32
