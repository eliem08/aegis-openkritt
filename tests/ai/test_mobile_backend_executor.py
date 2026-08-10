from __future__ import annotations

from dataclasses import replace

import pytest

from aegis.ai.agentic_os import (
    AuthorizationEnvelope,
    Budget,
    mint_execution_grant,
    process_grant_verifier,
)
from aegis.ai.jarvis.cross_surface_intelligence import CrossSurfaceOutcome
from aegis.ai.jarvis.mission_scheduler import MissionPlan, MissionTask, TaskState
from aegis.ai.jarvis.mobile_backend_executor import (
    AndroidAdbDeepLinkBackend,
    ControlledDeepLinkExecutor,
    MobileBackendCorrelationExecutor,
    MobileBackendReference,
    RegisteredDeepLinkExperiment,
    RegisteredMobileSurface,
)

SCOPE = "scope:mobile"


def _authorization(*, state_change=True):
    verifier = process_grant_verifier()
    budget = Budget(max_cost_usd=1, max_requests=4, max_human_minutes=2)
    grant = mint_execution_grant(
        type("AllowedPolicyDecision", (), {"allowed": True})(),
        scope_digest=SCOPE, budget=budget, verifier=verifier,
        network=True, state_change=state_change, human_approval=True,
    )
    return verifier, AuthorizationEnvelope(scope_digest=SCOPE, budget=budget, grant=grant)


def _surface(*, confirmed=True, payload=True):
    return RegisteredMobileSurface(
        "mobile-1", SCOPE, "android_apk", "a" * 64,
        ("operator-artifact:mobile.apk",),
        (MobileBackendReference(
            "https://api.example.test/graphql", "src/Api.kt:42",
            "dynamic:graphql-auth-differential", ("callsite:sha256",),
            (("scope-confirmed:api.example.test",) if confirmed else ()),
            ({"fixture_set_id": "fixtures:mobile", "expected_requests": 2}
             if payload else None),
        ),),
        deep_links=("demo://open/account",), oauth_client_ids=("mobile-client",),
    )


def _correlation_task():
    return MissionTask(
        "task:mobile", "research", "correlate mobile backend", risk="offline",
        executor_capability=MobileBackendCorrelationExecutor.CAPABILITY,
        payload={"mobile_surface_id": "mobile-1"},
    )


def test_scope_confirmed_mobile_route_compiles_existing_real_executor_task():
    verifier, authorization = _authorization()
    executor = MobileBackendCorrelationExecutor(
        surfaces={"mobile-1": _surface()}, grant_verifier=verifier,
    )
    task = _correlation_task()
    plan = MissionPlan("mission:mobile", SCOPE, "correlate", (task,),
                       authorization_id="auth:mobile")
    outcome = executor(task, plan, authorization)
    assert len(outcome.opportunities) == len(outcome.mission_tasks) == 1
    assert outcome.opportunities[0].estimated_payout_usd is None
    followup = outcome.mission_tasks[0]
    assert followup.executor_capability == "dynamic:graphql-auth-differential"
    assert followup.state is TaskState.PENDING
    assert outcome.verdicts[0].outcome is CrossSurfaceOutcome.CORRELATION


def test_mobile_reference_never_authorizes_backend_and_missing_fixture_waits():
    verifier, authorization = _authorization()
    task = _correlation_task()
    plan = MissionPlan("mission:mobile", SCOPE, "correlate", (task,))
    inferred = MobileBackendCorrelationExecutor(
        surfaces={"mobile-1": _surface(confirmed=False)}, grant_verifier=verifier,
    )(task, plan, authorization)
    assert inferred.opportunities == () and inferred.mission_tasks == ()
    assert inferred.inferred_endpoints == ("https://api.example.test/graphql",)
    assert inferred.verdicts[0].outcome is CrossSurfaceOutcome.INCONCLUSIVE

    waiting = MobileBackendCorrelationExecutor(
        surfaces={"mobile-1": _surface(payload=False)}, grant_verifier=verifier,
    )(task, plan, authorization)
    assert waiting.mission_tasks[0].state is TaskState.WAITING_FOR_PREREQUISITE


def _deep_link_executor(*, confirmation=False):
    states = iter((
        ("state-0", True), ("state-0", True),
        ("state-0", confirmation), ("state-1", confirmation),
    ))
    commands = []

    def runner(command):
        commands.append(tuple(command))
        return 0, "Starting: Intent"

    backend = AndroidAdbDeepLinkBackend(
        device_serial="controlled-emulator-1", state_reader=lambda: next(states), runner=runner,
    )
    experiment = RegisteredDeepLinkExperiment(
        "deep-link-1", SCOPE, "com.example.app", "demo://open/home",
        "demo://open/transfer", True,
        ("operator-test-app", "scope-confirmed:controlled-emulator"),
    )
    verifier, authorization = _authorization()
    executor = ControlledDeepLinkExecutor(
        backend, experiments={"deep-link-1": experiment}, grant_verifier=verifier,
    )
    task = MissionTask(
        "task:deep-link", "mobile", "controlled deep-link differential",
        executor_capability=ControlledDeepLinkExecutor.CAPABILITY,
        risk="controlled_state_change", payload={"experiment_id": "deep-link-1"},
    )
    return executor, task, authorization, commands


def test_adb_deep_link_argv_adapter_detects_unconfirmed_sensitive_state_change():
    executor, task, authorization, commands = _deep_link_executor(confirmation=False)
    outcome = executor(task, MissionPlan("mission:deep", SCOPE, "deep link", (task,)),
                       authorization)
    assert outcome.verdict.outcome is CrossSurfaceOutcome.VIOLATION
    assert len(commands) == 2
    assert all(command[0] == "adb" and "shell" in command for command in commands)
    assert outcome.evidence.is_reproducible


def test_confirmed_deep_link_state_change_is_not_mislabeled_violation():
    executor, task, authorization, _ = _deep_link_executor(confirmation=True)
    outcome = executor(task, MissionPlan("mission:deep", SCOPE, "deep link", (task,)),
                       authorization)
    assert outcome.verdict.outcome is CrossSurfaceOutcome.INCONCLUSIVE


def test_deep_link_missing_experiment_and_grant_fail_closed():
    executor, task, authorization, _ = _deep_link_executor()
    missing = replace(task, payload={"experiment_id": "missing"})
    with pytest.raises(RuntimeError, match="not registered"):
        executor(missing, MissionPlan("mission:missing", SCOPE, "deep", (missing,)), authorization)
    with pytest.raises(PermissionError, match="exact verified"):
        executor(task, MissionPlan("mission:no-grant", SCOPE, "deep", (task,)),
                 AuthorizationEnvelope(scope_digest=SCOPE, budget=authorization.budget))
