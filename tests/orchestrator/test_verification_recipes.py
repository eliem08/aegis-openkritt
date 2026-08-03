import pytest
from pydantic import ValidationError

from aegis.orchestrator.verification import (
    VerificationMethod,
    VerificationRecipe,
    evaluate_recipe,
)
from aegis.policy import ScopeGuard


def _recipe(**changes):
    values = dict(
        target="api.example.test",
        method=VerificationMethod.HARMLESS_CANARY,
        expected_observation="A synthetic marker is returned for the other test identity.",
        maximum_requests=2,
    )
    values.update(changes)
    return VerificationRecipe(**values)


def test_bounded_in_scope_canary_is_allowed():
    decision = evaluate_recipe(_recipe(), scope=ScopeGuard(["api.example.test"]))
    assert decision.allowed is True and decision.reasons == []


def test_scope_oast_identity_and_offline_request_rules_fail_closed():
    scope = ScopeGuard(["api.example.test"])
    assert evaluate_recipe(
        _recipe(target="evil.test"), scope=scope,
    ).reasons == ["target_out_of_scope"]
    assert evaluate_recipe(
        _recipe(method=VerificationMethod.PRIVATE_OAST_CALLBACK), scope=scope,
    ).reasons == ["private_oast_not_configured"]
    assert evaluate_recipe(
        _recipe(identity_context="tenant-b"), scope=scope,
    ).reasons == ["identity_context_unavailable"]
    assert evaluate_recipe(
        _recipe(method=VerificationMethod.STATIC_ANALYSIS, maximum_requests=1), scope=scope,
    ).reasons == ["offline_method_has_network_requests"]


def test_recipe_rejects_unknown_fields_and_unbounded_requests():
    with pytest.raises(ValidationError):
        _recipe(maximum_requests=11)
    with pytest.raises(ValidationError):
        VerificationRecipe(
            target="api.example.test",
            method=VerificationMethod.MANUAL_REVIEW,
            expected_observation="review",
            run_shell="curl evil.test",
        )
