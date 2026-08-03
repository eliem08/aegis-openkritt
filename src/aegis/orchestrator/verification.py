"""Versioned, bounded verification recipes proposed by tools or models."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

from aegis.policy import ScopeGuard


class VerificationMethod(str, Enum):
    STATIC_ANALYSIS = "static_analysis"
    RESPONSE_DIFFERENTIAL = "response_differential"
    HARMLESS_CANARY = "harmless_canary"
    CONTRACT_PROPERTY = "contract_property"
    PRIVATE_OAST_CALLBACK = "private_oast_callback"
    MANUAL_REVIEW = "manual_review"


class VerificationRecipe(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    version: int = Field(default=1, ge=1, le=1)
    target: str = Field(min_length=1, max_length=1000)
    method: VerificationMethod
    preconditions: list[str] = Field(default_factory=list, max_length=20)
    identity_context: str = Field(default="", max_length=1000)
    expected_observation: str = Field(min_length=1, max_length=4000)
    maximum_requests: int = Field(default=0, ge=0, le=10)
    timeout_seconds: float = Field(default=30, gt=0, le=120)
    cleanup: str = Field(default="none required", max_length=2000)


class VerificationDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    allowed: bool
    reasons: list[str] = Field(default_factory=list)


def evaluate_recipe(
    recipe: VerificationRecipe,
    *,
    scope: ScopeGuard,
    private_oast_configured: bool = False,
    identity_available: bool = False,
) -> VerificationDecision:
    reasons = []
    if not scope.is_allowed(recipe.target):
        reasons.append("target_out_of_scope")
    if recipe.method is VerificationMethod.PRIVATE_OAST_CALLBACK and not private_oast_configured:
        reasons.append("private_oast_not_configured")
    if recipe.identity_context and not identity_available:
        reasons.append("identity_context_unavailable")
    if recipe.method in {
        VerificationMethod.STATIC_ANALYSIS,
        VerificationMethod.CONTRACT_PROPERTY,
        VerificationMethod.MANUAL_REVIEW,
    } and recipe.maximum_requests != 0:
        reasons.append("offline_method_has_network_requests")
    return VerificationDecision(allowed=not reasons, reasons=reasons)
