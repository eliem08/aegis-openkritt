"""Declarative, safety-aware template contracts for Aegis checks.

Templates describe discovery, validation, and regression work. They never embed arbitrary
shell commands. Before any executor sees a template, the policy engine can validate its
request budget, side effects, authentication needs, evidence oracle, digest, and signature.
"""
from __future__ import annotations

import hashlib
import json
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class TemplateKind(str, Enum):
    DISCOVERY = "discovery"
    VALIDATION = "validation"
    REGRESSION = "regression"


class RiskMode(str, Enum):
    PASSIVE = "passive"
    READ_ONLY = "read_only"
    CONTROLLED_STATE_CHANGE = "controlled_state_change"


class TemplateRisk(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    mode: RiskMode
    maximum_requests: int = Field(ge=0, le=100)
    state_changes: bool = False
    requires_human_approval: bool = True

    @model_validator(mode="after")
    def consistency(self) -> TemplateRisk:
        if self.mode in {RiskMode.PASSIVE, RiskMode.READ_ONLY} and self.state_changes:
            raise ValueError("passive and read-only templates cannot change state")
        if self.mode == RiskMode.CONTROLLED_STATE_CHANGE and not self.requires_human_approval:
            raise ValueError("controlled state changes require human approval")
        return self


class TemplateRequirements(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    asset_types: tuple[str, ...]
    authentication_contexts: int = Field(default=0, ge=0, le=4)
    capabilities: tuple[str, ...] = ()
    evidence: tuple[str, ...] = ()


class SecurityTemplateManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    template_id: str
    version: str
    kind: TemplateKind
    author: str
    risk: TemplateRisk
    requirements: TemplateRequirements
    oracle_type: str
    cwe: tuple[str, ...] = ()
    content_digest: str | None = None
    signature: str | None = None

    @field_validator("template_id", "version", "author", "oracle_type")
    @classmethod
    def non_empty(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("template identity fields are required")
        return value

    def canonical_payload(self) -> bytes:
        payload = self.model_dump(mode="json", exclude={"signature", "content_digest"})
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()

    def digest(self) -> str:
        return "tpl1:" + hashlib.sha256(self.canonical_payload()).hexdigest()

    def verify_declared_digest(self) -> bool:
        return bool(self.content_digest) and self.content_digest == self.digest()

    def policy_summary(self) -> dict:
        return {
            "template_id": self.template_id,
            "kind": self.kind.value,
            "risk_mode": self.risk.mode.value,
            "maximum_requests": self.risk.maximum_requests,
            "state_changes": self.risk.state_changes,
            "requires_human_approval": self.risk.requires_human_approval,
            "authentication_contexts": self.requirements.authentication_contexts,
            "capabilities": list(self.requirements.capabilities),
            "oracle_type": self.oracle_type,
            "digest_valid": self.verify_declared_digest(),
            "signed": bool(self.signature),
        }
