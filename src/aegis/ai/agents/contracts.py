"""Typed inputs and non-executable outputs for specialized agents."""

from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class AgentKind(str, Enum):
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    INJECTION = "injection"
    SSRF_PARSERS = "ssrf_parsers"
    SECRETS_CRYPTO = "secrets_crypto"
    SUPPLY_CHAIN = "supply_chain"
    BUSINESS_LOGIC = "business_logic"
    CLIENT_API = "client_api"
    SMART_CONTRACT = "smart_contract"


class SourceSlice(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    path: str = Field(min_length=1, max_length=500)
    content: str = Field(max_length=250_000)


class AgentTask(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    kind: AgentKind
    target: str = Field(min_length=1, max_length=500)
    source_slices: list[SourceSlice] = Field(min_length=1, max_length=50)
    evidence: list[str] = Field(default_factory=list, max_length=100)
    allowed_weaknesses: list[str] = Field(default_factory=list, max_length=100)
    policy_notes: str = Field(default="", max_length=10_000)


class VerificationProposal(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    method: str
    expected_observation: str = Field(min_length=1, max_length=2000)
    maximum_requests: int = Field(default=0, ge=0, le=10)


#: Severity as a Literal, not an Enum: these models run with ``strict=True``, which
#: refuses to coerce a JSON string into an Enum member — an Enum here would reject
#: every hypothesis the model actually returns.
Severity = Literal["critical", "high", "medium", "low"]


class Hypothesis(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    weakness: str = Field(min_length=1, max_length=200)
    title: str = Field(min_length=1, max_length=300)
    file_path: str = Field(min_length=1, max_length=500)
    line: int = Field(ge=1)
    rationale: str = Field(min_length=1, max_length=4000)
    confidence: float = Field(ge=0, le=1)
    verification: VerificationProposal

    # Reachability evidence. These exist to force the model to name a concrete
    # attacker path instead of reporting hardening observations; a hypothesis that
    # cannot name an entry point and an impact is not a vulnerability claim.
    entry_point: str = Field(default="", max_length=600)
    attacker: str = Field(default="", max_length=300)
    impact: str = Field(default="", max_length=600)
    severity: Severity = "medium"

    # Trust model. Every false positive this pipeline has produced was a correct code
    # observation with a wrong security conclusion, because nothing forced an answer
    # to "what does the attacker already have to possess?" — a bearer token whose
    # request is rejected anyway, an email that is a verified IdP claim, a CSRF gap on
    # a flow gated by a secret invite token. ``preconditions`` names what the attacker
    # must already hold; ``gating`` names what authenticates the entry point.
    preconditions: str = Field(default="", max_length=600)
    gating: str = Field(default="", max_length=600)

    @property
    def has_reachability_evidence(self) -> bool:
        return bool(self.entry_point.strip()) and bool(self.impact.strip())
