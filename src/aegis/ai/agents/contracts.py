"""Typed inputs and non-executable outputs for specialized agents."""

from __future__ import annotations

from enum import Enum

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


class Hypothesis(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    weakness: str = Field(min_length=1, max_length=200)
    title: str = Field(min_length=1, max_length=300)
    file_path: str = Field(min_length=1, max_length=500)
    line: int = Field(ge=1)
    rationale: str = Field(min_length=1, max_length=4000)
    confidence: float = Field(ge=0, le=1)
    verification: VerificationProposal
