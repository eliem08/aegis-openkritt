"""Operator-supplied, scope-bound identity fixtures for differential executors."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Mapping

from .identity_intelligence import (
    AuthorizationMatrix,
    AuthorizationRule,
    ControlledPrincipal,
    ExpectedAccess,
    SyntheticResource,
)


class FixtureKind(str, Enum):
    OWNER = "owner"
    FOREIGN_SAME_ROLE = "foreign_same_role"
    LOWER_ROLE = "lower_role"
    HIGHER_ROLE = "higher_role"
    CROSS_TENANT = "cross_tenant"


class FixtureProtocol(str, Enum):
    HTTP = "http"
    GRAPHQL = "graphql"
    WEBSOCKET = "websocket"
    GRPC = "grpc"
    BROWSER = "browser"


@dataclass(frozen=True, slots=True)
class CredentialReference:
    reference: str
    scope_digest: str
    evidence: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.reference.startswith(("vault://", "secret://", "file-secret://")):
            raise ValueError("credentials must be operator-supplied secret references")
        if not self.scope_digest or not self.evidence:
            raise ValueError("credential reference requires scope and authorization evidence")


@dataclass(frozen=True, slots=True)
class ControlledIdentityFixture:
    kind: FixtureKind
    principal_id: str
    role: str
    tenant: str
    credential: CredentialReference

    def principal(self) -> ControlledPrincipal:
        return ControlledPrincipal(
            self.principal_id, self.role, self.tenant, True, self.credential.evidence,
        )


@dataclass(frozen=True, slots=True)
class ProtocolBinding:
    protocol: FixtureProtocol
    endpoint: str
    evidence: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.endpoint or not self.evidence:
            raise ValueError("protocol binding requires an endpoint and scope evidence")


@dataclass(frozen=True, slots=True)
class FixtureExpectation:
    operation: str
    fixture_kind: FixtureKind
    resource_id: str
    expected: ExpectedAccess
    evidence: tuple[str, ...]


class ControlledIdentityFixtureSet:
    """Validated fixtures shared by HTTP, GraphQL, WS, gRPC, browser and state missions."""

    def __init__(
        self, *, scope_digest: str, fixtures: tuple[ControlledIdentityFixture, ...],
        bindings: tuple[ProtocolBinding, ...],
        expectations: tuple[FixtureExpectation, ...] = (),
    ) -> None:
        if not scope_digest:
            raise ValueError("fixture set requires a scope digest")
        by_kind = {fixture.kind: fixture for fixture in fixtures}
        if len(by_kind) != len(fixtures):
            raise ValueError("fixture kinds must be unique")
        if FixtureKind.OWNER not in by_kind:
            raise ValueError("fixture set requires an owner control")
        for fixture in fixtures:
            if fixture.credential.scope_digest != scope_digest:
                raise ValueError("credential reference is bound to a different scope")
        self.scope_digest = scope_digest
        self.fixtures: Mapping[FixtureKind, ControlledIdentityFixture] = by_kind
        self.bindings: Mapping[FixtureProtocol, ProtocolBinding] = {
            binding.protocol: binding for binding in bindings
        }
        self.expectations = expectations

    def require_protocol(self, protocol: FixtureProtocol) -> ProtocolBinding:
        try:
            return self.bindings[protocol]
        except KeyError as exc:
            raise LookupError(f"no controlled fixture binding for {protocol.value}") from exc

    def differential_pairs(self) -> tuple[tuple[ControlledPrincipal, ControlledPrincipal], ...]:
        owner = self.fixtures[FixtureKind.OWNER].principal()
        return tuple(
            (owner, fixture.principal())
            for kind, fixture in sorted(self.fixtures.items(), key=lambda item: item[0].value)
            if kind is not FixtureKind.OWNER
        )

    def authorization_matrix(self, resource: SyntheticResource) -> AuthorizationMatrix:
        rules = []
        for expectation in self.expectations:
            fixture = self.fixtures.get(expectation.fixture_kind)
            if fixture is None or expectation.resource_id != resource.resource_id:
                continue
            rules.append(AuthorizationRule(
                expectation.operation, fixture.principal_id, resource.resource_id,
                expectation.expected, expectation.evidence,
            ))
        return AuthorizationMatrix(rules)


__all__ = [
    "ControlledIdentityFixture", "ControlledIdentityFixtureSet", "CredentialReference",
    "FixtureExpectation", "FixtureKind", "FixtureProtocol", "ProtocolBinding",
]
