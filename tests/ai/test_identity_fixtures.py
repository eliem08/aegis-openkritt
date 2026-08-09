from __future__ import annotations

import pytest

from aegis.ai.jarvis.identity_fixtures import (
    ControlledIdentityFixture,
    ControlledIdentityFixtureSet,
    CredentialReference,
    FixtureExpectation,
    FixtureKind,
    FixtureProtocol,
    ProtocolBinding,
)
from aegis.ai.jarvis.identity_intelligence import ExpectedAccess, SyntheticResource

SCOPE = "scope:identity"


def fixture(kind, principal, role, tenant):
    return ControlledIdentityFixture(
        kind, principal, role, tenant,
        CredentialReference(f"vault://identities/{principal}", SCOPE, (f"operator:{principal}",)),
    )


def test_fixture_set_builds_cross_account_role_tenant_pairs_and_explicit_matrix():
    resource = SyntheticResource("invoice-1", "owner", "tenant-a", "canary", True)
    fixtures = ControlledIdentityFixtureSet(
        scope_digest=SCOPE,
        fixtures=(
            fixture(FixtureKind.OWNER, "owner", "member", "tenant-a"),
            fixture(FixtureKind.FOREIGN_SAME_ROLE, "peer", "member", "tenant-a"),
            fixture(FixtureKind.LOWER_ROLE, "viewer", "viewer", "tenant-a"),
            fixture(FixtureKind.HIGHER_ROLE, "admin", "admin", "tenant-a"),
            fixture(FixtureKind.CROSS_TENANT, "outside", "member", "tenant-b"),
        ),
        bindings=(ProtocolBinding(
            FixtureProtocol.GRAPHQL, "https://api.example.test/graphql", ("scope:api",),
        ),),
        expectations=(FixtureExpectation(
            "invoice.read", FixtureKind.CROSS_TENANT, resource.resource_id,
            ExpectedAccess.DENY, ("policy:tenant-isolation",),
        ),),
    )
    pairs = fixtures.differential_pairs()
    assert len(pairs) == 4 and all(control.principal_id == "owner" for control, _ in pairs)
    assert fixtures.require_protocol(FixtureProtocol.GRAPHQL).endpoint.endswith("/graphql")
    outside = fixtures.fixtures[FixtureKind.CROSS_TENANT].principal()
    rule = fixtures.authorization_matrix(resource).expectation(type("Obs", (), {
        "operation": "invoice.read", "principal": outside, "resource": resource,
    })())
    assert rule.expected is ExpectedAccess.DENY


def test_fixture_set_rejects_raw_credentials_scope_mismatch_and_missing_backend():
    with pytest.raises(ValueError, match="secret references"):
        CredentialReference("Bearer raw-token", SCOPE, ("operator",))
    owner = fixture(FixtureKind.OWNER, "owner", "member", "tenant-a")
    wrong = ControlledIdentityFixture(
        FixtureKind.CROSS_TENANT, "outside", "member", "tenant-b",
        CredentialReference("vault://outside", "scope:other", ("operator",)),
    )
    with pytest.raises(ValueError, match="different scope"):
        ControlledIdentityFixtureSet(
            scope_digest=SCOPE, fixtures=(owner, wrong), bindings=(),
        )
    fixtures = ControlledIdentityFixtureSet(
        scope_digest=SCOPE, fixtures=(owner,), bindings=(),
    )
    with pytest.raises(LookupError, match="no controlled fixture binding"):
        fixtures.require_protocol(FixtureProtocol.GRPC)
