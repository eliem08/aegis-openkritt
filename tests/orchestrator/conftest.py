"""Fixtures for orchestrator + model tests (self-contained)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from aegis.model import Candidate, Canary, CanaryKind, EvidenceBundle, InteractionStep
from aegis.orchestrator import PassiveReconWorker, WorkerRegistry
from aegis.policy import Authorization, HmacSignatureVerifier, PolicyEngine

KID, SECRET = "kid-orch", "orch-secret"


def _sign(auth: Authorization) -> Authorization:
    v = HmacSignatureVerifier({KID: SECRET})
    auth.signature = v.sign(auth.signing_payload(), KID)
    auth.signing_key_id = KID
    return auth


@pytest.fixture
def make_engine():
    def _make(**auth_overrides) -> PolicyEngine:
        now = datetime.now(timezone.utc)
        base = dict(
            customer_id="c",
            authorization_id="eng-1",
            ownership_proof=["dns-txt"],
            targets=["api.example.test", "app.example.test"],
            valid_from=now - timedelta(days=1),
            valid_until=now + timedelta(days=10),
            permitted_actions=[
                "passive_discovery",
                "authenticated_testing",
                "cross_tenant_proof",
                "safe_state_change",
            ],
            prohibited_actions=["denial_of_service", "persistence"],
            rate_limits={"requests_per_second": 5, "max_concurrent_sessions": 3},
            approval_required_for=["cross_tenant_proof"],
            spend_budget=100.0,
        )
        base.update(auth_overrides)
        auth = _sign(Authorization(**base))
        return PolicyEngine(
            authorization=auth,
            verifier=HmacSignatureVerifier({KID: SECRET}),
            audit=lambda _d: None,
        )

    return _make


@pytest.fixture
def engine(make_engine) -> PolicyEngine:
    return make_engine()


@pytest.fixture
def registry() -> WorkerRegistry:
    reg = WorkerRegistry()
    reg.register(PassiveReconWorker())
    return reg


@pytest.fixture
def make_evidence():
    def _make(reproducible: bool = True, confidence: float = 0.8) -> EvidenceBundle:
        return EvidenceBundle(
            steps=[InteractionStep(summary="GET /users/1 -> seeded record")] if reproducible else [],
            canary=Canary(kind=CanaryKind.SEEDED_RECORD, value="CANARY-123") if reproducible else None,
            observed="returned a seeded record for another tenant",
            expected="403 forbidden",
            confidence=confidence,
        )

    return _make


@pytest.fixture
def make_candidate():
    def _make(
        evidence_id: str | None = None,
        cwe: str = "CWE-639",
        confidence: float = 0.8,
        route: str = "/users/{id}",
        parameter: str = "id",
        **kw,
    ) -> Candidate:
        return Candidate(
            asset=kw.get("asset", "api.example.test"),
            route=route,
            parameter=parameter,
            cwe=cwe,
            action="authenticated_testing",
            worker="probe",
            confidence=confidence,
            evidence_id=evidence_id,
            p_exploit=kw.get("p_exploit", 0.8),
            business_impact=kw.get("business_impact", 0.7),
            asset_criticality=kw.get("asset_criticality", 0.9),
        )

    return _make
