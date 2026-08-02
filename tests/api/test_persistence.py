"""Durability: repository CRUD, and engagement state surviving a 'restart'
(a fresh EngagementStore over the same SQLite file, empty live cache)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from aegis.api.persistence import SqliteRepository
from aegis.api.store import (
    ApprovalGrant,
    DuplicateEngagementError,
    EngagementRecord,
    EngagementStore,
)
from aegis.policy import ActionRequest, Authorization, HmacSignatureVerifier, Verdict
from aegis.policy.killswitch import KillSwitchState

KID, SECRET = "kid-p", "persist-secret"


def _verifier() -> HmacSignatureVerifier:
    return HmacSignatureVerifier({KID: SECRET})


def signed_auth(aid: str = "auth-p1", spend: float = 100.0) -> Authorization:
    now = datetime.now(timezone.utc)
    a = Authorization(
        customer_id="c", authorization_id=aid, ownership_proof=["dns"],
        targets=["api.example.test"], valid_from=now - timedelta(days=1), valid_until=now + timedelta(days=10),
        permitted_actions=["passive_discovery", "cross_tenant_proof"], prohibited_actions=["denial_of_service"],
        rate_limits={"requests_per_second": 5, "max_concurrent_sessions": 3},
        approval_required_for=["cross_tenant_proof"], spend_budget=spend,
    )
    a.signature = _verifier().sign(a.signing_payload(), KID)
    a.signing_key_id = KID
    return a


def store(db: str) -> EngagementStore:
    return EngagementStore(verifier=_verifier(), require_signature=True, repository=SqliteRepository(db))


# --- repository-level ---

def test_repo_engagement_roundtrip(tmp_path):
    repo = SqliteRepository(str(tmp_path / "a.db"))
    rec = EngagementRecord(id="e1", authorization={"x": 1}, status="active",
                           created_at=datetime.now(timezone.utc))
    repo.save_engagement(rec)
    got = repo.get_engagement("e1")
    assert got.authorization == {"x": 1} and got.status == "active"
    assert repo.list_engagement_ids() == ["e1"]
    repo.update_engagement_status("e1", "closed")
    assert repo.get_engagement("e1").status == "closed"


def test_repo_grant_upsert(tmp_path):
    repo = SqliteRepository(str(tmp_path / "a.db"))
    g = ApprovalGrant(grant_id="g1", action="cross_tenant_proof", target="api.example.test",
                      tokens=frozenset({"a", "b"}), granted_by="op", granted_at=datetime.now(timezone.utc))
    repo.save_grant("e1", g)
    assert repo.list_grants("e1")[0].tokens == frozenset({"a", "b"})
    g.revoked = True
    repo.save_grant("e1", g)  # upsert
    assert repo.list_grants("e1")[0].revoked is True


def test_repo_kill_and_spend(tmp_path):
    repo = SqliteRepository(str(tmp_path / "a.db"))
    assert repo.get_kill_state("e1") is None  # never fired
    repo.save_kill_state("e1", KillSwitchState(fired=True, reason="stop", source="op",
                                               fired_at=datetime.now(timezone.utc)))
    st = repo.get_kill_state("e1")
    assert st.fired and st.reason == "stop"
    repo.save_spend("e1", 42.5)
    assert repo.get_spend("e1") == 42.5


def test_repo_audit_chronological(tmp_path):
    repo = SqliteRepository(str(tmp_path / "a.db"))
    for i in range(5):
        repo.append_audit("e1", {"n": i})
    assert [r["n"] for r in repo.recent_audit("e1", 3)] == [2, 3, 4]


# --- store durability across restart ---

def test_engagement_survives_restart(tmp_path):
    db = str(tmp_path / "agg.db")
    store(db).create(signed_auth())
    eng = store(db).get("auth-p1")  # fresh store, same db
    assert eng is not None and eng.is_active
    assert store(db).list() and store(db).list()[0].id == "auth-p1"


def test_approvals_kill_and_spend_survive_restart(tmp_path):
    db = str(tmp_path / "agg.db")
    now = datetime.now(timezone.utc)
    e1 = store(db).create(signed_auth())
    e1.approvals.grant(action="cross_tenant_proof", target="api.example.test",
                       tokens=["cross_tenant_proof", "tier:SENSITIVE"], granted_by="op")
    req = ActionRequest(target="api.example.test", action="passive_discovery", estimated_cost=30.0)
    d = e1.engine.authorize(req, now=now)
    e1.engine.commit(d, request=req, now=now)  # spend 30
    e1.engine.kill_switch.fire("operator stop")

    e2 = store(db).get("auth-p1")  # restart
    assert e2.approvals.tokens_for("cross_tenant_proof", "api.example.test", now) == {
        "cross_tenant_proof", "tier:SENSITIVE"
    }
    # fired kill switch survived
    denied = e2.engine.authorize(ActionRequest(target="api.example.test", action="passive_discovery"), now=now)
    assert denied.verdict == Verdict.DENY and "KILL_SWITCH" in denied.incidents
    # spend survived: 30 already spent, a +90 action exceeds the 100 cap
    e2.engine.kill_switch.reset()
    over = e2.engine.authorize(
        ActionRequest(target="api.example.test", action="passive_discovery", estimated_cost=90.0), now=now
    )
    assert over.verdict == Verdict.DENY
    assert any(r.code.value == "spend_budget_exceeded" for r in over.reasons)


def test_audit_survives_restart(tmp_path):
    db = str(tmp_path / "agg.db")
    e1 = store(db).create(signed_auth())
    e1.engine.authorize(ActionRequest(target="api.example.test", action="passive_discovery"))
    e2 = store(db).get("auth-p1")
    assert len(e2.audit.recent()) >= 1


def test_duplicate_detected_across_restart(tmp_path):
    db = str(tmp_path / "agg.db")
    store(db).create(signed_auth())
    with pytest.raises(DuplicateEngagementError):
        store(db).create(signed_auth())  # same id already persisted


# --- end-to-end durability through the HTTP layer ---

def test_api_state_survives_app_restart(tmp_path):
    from fastapi.testclient import TestClient

    from aegis.api import ApiPrincipal, ControlPlaneConfig, Role, create_app

    db = str(tmp_path / "api.db")
    op = {"Authorization": "Bearer op"}
    ag = {"Authorization": "Bearer ag"}

    def cfg():
        return ControlPlaneConfig(
            api_keys={"op": ApiPrincipal("op", Role.OPERATOR), "ag": ApiPrincipal("ag", Role.AGENT)},
            signing_keys={KID: SECRET}, db_path=db,
        )

    c1 = TestClient(create_app(cfg()))
    payload = signed_auth("auth-api1").model_dump(mode="json")
    assert c1.post("/engagements", headers=op, json=payload).status_code == 201
    assert c1.post("/engagements/auth-api1/kill", headers=op, json={"reason": "stop"}).status_code == 200

    # brand-new app instance, same database file
    c2 = TestClient(create_app(cfg()))
    assert c2.get("/engagements/auth-api1", headers=ag).status_code == 200  # rehydrated
    d = c2.post("/engagements/auth-api1/decisions", headers=ag,
                json={"target": "api.example.test", "action": "passive_discovery"})
    assert d.json()["verdict"] == "deny"
    assert "KILL_SWITCH" in d.json()["incidents"]  # fired kill switch survived the restart
