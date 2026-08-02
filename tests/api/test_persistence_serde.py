"""Pure row<->object serialization shared by SQLite and Postgres (no DB needed)."""

from datetime import datetime, timezone

from aegis.api.persistence import (
    engagement_from_row,
    engagement_values,
    grant_from_row,
    grant_values,
    kill_from_row,
    kill_values,
)
from aegis.api.store import ApprovalGrant, EngagementRecord
from aegis.policy.killswitch import KillSwitchState

TS = datetime(2026, 8, 2, 12, 0, tzinfo=timezone.utc)


def test_engagement_roundtrip():
    rec = EngagementRecord(id="e1", authorization={"a": 1, "b": "x"}, status="active", created_at=TS)
    row = engagement_values(rec)  # (id, auth_json, status, created_at)
    back = engagement_from_row(row)
    assert (back.id, back.authorization, back.status, back.created_at) == (
        "e1", {"a": 1, "b": "x"}, "active", TS
    )


def test_grant_roundtrip():
    g = ApprovalGrant(grant_id="g1", action="x", target="h", tokens=frozenset({"b", "a"}),
                      granted_by="op", granted_at=TS, expires_at=None,
                      single_use=True, used=False, revoked=True)
    v = grant_values("e1", g)  # 11 values incl engagement_id at index 1
    row = (v[0], v[2], v[3], v[4], v[5], v[6], v[7], v[8], v[9], v[10])  # drop engagement_id
    back = grant_from_row(row)
    assert back.grant_id == "g1"
    assert back.tokens == frozenset({"a", "b"})
    assert back.single_use is True and back.used is False and back.revoked is True
    assert back.expires_at is None


def test_grant_roundtrip_with_expiry():
    g = ApprovalGrant(grant_id="g2", action="x", target="h", tokens=frozenset({"t"}),
                      granted_by="op", granted_at=TS, expires_at=TS)
    v = grant_values("e1", g)
    row = (v[0], v[2], v[3], v[4], v[5], v[6], v[7], v[8], v[9], v[10])
    assert grant_from_row(row).expires_at == TS


def test_kill_state_roundtrip():
    st = KillSwitchState(fired=True, reason="stop", source="op", fired_at=TS)
    v = kill_values("e1", st)  # (engagement_id, fired, reason, source, fired_at)
    back = kill_from_row((v[1], v[2], v[3], v[4]))
    assert back.fired and back.reason == "stop" and back.source == "op" and back.fired_at == TS


def test_kill_state_not_fired_is_none():
    v = kill_values("e1", KillSwitchState())  # not fired
    assert kill_from_row((v[1], v[2], v[3], v[4])) is None
    assert kill_from_row(None) is None
