"""Private OAST integration (Phase 4).

Authenticated tenant-bound sessions, secrets kept out of the worker view,
interactions encrypted at rest and matched to an outstanding authorized probe,
protected polling, lifecycle/expiration/deletion, and quarantine of everything
unmatched / cross-tenant / disabled-protocol / public-server.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from aegis.api.crypto import FernetEncryptor, generate_key
from aegis.oast import (
    AuthenticationRequired,
    CrossTenantDenied,
    Interaction,
    PrivateOastConfig,
    PrivateOastService,
    PublicOastRejected,
    QuarantineReason,
    SessionExpired,
)

DOMAIN = "oast.aegis.internal"


def principal(tenant="tenant-a", name="agent"):
    return SimpleNamespace(tenant_id=tenant, name=name)


class Clock:
    def __init__(self, start=None):
        self.now = start or datetime(2026, 8, 2, 12, 0, tzinfo=timezone.utc)

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += timedelta(seconds=seconds)


def service(clock=None, *, is_production=True, ttl=3600, allowed=None):
    cfg = PrivateOastConfig(oast_domain=DOMAIN, is_production=is_production,
                            session_ttl_seconds=ttl,
                            **({"allowed_protocols": allowed} if allowed else {}))
    return PrivateOastService(cfg, encryptor=FernetEncryptor(generate_key()),
                              clock=clock or Clock())


def register(svc, p=None):
    return svc.register(p or principal(), engagement_id="eng-1", scan_id="scan-1",
                        reservation_id="resv-1")


def callback(host, *, protocol="dns", raw="payload", remote="203.0.113.9", when=None):
    return Interaction(protocol=protocol, host=host, remote_address=remote,
                       raw=raw, observed_at=when or datetime(2026, 8, 2, 12, 0, tzinfo=timezone.utc))


# --- production / public rejection ------------------------------------------

@pytest.mark.parametrize("domain", ["oast.pro", "sub.interact.sh", "oastify.com"])
def test_public_oast_server_is_rejected_in_production(domain):
    with pytest.raises(PublicOastRejected):
        PrivateOastService(PrivateOastConfig(oast_domain=domain, is_production=True))


def test_public_server_allowed_only_in_non_production():
    # Explicitly non-production may use a public server (dev only).
    PrivateOastService(PrivateOastConfig(oast_domain="oast.pro", is_production=False))


# --- registration ------------------------------------------------------------

def test_registration_requires_an_authenticated_tenant():
    svc = service()
    with pytest.raises(AuthenticationRequired):
        svc.register(SimpleNamespace(tenant_id=None), engagement_id="e", scan_id="s", reservation_id="r")


def test_registration_binds_to_tenant_engagement_scan_reservation():
    svc = service()
    reg = register(svc)
    session = svc.session(reg.session_ref)
    assert (session.tenant_id, session.engagement_id, session.scan_id, session.reservation_id) == \
        ("tenant-a", "eng-1", "scan-1", "resv-1")


def test_worker_view_carries_no_secret_material():
    svc = service()
    reg = register(svc)
    fields = vars(reg)
    assert reg.interaction_domain.endswith(DOMAIN) and reg.session_ref
    # no secret/private-key/token anywhere in the worker-facing registration
    assert not any(k in fields for k in ("secret_key", "private_key", "token", "secret_ref"))
    assert "secret" not in str(fields).lower()


def test_sessions_have_unique_correlation_and_nonce():
    svc = service()
    a, b = register(svc), register(svc)
    sa, sb = svc.session(a.session_ref), svc.session(b.session_ref)
    assert sa.correlation_id != sb.correlation_id and sa.nonce != sb.nonce


# --- correlation + matching --------------------------------------------------

def test_authorized_probe_interaction_is_matched_and_encrypted():
    svc = service()
    reg = register(svc)
    probe = svc.plant_probe(reg.session_ref, principal())

    matched = svc.ingest(callback(probe.address, raw="dns lookup body"))
    assert matched.__class__.__name__ == "MatchedInteraction"

    polled = svc.poll(reg.session_ref, principal())
    assert len(polled) == 1 and polled[0].interaction_id == matched.interaction_id
    # stored encrypted; only the owner can read the raw back
    assert svc.read_raw(reg.session_ref, matched.interaction_id, principal()) == "dns lookup body"


def test_interaction_without_a_probe_is_quarantined():
    svc = service()
    reg = register(svc)               # correlation exists, but no probe planted
    result = svc.ingest(callback(f"random.{reg.interaction_domain}"))
    assert result.reason == QuarantineReason.UNMATCHED_NO_PROBE.value
    assert svc.poll(reg.session_ref, principal()) == []       # never becomes evidence


def test_unknown_correlation_is_quarantined():
    svc = service()
    result = svc.ingest(callback(f"whatever.deadbeef.{DOMAIN}"))
    assert result.reason == QuarantineReason.UNKNOWN_CORRELATION.value


def test_foreign_host_is_quarantined():
    svc = service()
    result = svc.ingest(callback("attacker.evil.test"))
    assert result.reason == QuarantineReason.FOREIGN_HOST.value


def test_disabled_protocol_is_quarantined():
    svc = service()                    # default allows dns + https only
    reg = register(svc)
    probe = svc.plant_probe(reg.session_ref, principal())
    result = svc.ingest(callback(probe.address, protocol="smtp"))
    assert result.reason == QuarantineReason.PROTOCOL_NOT_ALLOWED.value


# --- protected polling / cross-tenant ---------------------------------------

def test_another_tenant_cannot_poll_a_session():
    svc = service()
    reg = register(svc, principal("tenant-a"))
    with pytest.raises(CrossTenantDenied):
        svc.poll(reg.session_ref, principal("tenant-b"))


def test_another_tenant_cannot_plant_a_probe():
    svc = service()
    reg = register(svc, principal("tenant-a"))
    with pytest.raises(CrossTenantDenied):
        svc.plant_probe(reg.session_ref, principal("tenant-b"))


def test_a_cross_tenant_matched_interaction_stays_with_its_owner():
    svc = service()
    reg = register(svc, principal("tenant-a"))
    probe = svc.plant_probe(reg.session_ref, principal("tenant-a"))
    svc.ingest(callback(probe.address))
    # tenant-b sees nothing (and is denied), tenant-a sees the interaction
    with pytest.raises(CrossTenantDenied):
        svc.poll(reg.session_ref, principal("tenant-b"))
    assert len(svc.poll(reg.session_ref, principal("tenant-a"))) == 1


# --- lifecycle: expiration + deletion ---------------------------------------

def test_expired_session_cannot_be_polled_and_new_callbacks_quarantine():
    clock = Clock()
    svc = service(clock, ttl=100)
    reg = register(svc)
    probe = svc.plant_probe(reg.session_ref, principal())

    clock.advance(200)                 # past expiry
    result = svc.ingest(callback(probe.address))
    assert result.reason == QuarantineReason.SESSION_INACTIVE.value
    with pytest.raises(SessionExpired):
        svc.poll(reg.session_ref, principal())


def test_deregistration_wipes_secrets_and_is_audited():
    svc = service()
    reg = register(svc)
    session = svc.session(reg.session_ref)
    assert svc._secrets.get(session.secret_ref) is not None

    svc.deregister(reg.session_ref, principal())
    assert session.deleted_at is not None
    assert svc._secrets.get(session.secret_ref) is None        # secrets gone
    actions = [e["action"] for e in svc.audit_log()]
    assert "register" in actions and "deregister" in actions


def test_retention_purge_drops_old_sessions():
    clock = Clock()
    svc = service(clock, ttl=100)
    reg = register(svc)
    clock.advance(100_000)             # well past retention (86400s default)
    assert svc.purge_expired() == 1 and svc.session(reg.session_ref) is None


def test_last_used_is_tracked_on_match():
    clock = Clock()
    svc = service(clock)
    reg = register(svc)
    probe = svc.plant_probe(reg.session_ref, principal())
    assert svc.session(reg.session_ref).last_used_at is None
    clock.advance(10)
    svc.ingest(callback(probe.address))
    assert svc.session(reg.session_ref).last_used_at == clock.now


# --- operator view -----------------------------------------------------------

def test_quarantined_interactions_are_operator_visible_only():
    svc = service()
    svc.ingest(callback("attacker.evil.test"))
    q = svc.quarantined()
    assert len(q) == 1 and q[0].reason == QuarantineReason.FOREIGN_HOST.value
