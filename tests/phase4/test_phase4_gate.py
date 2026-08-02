"""Phase 4 completion gate.

Proves, in-process: private OAST and browser workflows verify seeded local-lab
findings without cross-session leakage; sensitive artifacts cannot pass the
quarantine boundary; and continuous monitoring produces accurate durable diffs and
bounded authorized subscans.
"""

from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from aegis.api.crypto import FernetEncryptor, generate_key
from aegis.browser import BrowserWorker, BrowserWorkflow, PageResult, StepType, WorkflowStep
from aegis.gateway import GatewayConfig, NetworkProfile, ScopedExecutionGateway
from aegis.graph import Asset, AssetKind, new_snapshot
from aegis.monitor import MonitoringPlanner, ScopeWidened, new_schedule
from aegis.oast import (
    CrossTenantDenied,
    Interaction,
    PrivateOastConfig,
    PrivateOastService,
    QuarantineReason,
)
from aegis.policy.scope import ScopeGuard
from aegis.sensitive import SensitiveDataBoundary, SensitiveDataClassifier

NOW = datetime(2026, 8, 2, 12, 0, tzinfo=timezone.utc)
HOST = "lab.example.test"
BASE = f"https://{HOST}"
RESOLVER = lambda h: ["93.184.216.34"]


def principal(tenant):
    return SimpleNamespace(tenant_id=tenant, name="agent")


# --- OAST verifies a seeded blind finding, no cross-session leakage ----------

def test_private_oast_verifies_a_seeded_callback_without_cross_tenant_leakage():
    svc = PrivateOastService(
        PrivateOastConfig(oast_domain="oast.aegis.internal", is_production=True),
        encryptor=FernetEncryptor(generate_key()))
    reg = svc.register(principal("tenant-a"), engagement_id="e", scan_id="s", reservation_id="r")
    probe = svc.plant_probe(reg.session_ref, principal("tenant-a"))

    # The seeded blind vuln calls back to the planted probe -> matched evidence.
    matched = svc.ingest(Interaction(protocol="dns", host=probe.address,
                                     remote_address="203.0.113.5", raw="blind-xss-callback",
                                     observed_at=NOW))
    assert matched.__class__.__name__ == "MatchedInteraction"
    assert len(svc.poll(reg.session_ref, principal("tenant-a"))) == 1

    # No cross-session leakage: another tenant cannot poll, and a stray callback
    # to an unrelated host is quarantined, not correlated.
    with pytest.raises(CrossTenantDenied):
        svc.poll(reg.session_ref, principal("tenant-b"))
    stray = svc.ingest(Interaction(protocol="dns", host="attacker.evil.test",
                                   remote_address="198.51.100.9", raw="x", observed_at=NOW))
    assert stray.reason == QuarantineReason.FOREIGN_HOST.value


# --- browser verifies a seeded finding, contexts isolated --------------------

class _Driver:
    def __init__(self, body):
        self._body = body
        self.contexts = []

    def open_context(self, cid, *, disabled, credentials):
        self.contexts.append(cid)

    def navigate(self, url):
        return PageResult(status=200, body=self._body,
                          subresources=["https://cdn.evil.test/x.js"])   # out-of-scope beacon

    def fill(self, s, v):
        pass

    def click(self, s):
        return PageResult(body=self._body)

    def query(self, s):
        return True

    def body(self):
        return self._body

    def close_context(self, cid):
        pass


def gateway():
    return ScopedExecutionGateway(
        GatewayConfig(profile=NetworkProfile.TARGET_OBSERVATION, scope=ScopeGuard([HOST])),
        resolver=RESOLVER)


def test_browser_verifies_a_seeded_canary_and_blocks_cross_origin_leakage():
    driver = _Driver(body="dashboard shows CANARY-LAB-42")
    worker = BrowserWorker(gateway(), driver)
    wf = BrowserWorkflow(
        steps=(WorkflowStep(StepType.NAVIGATE, {"url": "/dashboard"}),
               WorkflowStep(StepType.CANARY_CHECK, {"canary": "CANARY-LAB-42"})),
        identity="alice")

    a = worker.run(wf, tenant_id="tenant-a", base_url=BASE)
    assert a.canaries == [{"canary": "CANARY-LAB-42", "present": True}]       # finding verified
    # the out-of-scope beacon subresource is blocked (no exfil to another origin)
    assert any(b["url"] == "https://cdn.evil.test/x.js" for b in a.blocked)

    # a different tenant gets a fresh, non-shared context
    b = worker.run(wf, tenant_id="tenant-b", base_url=BASE)
    assert a.context_id != b.context_id


# --- sensitive artifacts cannot pass the quarantine boundary -----------------

def test_sensitive_artifact_cannot_cross_the_boundary():
    clf = SensitiveDataClassifier()
    boundary = SensitiveDataBoundary(encryptor=FernetEncryptor(generate_key()))
    artifact = {"oast_body": "leaked -----BEGIN RSA PRIVATE KEY-----abc-----END RSA PRIVATE KEY-----"}

    classification = clf.classify(artifact)
    assert classification.sensitive
    outcome = boundary.quarantine(artifact, classification, context={"tenant_id": "tenant-a"})
    # cancelled, encrypted, report-blocked, and no raw value in the product-data event
    assert outcome.cancelled and outcome.report_blocked
    assert "PRIVATE KEY" not in str(outcome.classification_event)
    assert "PRIVATE KEY" not in outcome.encrypted_artifact
    assert outcome.escalation["status"] == "open"


# --- continuous monitoring: accurate diffs + bounded subscans ----------------

def asset(key, host):
    return Asset(engagement_id="eng-1", asset_key=key, kind=AssetKind.ROUTE,
                 attributes={"host": host}, first_seen=NOW, last_seen=NOW)


def snap(entries, *, complete=True, scan_id="s"):
    assets = []
    for k, meta in entries.items():
        a = asset(k, meta["host"])
        a.attributes["d"] = meta.get("d", 1)
        assets.append(a)
    return new_snapshot(engagement_id="eng-1", scan_id=scan_id, assets=assets, complete=complete)


def schedule():
    return new_schedule(tenant_id="t", engagement_id="eng-1", scope_digest="digest",
                        targets=(HOST,), manifest_set=("subfinder",), cadence_seconds=3600)


def test_monitoring_diffs_drive_bounded_authorized_subscans():
    plan = MonitoringPlanner()
    prev = snap({"route:GET lab.example.test/a": {"host": HOST, "d": 1}})
    curr = snap({"route:GET lab.example.test/a": {"host": HOST, "d": 2},   # changed
                 "route:GET lab.example.test/b": {"host": HOST, "d": 1}},   # added
                scan_id="s2")
    assets = {a.asset_key: a for a in
              [asset("route:GET lab.example.test/a", HOST), asset("route:GET lab.example.test/b", HOST)]}

    subscans = plan.subscans_from_diff(schedule(), prev, curr, parent_scan_id="scan-1", assets=assets)
    assert subscans and all(s.kind == "subscan" and s.scope_digest == "digest" for s in subscans)
    assert all(s.targets[0] == HOST for s in subscans)                      # within parent scope
    assert plan.activity.records("subscan")


def test_subscan_cannot_widen_scope_and_incomplete_scans_never_remove():
    plan = MonitoringPlanner()
    # widening is refused
    prev = snap({})
    curr = snap({"route:GET evil.other.test/x": {"host": "evil.other.test"}}, scan_id="s2")
    with pytest.raises(ScopeWidened):
        plan.subscans_from_diff(schedule(), prev, curr, parent_scan_id="p",
                                assets={"route:GET evil.other.test/x":
                                        asset("route:GET evil.other.test/x", "evil.other.test")})

    # a repeatedly-missing asset from incomplete scans is never declared removed
    s1 = snap({"a": {"host": HOST}, "b": {"host": HOST}})
    p1 = snap({"a": {"host": HOST}}, complete=False, scan_id="s2")
    p2 = snap({"a": {"host": HOST}}, complete=False, scan_id="s3")
    assert plan.confirmed_asset_removals(schedule(), [s1, p1, p2]) == []
