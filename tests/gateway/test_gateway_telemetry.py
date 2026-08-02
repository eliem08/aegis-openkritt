"""Gateway emits telemetry on every decision (Phase 5 wiring)."""

from __future__ import annotations

from aegis.gateway import GatewayConfig, NetworkProfile, ScopedExecutionGateway
from aegis.observ import MetricNames, Telemetry
from aegis.policy.scope import ScopeGuard

HOST = "api.example.test"
RESOLVER = lambda h: ["93.184.216.34"]


def gateway(tel, scope=(HOST,), tenant=None):
    return ScopedExecutionGateway(
        GatewayConfig(profile=NetworkProfile.TARGET_OBSERVATION, scope=ScopeGuard(list(scope))),
        resolver=RESOLVER, telemetry=tel, tenant_id=tenant)


def metrics(tel, name):
    return [m for m in tel.exporter.metrics if m.name == name]


def test_allowed_request_increments_the_request_rate():
    tel = Telemetry()
    gw = gateway(tel)
    gw.require("GET", f"https://{HOST}/x")
    rate = metrics(tel, MetricNames.REQUEST_RATE)
    assert rate and rate[0].labels["profile"] == "target-observation"
    assert metrics(tel, MetricNames.GATEWAY_BLOCKS) == []


def test_blocked_request_records_a_categorized_reason():
    tel = Telemetry()
    gw = gateway(tel, scope=("other.example.test",))
    gw.check("GET", f"https://{HOST}/x")            # out of scope
    blocks = metrics(tel, MetricNames.GATEWAY_BLOCKS)
    assert blocks and blocks[0].labels["reason"] == "out_of_scope"


def test_budget_exhaustion_is_categorized():
    tel = Telemetry()
    gw = ScopedExecutionGateway(
        GatewayConfig(profile=NetworkProfile.TARGET_OBSERVATION, scope=ScopeGuard([HOST]),
                      request_budget=1),
        resolver=RESOLVER, telemetry=tel)
    gw.authorize("GET", f"https://{HOST}/a")
    gw.authorize("GET", f"https://{HOST}/b")        # over budget
    reasons = {m.labels["reason"] for m in metrics(tel, MetricNames.GATEWAY_BLOCKS)}
    assert "budget_exhausted" in reasons


def test_tenant_label_is_pseudonymous():
    tel = Telemetry()
    gateway(tel, tenant="tenant-a").require("GET", f"https://{HOST}/x")
    label = metrics(tel, MetricNames.REQUEST_RATE)[0].labels["tenant_id"]
    assert label.startswith("tnt_") and label != "tenant-a"


def test_no_telemetry_is_a_no_op():
    ScopedExecutionGateway(
        GatewayConfig(profile=NetworkProfile.TARGET_OBSERVATION, scope=ScopeGuard([HOST])),
        resolver=RESOLVER).require("GET", f"https://{HOST}/x")   # no telemetry -> no error
