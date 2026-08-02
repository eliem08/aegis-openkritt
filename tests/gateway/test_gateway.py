"""Scoped execution gateway: profiles, scope, DNS pinning/change, private IPs,
redirects, method allowlists, budgets, and audit."""

import pytest

from aegis.gateway import (
    GatewayBlocked,
    GatewayConfig,
    NetworkProfile,
    ScopedExecutionGateway,
)
from aegis.policy import ScopeGuard

PUBLIC = lambda h: ["93.184.216.34"]  # noqa: E731
SCOPE = ScopeGuard(["api.example.test", "*.example.test"])


def obs(resolver=PUBLIC, **cfg):
    return ScopedExecutionGateway(
        GatewayConfig(profile=NetworkProfile.TARGET_OBSERVATION, scope=SCOPE, **cfg), resolver=resolver
    )


# --- scope / direct-egress ---

def test_in_scope_allowed_and_pinned():
    d = obs().authorize("GET", "https://api.example.test/x")
    assert d.allowed and d.pinned_ip == "93.184.216.34"


def test_wildcard_scope_allowed():
    assert obs().authorize("GET", "https://shop.example.test/").allowed


def test_out_of_scope_direct_egress_denied():
    assert obs().authorize("GET", "https://evil.com/").allowed is False


# --- private IPs / DNS ---

def test_private_ip_denied():
    d = obs(resolver=lambda h: ["10.0.0.5"]).authorize("GET", "https://api.example.test/")
    assert not d.allowed and "internal" in d.reason


def test_mixed_dns_with_a_private_ip_denied():
    d = obs(resolver=lambda h: ["93.184.216.34", "10.0.0.5"]).authorize("GET", "https://api.example.test/")
    assert not d.allowed


def test_dns_change_after_pinning_denied():
    state = {"ips": ["93.184.216.34"]}
    g = obs(resolver=lambda h: state["ips"])
    assert g.authorize("GET", "https://api.example.test/").allowed  # pins .34
    state["ips"] = ["8.8.8.8"]  # entirely different resolution
    d = g.authorize("GET", "https://api.example.test/")
    assert not d.allowed and "DNS changed" in d.reason


def test_dns_resolution_failure_fails_closed():
    def bad(h):
        raise OSError("nxdomain")

    assert not obs(resolver=bad).authorize("GET", "https://api.example.test/").allowed


# --- redirects ---

def test_redirect_out_of_scope_denied():
    g = obs()
    assert g.authorize("GET", "https://api.example.test/go").allowed
    assert not g.check_redirect("GET", "https://evil.com/").allowed


# --- methods ---

def test_observation_rejects_unsafe_method():
    assert not obs().authorize("POST", "https://api.example.test/").allowed


def test_mutation_allows_reservation_methods_only():
    g = ScopedExecutionGateway(
        GatewayConfig(profile=NetworkProfile.TARGET_MUTATION, scope=SCOPE, allowed_methods={"POST"}),
        resolver=PUBLIC,
    )
    assert g.authorize("POST", "https://api.example.test/").allowed
    assert not g.authorize("DELETE", "https://api.example.test/").allowed


# --- passive provider ---

def test_passive_provider_allowlist_and_no_target_traffic():
    g = ScopedExecutionGateway(
        GatewayConfig(profile=NetworkProfile.PASSIVE_PROVIDER, allowed_providers=["api.provider.test"], scope=SCOPE),
        resolver=PUBLIC,
    )
    assert g.authorize("GET", "https://api.provider.test/data").allowed
    assert not g.authorize("GET", "https://api.example.test/").allowed  # cannot hit targets
    assert not g.authorize("GET", "https://evil.com/").allowed


# --- private OAST ---

def test_private_oast_internal_host_allowed():
    def resolver(h):
        return ["10.1.2.3"] if h == "oast.aegis.internal" else ["93.184.216.34"]

    g = ScopedExecutionGateway(
        GatewayConfig(profile=NetworkProfile.PRIVATE_OAST, scope=SCOPE, oast_host="oast.aegis.internal"),
        resolver=resolver,
    )
    assert g.authorize("GET", "https://oast.aegis.internal/poll").allowed  # internal OAST exempt from private-IP block
    assert g.authorize("GET", "https://api.example.test/").allowed         # scope still allowed
    assert not g.authorize("GET", "https://evil.com/").allowed


# --- budget ---

def test_request_budget_exhaustion():
    g = obs(request_budget=2)
    assert g.authorize("GET", "https://api.example.test/1").allowed
    assert g.authorize("GET", "https://api.example.test/2").allowed
    d = g.authorize("GET", "https://api.example.test/3")
    assert not d.allowed and "budget" in d.reason
    assert g.requests_made == 2  # a denied request does not consume budget


def test_check_is_dry_run():
    g = obs(request_budget=1)
    assert g.check("GET", "https://api.example.test/").allowed
    assert g.requests_made == 0


# --- audit / require ---

def test_require_raises_on_block():
    with pytest.raises(GatewayBlocked):
        obs().require("GET", "https://evil.com/")


def test_audit_records_allow_and_deny():
    g = obs()
    g.authorize("GET", "https://api.example.test/")
    g.authorize("GET", "https://evil.com/")
    events = g.audit_events()
    assert [e.allowed for e in events] == [True, False]
    assert events[1].host == "evil.com"
