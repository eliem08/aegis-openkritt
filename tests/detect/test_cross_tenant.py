"""Cross-tenant access-control detector (report-corpus driven).

Two researcher-owned accounts in different tenants; if tenant B can read tenant
A's canaried object, that is a cross-tenant isolation failure — proven with no
real customer data.
"""

from __future__ import annotations

import httpx

from aegis.detect import CrossTenantDetector, CrossTenantResource, DetectorContext, Identity

CANARY = "CANARY-tenantA-9f2c"
IDENTITIES = [
    Identity("alice", {"X-Account": "alice", "X-Tenant": "tenant-a"}, tenant="tenant-a"),
    Identity("bob", {"X-Account": "bob", "X-Tenant": "tenant-b"}, tenant="tenant-b"),
]


class TenantApp:
    """/vault/1001 belongs to alice (tenant-a). `leaky` controls cross-tenant read."""

    def __init__(self, *, leaky: bool):
        self.leaky = leaky

    def __call__(self, request: httpx.Request) -> httpx.Response:
        headers = {k.lower(): v for k, v in request.headers.items()}
        tenant = headers.get("x-tenant")
        path = request.url.path
        if path == "/vault/1001":
            if tenant == "tenant-a":                       # the owner tenant
                return httpx.Response(200, text=f"<record>{CANARY}</record>")
            if self.leaky:                                 # bug: any tenant reads it
                return httpx.Response(200, text=f"<record>{CANARY}</record>")
            return httpx.Response(403, text="forbidden")
        return httpx.Response(404, text="not found")


def context(app):
    client = httpx.Client(transport=httpx.MockTransport(app))
    return DetectorContext(base_url="https://api.example.test", client=client,
                           identities=IDENTITIES, action="authenticated_testing")


def resources():
    return [CrossTenantResource(url="/vault/1001", owner="alice", canary=CANARY)]


def test_cross_tenant_read_is_detected():
    ctx = context(TenantApp(leaky=True))
    result = CrossTenantDetector(resources()).run(ctx)
    assert len(result.candidates) == 1
    c = result.candidates[0]
    assert c.cwe == "CWE-639" and "isolation failure" in c.impact
    assert "tenant-b" in result.evidence[0].observed and "tenant-a" in result.evidence[0].observed


def test_properly_isolated_tenants_yield_no_finding():
    ctx = context(TenantApp(leaky=False))
    assert CrossTenantDetector(resources()).run(ctx).candidates == []


def test_detector_requires_two_distinct_tenants():
    single = [Identity("alice", {}, tenant="tenant-a"), Identity("alice2", {}, tenant="tenant-a")]
    client = httpx.Client(transport=httpx.MockTransport(TenantApp(leaky=True)))
    ctx = DetectorContext(base_url="https://api.example.test", client=client,
                          identities=single, action="authenticated_testing")
    assert CrossTenantDetector(resources()).applicable(ctx) is False


def test_detector_is_applicable_with_two_tenants_and_resources():
    assert CrossTenantDetector(resources()).applicable(context(TenantApp(leaky=True))) is True


def test_registered_in_default_registry():
    from aegis.detect import default_registry

    names = {d.name for d in default_registry().all()}
    assert "cross_tenant" in names
