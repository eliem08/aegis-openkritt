"""Cross-tenant access control — CWE-639 across the tenant boundary.

A recurring, high-impact class in the report corpus: a resource created by one
tenant is readable (or a ciphertext decryptable) by a *different* tenant because a
single endpoint validates the session but not the tenant scope. This detector
proves it the same safe way BOLA does — with two **researcher-owned** accounts,
but ones deliberately placed in *different tenants*: confirm tenant A can read its
own seeded object (holding a canary only A should see), then attempt it as tenant
B. If B receives the canary, that is a cross-tenant read — proven without ever
touching a real customer's data.
"""

from __future__ import annotations

from dataclasses import dataclass

from aegis.model import Canary, CanaryKind, Candidate, EvidenceBundle, InteractionStep

from .base import DetectionResult, DetectorContext, path_of


@dataclass
class CrossTenantResource:
    """A tenant A object seeded with a canary, to be re-fetched as tenant B."""

    url: str
    owner: str          # identity name that owns it (in tenant A)
    canary: str         # marker present only in the owner-tenant's private data


class CrossTenantDetector:
    name = "cross_tenant"
    action = "authenticated_testing"
    cwe = "CWE-639"

    def __init__(self, resources: list[CrossTenantResource] | None = None) -> None:
        self._resources = resources

    def _refs(self, ctx: DetectorContext) -> list[CrossTenantResource]:
        if self._resources is not None:
            return self._resources
        return [CrossTenantResource(**r) if isinstance(r, dict) else r
                for r in ctx.params.get("cross_tenant_resources", [])]

    def applicable(self, ctx: DetectorContext) -> bool:
        # Needs owned accounts spanning at least two distinct tenants.
        tenants = {i.tenant for i in ctx.identities if i.tenant}
        return len(tenants) >= 2 and bool(self._refs(ctx))

    def run(self, ctx: DetectorContext) -> DetectionResult:
        result = DetectionResult()
        for res in self._refs(ctx):
            owner = ctx.identity(res.owner)
            if owner is None or owner.tenant is None:
                continue

            baseline = ctx.get(res.url, identity=owner)
            # Establish it really is the owner-tenant's private object.
            if baseline.status_code != 200 or res.canary not in baseline.text:
                continue

            for other in [i for i in ctx.identities if i.tenant and i.tenant != owner.tenant]:
                probe = ctx.get(res.url, identity=other)
                if probe.status_code == 200 and res.canary in probe.text:
                    result.add(*self._finding(ctx, res, owner, other, baseline, probe))
        return result

    def _finding(self, ctx, res, owner, other, baseline, probe):
        route = path_of(res.url)
        evidence = EvidenceBundle(
            steps=[
                InteractionStep(
                    summary=f"GET {route} as '{owner.name}' (tenant {owner.tenant}) -> "
                            f"{baseline.status_code} (canary present)",
                    request=f"GET {res.url} (identity={owner.name}, tenant={owner.tenant})",
                    response=f"{baseline.status_code} … canary {res.canary} present",
                ),
                InteractionStep(
                    summary=f"GET {route} as '{other.name}' (tenant {other.tenant}) -> "
                            f"{probe.status_code} (canary LEAKED across tenants)",
                    request=f"GET {res.url} (identity={other.name}, tenant={other.tenant})",
                    response=f"{probe.status_code} … canary {res.canary} present",
                ),
            ],
            canary=Canary(kind=CanaryKind.SEEDED_RECORD, value=res.canary,
                          note=f"seeded in tenant {owner.tenant}'s own object"),
            observed=f"tenant '{other.tenant}' read tenant '{owner.tenant}'s private object",
            expected="403 Forbidden / 404 Not Found across tenant boundaries",
            confidence=0.92,
            replay_ref=f"replay://{ctx.host}{route}/cross-tenant",
        )
        candidate = Candidate(
            asset=ctx.host, route=route, parameter="object id (cross-tenant)",
            action=self.action, worker="detector:cross_tenant",
            observed=f"cross-tenant object read ({other.tenant} read {owner.tenant}'s object)",
            expected="tenant-scoped authorization enforced server-side",
            impact="one tenant can read another tenant's data — multi-tenant isolation failure",
            cwe=self.cwe, confidence=0.92, evidence_id=evidence.evidence_id,
            p_exploit=0.9, business_impact=0.95, asset_criticality=0.95,
        )
        return candidate, evidence
