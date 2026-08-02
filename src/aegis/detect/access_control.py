"""Broken object-level authorization — BOLA / IDOR (CWE-639).

The highest-value, hardest-to-duplicate bug class. Method (safe by construction):
using two *researcher-owned* test accounts, confirm account A can read its own
seeded object (the object contains a canary only A should see), then attempt the
same object as account B. If B also receives the canary, that is a cross-account
read — proven **without ever touching a real user's data** (§18).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from aegis.model import AttackSurface, Canary, CanaryKind, Candidate, EvidenceBundle, InteractionStep

from .base import DetectionResult, DetectorContext, path_of

_ID_SEGMENT = re.compile(r"^(\{[^}]+\}|\d+)$")


@dataclass
class ObjectRef:
    url: str
    owner: str  # identity name that owns this object
    canary: str  # a marker string present only in the owner's private data


@dataclass
class ObjectSeed:
    """An operator-seeded object in a discovered endpoint (their own account's).

    ``route`` is the endpoint template (e.g. ``/users/{id}``); ``object_id`` is
    the owner's own object; ``canary`` is a marker known to be in that object.
    """

    route: str
    object_id: str
    owner: str
    canary: str
    param: str = "id"


def route_signature(path: str) -> str:
    """Normalise id-bearing segments so ``/users/{id}`` and ``/users/1001`` match."""
    return "/".join("*" if _ID_SEGMENT.match(seg) else seg for seg in path.split("/"))


def build_bola_objects(surface: AttackSurface, seeds: list[ObjectSeed]) -> list[ObjectRef]:
    """Auto-wire recon output to BOLA targets: for each seed whose endpoint
    template was actually discovered, produce a concrete :class:`ObjectRef`."""
    discovered = {route_signature(r.path) for a in surface.assets for r in a.routes}
    objects: list[ObjectRef] = []
    for seed in seeds:
        if route_signature(seed.route) in discovered:
            if "{" in seed.route:
                url = seed.route.replace("{" + seed.param + "}", str(seed.object_id))
            else:
                url = seed.route
            objects.append(ObjectRef(url=url, owner=seed.owner, canary=seed.canary))
    return objects


class BflaDetector:
    """Broken Function-Level Authorization — BFLA (CWE-285).

    The function-level pair to BOLA: a *low-privilege* owned account calling a
    *privileged* endpoint. Config lists endpoints that should require elevation,
    each with the low-privilege identity name and a signature proving the
    privileged response. If the low-priv account gets 200 + signature, the
    function is not properly restricted.
    """

    name = "bfla"
    action = "authenticated_testing"
    cwe = "CWE-285"

    def __init__(self, endpoints: list[dict] | None = None) -> None:
        self._endpoints = endpoints

    def _refs(self, ctx: DetectorContext) -> list[dict]:
        return self._endpoints if self._endpoints is not None else ctx.params.get("privileged_endpoints", [])

    def applicable(self, ctx: DetectorContext) -> bool:
        return bool(self._refs(ctx)) and len(ctx.identities) >= 1

    def run(self, ctx: DetectorContext) -> DetectionResult:
        result = DetectionResult()
        for ref in self._refs(ctx):
            url = ref.get("url")
            signature = ref.get("signature", "")
            low = ctx.identity(ref.get("low_identity", "")) if ref.get("low_identity") else None
            if not url:
                continue
            resp = ctx.get(url, identity=low)
            if resp.status_code == 200 and (not signature or signature in resp.text):
                result.add(*self._finding(ctx, url, ref.get("low_identity", "low-priv"), signature, resp))
        return result

    def _finding(self, ctx, url, low_name, signature, resp):
        route = path_of(url)
        evidence = EvidenceBundle(
            steps=[InteractionStep(
                summary=f"GET {route} as low-priv '{low_name}' -> {resp.status_code} (privileged data)",
                request=f"GET {url} (identity={low_name})",
                response=f"{resp.status_code} … signature '{signature}' present" if signature else str(resp.status_code),
            )],
            canary=Canary(kind=CanaryKind.SYNTHETIC_MARKER, value=signature or "privileged-200",
                          note="privileged function reachable by a low-privilege account"),
            observed=f"low-privilege account '{low_name}' invoked a privileged function",
            expected="403 Forbidden for non-privileged roles",
            confidence=0.85,
            replay_ref=f"replay://{ctx.host}{route}/bfla",
        )
        candidate = Candidate(
            asset=ctx.host, route=route, action=self.action, worker="detector:bfla",
            observed="broken function-level authorization", expected="role check enforced server-side",
            impact="privilege escalation: low-privilege users can call privileged functions",
            cwe=self.cwe, confidence=0.85, evidence_id=evidence.evidence_id,
            p_exploit=0.8, business_impact=0.9, asset_criticality=0.9,
        )
        return candidate, evidence


class BolaDetector:
    name = "bola"
    action = "authenticated_testing"
    cwe = "CWE-639"

    def __init__(self, objects: list[ObjectRef] | None = None) -> None:
        self._objects = objects

    def _refs(self, ctx: DetectorContext) -> list[ObjectRef]:
        if self._objects is not None:
            return self._objects
        return [ObjectRef(**o) if isinstance(o, dict) else o for o in ctx.params.get("objects", [])]

    def applicable(self, ctx: DetectorContext) -> bool:
        return len(ctx.identities) >= 2 and bool(self._refs(ctx))

    def run(self, ctx: DetectorContext) -> DetectionResult:
        result = DetectionResult()
        for obj in self._refs(ctx):
            owner = ctx.identity(obj.owner)
            if owner is None:
                continue

            baseline = ctx.get(obj.url, identity=owner)
            # Establish that this really is a private object holding the canary.
            if baseline.status_code != 200 or obj.canary not in baseline.text:
                continue

            for other in [i for i in ctx.identities if i.name != obj.owner]:
                probe = ctx.get(obj.url, identity=other)
                if probe.status_code == 200 and obj.canary in probe.text:
                    result.add(*self._finding(ctx, obj, other.name, baseline, probe))
        return result

    def _finding(self, ctx, obj: ObjectRef, other: str, baseline, probe):
        route = path_of(obj.url)
        evidence = EvidenceBundle(
            steps=[
                InteractionStep(
                    summary=f"GET {route} as owner '{obj.owner}' -> {baseline.status_code} (canary present)",
                    request=f"GET {obj.url} (identity={obj.owner})",
                    response=f"{baseline.status_code} … canary {obj.canary} present",
                ),
                InteractionStep(
                    summary=f"GET {route} as other '{other}' -> {probe.status_code} (canary leaked)",
                    request=f"GET {obj.url} (identity={other})",
                    response=f"{probe.status_code} … canary {obj.canary} present",
                ),
            ],
            canary=Canary(kind=CanaryKind.SEEDED_RECORD, value=obj.canary,
                          note=f"seeded in {obj.owner}'s own object"),
            observed=f"account '{other}' read account '{obj.owner}'s private object",
            expected="403 Forbidden / 404 Not Found",
            confidence=0.9,
            replay_ref=f"replay://{ctx.host}{route}/bola",
        )
        candidate = Candidate(
            asset=ctx.host,
            route=route,
            parameter="object id",
            action=self.action,
            worker="detector:bola",
            observed=f"cross-account object read ({other} read {obj.owner}'s object)",
            expected="access denied for non-owner",
            impact="one authenticated user can read another user's objects (tenant data exposure)",
            cwe=self.cwe,
            confidence=0.9,
            evidence_id=evidence.evidence_id,
            p_exploit=0.85,
            business_impact=0.9,
            asset_criticality=0.9,
        )
        return candidate, evidence
