"""Broken object-level authorization — BOLA / IDOR (CWE-639).

The highest-value, hardest-to-duplicate bug class. Method (safe by construction):
using two *researcher-owned* test accounts, confirm account A can read its own
seeded object (the object contains a canary only A should see), then attempt the
same object as account B. If B also receives the canary, that is a cross-account
read — proven **without ever touching a real user's data** (§18).
"""

from __future__ import annotations

from dataclasses import dataclass

from aegis.model import Canary, CanaryKind, Candidate, EvidenceBundle, InteractionStep

from .base import DetectionResult, DetectorContext, path_of


@dataclass
class ObjectRef:
    url: str
    owner: str  # identity name that owns this object
    canary: str  # a marker string present only in the owner's private data


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
