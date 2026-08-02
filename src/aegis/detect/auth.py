"""Missing authentication on a protected endpoint (CWE-306).

Given endpoints that are supposed to require authentication (configured, each
with a content signature to avoid false positives), request them with **no
credentials**. If the endpoint returns 200 with the signature, it is accessible
unauthenticated. Config comes from ``ctx.params["protected_endpoints"]`` as
``[{"url": "...", "signature": "..."}]``.
"""

from __future__ import annotations

from aegis.model import Canary, CanaryKind, Candidate, EvidenceBundle, InteractionStep

from .base import DetectionResult, DetectorContext, path_of


class MissingAuthDetector:
    name = "missing_auth"
    action = "authenticated_testing"
    cwe = "CWE-306"

    def __init__(self, endpoints: list[dict] | None = None) -> None:
        self._endpoints = endpoints

    def _refs(self, ctx: DetectorContext) -> list[dict]:
        return self._endpoints if self._endpoints is not None else ctx.params.get("protected_endpoints", [])

    def applicable(self, ctx: DetectorContext) -> bool:
        return bool(self._refs(ctx))

    def run(self, ctx: DetectorContext) -> DetectionResult:
        result = DetectionResult()
        for ref in self._refs(ctx):
            url = ref.get("url")
            signature = ref.get("signature", "")
            if not url:
                continue
            try:
                resp = ctx.get(url)  # deliberately no identity -> unauthenticated
            except Exception:
                continue
            if resp.status_code == 200 and (not signature or signature in resp.text):
                result.add(*self._finding(ctx, url, signature, resp))
        return result

    def _finding(self, ctx, url, signature, resp):
        route = path_of(url)
        evidence = EvidenceBundle(
            steps=[
                InteractionStep(
                    summary=f"GET {route} with NO auth -> {resp.status_code} (protected data returned)",
                    request=f"GET {url}\n(no Authorization header)",
                    response=f"{resp.status_code} … signature '{signature}' present" if signature else f"{resp.status_code}",
                )
            ],
            canary=Canary(kind=CanaryKind.SYNTHETIC_MARKER, value=signature or "unauthenticated-200",
                          note="protected content returned without credentials"),
            observed="protected endpoint served data without authentication",
            expected="401 Unauthorized / 403 Forbidden",
            confidence=0.85,
            replay_ref=f"replay://{ctx.host}{route}/missing-auth",
        )
        candidate = Candidate(
            asset=ctx.host,
            route=route,
            action=self.action,
            worker="detector:missing_auth",
            observed="endpoint accessible without authentication",
            expected="authentication required",
            impact="unauthenticated access to protected functionality/data",
            cwe=self.cwe,
            confidence=0.85,
            evidence_id=evidence.evidence_id,
            p_exploit=0.8,
            business_impact=0.85,
            asset_criticality=0.85,
        )
        return candidate, evidence
