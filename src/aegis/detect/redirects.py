"""Open redirect (CWE-601).

Safe by construction: send a redirect parameter pointing at a benign canary
host and inspect the response's ``Location`` header **without following it** (so
no out-of-scope request is ever made). If the target reflects the canary host
into ``Location`` on a 3xx, it is an open redirect.
"""

from __future__ import annotations

from aegis.model import Canary, CanaryKind, Candidate, EvidenceBundle, InteractionStep

from .base import DetectionResult, DetectorContext, path_of

CANARY_HOST = "aegis-canary.example"
REDIRECT_PARAMS = ["redirect", "url", "next", "return", "returnUrl", "dest", "destination", "redirect_uri"]


class OpenRedirectDetector:
    name = "open_redirect"
    action = "benign_request_mutation"
    cwe = "CWE-601"

    def __init__(self, paths: list[str] | None = None, params: list[str] | None = None) -> None:
        self._paths = paths
        self._params = params or REDIRECT_PARAMS

    def _target_paths(self, ctx: DetectorContext) -> list[str]:
        if self._paths is not None:
            return self._paths
        return ctx.params.get("redirect_paths", ["/login", "/logout", "/"])

    def applicable(self, ctx: DetectorContext) -> bool:
        return True

    def run(self, ctx: DetectorContext) -> DetectionResult:
        result = DetectionResult()
        target = f"https://{CANARY_HOST}/"
        for path in self._target_paths(ctx):
            for param in self._params:
                url = f"{path}?{param}={target}"
                try:
                    resp = ctx.get(url, follow_redirects=False)
                except Exception:
                    continue
                location = resp.headers.get("location", "")
                if resp.status_code in (301, 302, 303, 307, 308) and CANARY_HOST in location:
                    result.add(*self._finding(ctx, path, param, resp, location))
                    return result  # one solid proof is enough
        return result

    def _finding(self, ctx, path, param, resp, location):
        evidence = EvidenceBundle(
            steps=[
                InteractionStep(
                    summary=f"GET {path}?{param}=<canary> -> {resp.status_code} Location: {location}",
                    request=f"GET {path}?{param}=https://{CANARY_HOST}/",
                    response=f"{resp.status_code} Location: {location}",
                )
            ],
            canary=Canary(kind=CanaryKind.SYNTHETIC_MARKER, value=CANARY_HOST,
                          note="canary host reflected into Location"),
            observed=f"redirect to attacker-controlled host via '{param}'",
            expected="redirect only to allowlisted, same-origin targets",
            confidence=0.75,
            replay_ref=f"replay://{ctx.host}{path}/open-redirect",
        )
        candidate = Candidate(
            asset=ctx.host,
            route=path_of(path),
            parameter=param,
            action=self.action,
            worker="detector:open_redirect",
            observed="open redirect to external host",
            expected="redirect target validated against an allowlist",
            impact="phishing / OAuth token theft via redirect",
            cwe=self.cwe,
            confidence=0.75,
            evidence_id=evidence.evidence_id,
            p_exploit=0.6,
            business_impact=0.6,
            asset_criticality=0.6,
        )
        return candidate, evidence
