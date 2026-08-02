"""CORS misconfiguration (CWE-942).

Safe by construction: send a benign canary ``Origin`` and read the response
headers. The serious, high-value case is a server that **reflects an arbitrary
origin AND allows credentials** — that lets any site read authenticated
responses cross-origin. (``Access-Control-Allow-Origin: *`` with credentials is
ignored by browsers, so it is not flagged as critical.)
"""

from __future__ import annotations

from aegis.model import Canary, CanaryKind, Candidate, EvidenceBundle, InteractionStep

from .base import DetectionResult, DetectorContext, path_of

CANARY_ORIGIN = "https://aegis-canary.example"


class CorsMisconfigDetector:
    name = "cors"
    action = "benign_request_mutation"
    cwe = "CWE-942"

    def __init__(self, paths: list[str] | None = None) -> None:
        self._paths = paths

    def _target_paths(self, ctx: DetectorContext) -> list[str]:
        return self._paths if self._paths is not None else ctx.params.get("cors_paths", ["/", "/api", "/api/user"])

    def applicable(self, ctx: DetectorContext) -> bool:
        return True

    def run(self, ctx: DetectorContext) -> DetectionResult:
        result = DetectionResult()
        for path in self._target_paths(ctx):
            try:
                resp = ctx.get(path, headers={"Origin": CANARY_ORIGIN})
            except Exception:
                continue
            acao = resp.headers.get("access-control-allow-origin", "")
            acac = resp.headers.get("access-control-allow-credentials", "").lower()
            if acao == CANARY_ORIGIN and acac == "true":
                result.add(*self._finding(ctx, path, resp, acao))
                return result  # one solid proof is enough
        return result

    def _finding(self, ctx, path, resp, acao):
        evidence = EvidenceBundle(
            steps=[
                InteractionStep(
                    summary=f"GET {path} with Origin: {CANARY_ORIGIN} -> reflected with credentials",
                    request=f"GET {path}\nOrigin: {CANARY_ORIGIN}",
                    response=f"Access-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: true",
                )
            ],
            canary=Canary(kind=CanaryKind.SYNTHETIC_MARKER, value=CANARY_ORIGIN,
                          note="arbitrary origin reflected into ACAO with credentials"),
            observed="server reflects arbitrary Origin and allows credentials",
            expected="only allowlisted origins reflected; credentials not combined with reflection",
            confidence=0.8,
            replay_ref=f"replay://{ctx.host}{path}/cors",
        )
        candidate = Candidate(
            asset=ctx.host,
            route=path_of(path),
            parameter="Origin",
            action=self.action,
            worker="detector:cors",
            observed="credentialed CORS reflection of arbitrary origin",
            expected="strict origin allowlist",
            impact="any origin can read authenticated responses cross-origin",
            cwe=self.cwe,
            confidence=0.8,
            evidence_id=evidence.evidence_id,
            p_exploit=0.6,
            business_impact=0.8,
            asset_criticality=0.8,
        )
        return candidate, evidence
