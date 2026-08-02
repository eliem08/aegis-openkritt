"""Exposed sensitive files — VCS/config/credential leakage (CWE-538 / CWE-200).

High-value and safe: GET a short list of sensitive web-root paths and flag only
those returning 200 *with a content signature* (so a SPA 200 isn't a match). The
matched signature is the canary — real proof drawn from the response itself.
"""

from __future__ import annotations

from aegis.model import Canary, CanaryKind, Candidate, EvidenceBundle, InteractionStep

from .base import DetectionResult, DetectorContext

# path -> (signature that must appear in the body, cwe)
SENSITIVE_PATHS: dict[str, tuple[str, str]] = {
    "/.git/config": ("[core]", "CWE-538"),
    "/.git/HEAD": ("ref: refs/", "CWE-538"),
    "/.svn/entries": ("dir", "CWE-538"),
    "/.aws/credentials": ("aws_access_key_id", "CWE-200"),
    "/.DS_Store": ("Bud1", "CWE-538"),
}


class ExposedFileDetector:
    name = "exposed_files"
    action = "passive_discovery"
    cwe = "CWE-538"

    def __init__(self, paths: dict[str, tuple[str, str]] | None = None) -> None:
        self._paths = paths or SENSITIVE_PATHS

    def applicable(self, ctx: DetectorContext) -> bool:
        return True

    def run(self, ctx: DetectorContext) -> DetectionResult:
        result = DetectionResult()
        for path, (signature, cwe) in self._paths.items():
            try:
                resp = ctx.get(path)
            except Exception:
                continue
            if resp.status_code == 200 and signature in resp.text:
                result.add(*self._finding(ctx, path, signature, cwe, resp))
        return result

    def _finding(self, ctx, path, signature, cwe, resp):
        evidence = EvidenceBundle(
            steps=[
                InteractionStep(
                    summary=f"GET {path} -> 200 exposing sensitive content",
                    request=f"GET {path}",
                    response=f"200 … contains signature '{signature}'",
                )
            ],
            canary=Canary(kind=CanaryKind.SYNTHETIC_MARKER, value=signature,
                          note="signature proving the file is served"),
            observed=f"{path} is publicly readable",
            expected="404 / 403 (file not web-reachable)",
            confidence=0.8,
            replay_ref=f"replay://{ctx.host}{path}/exposed",
        )
        candidate = Candidate(
            asset=ctx.host,
            route=path,
            action=self.action,
            worker="detector:exposed_files",
            observed=f"sensitive file {path} exposed",
            expected="file not reachable from the web root",
            impact="source/config/credential exposure",
            cwe=cwe,
            confidence=0.8,
            evidence_id=evidence.evidence_id,
            p_exploit=0.6,
            business_impact=0.8,
            asset_criticality=0.7,
        )
        return candidate, evidence
