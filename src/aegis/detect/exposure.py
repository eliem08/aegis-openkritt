"""Exposed sensitive files — VCS/config/credential leakage (CWE-538 / CWE-200).

High-value and safe: GET a short list of sensitive web-root paths and flag only
those returning 200 *with a content signature* (so a SPA 200 isn't a match). The
matched signature is the canary — real proof drawn from the response itself.
"""

from __future__ import annotations

from aegis.model import Canary, CanaryKind, Candidate, EvidenceBundle, InteractionStep

from .base import DetectionResult, DetectorContext, path_of

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


# Specific framework/DB error signatures (chosen to avoid false positives).
_ERROR_SIGNATURES = [
    "Traceback (most recent call last)",
    "java.lang.",
    "SQLSTATE[",
    "ORA-0",
    ".php on line",
    "org.postgresql.util.PSQLException",
    "com.mysql.jdbc",
    "psycopg2.errors",
    "System.NullReferenceException",
    "Microsoft OLE DB Provider",
]
# Odd input likely to trip weak error handling (non-destructive).
_PROBE_VALUE = "%27%22%5B%5D%00"  # ' " [ ] NUL, url-encoded


class ErrorDisclosureDetector:
    """Verbose error / stack-trace disclosure (CWE-209).

    Sends a benign malformed value and flags responses that leak a framework or
    database stack trace. GET-only; the probe value is inert.
    """

    name = "error_disclosure"
    action = "benign_request_mutation"
    cwe = "CWE-209"

    def __init__(self, paths: list[str] | None = None) -> None:
        self._paths = paths

    def _target_paths(self, ctx: DetectorContext) -> list[str]:
        return self._paths if self._paths is not None else ctx.params.get("error_paths", ["/", "/search", "/api"])

    def applicable(self, ctx: DetectorContext) -> bool:
        return True

    def run(self, ctx: DetectorContext) -> DetectionResult:
        result = DetectionResult()
        for path in self._target_paths(ctx):
            url = f"{path}?aegisprobe={_PROBE_VALUE}"
            try:
                resp = ctx.get(url)
            except Exception:
                continue
            hit = next((s for s in _ERROR_SIGNATURES if s in resp.text), None)
            if hit:
                result.add(*self._finding(ctx, path, hit, resp))
                return result
        return result

    def _finding(self, ctx, path, signature, resp):
        evidence = EvidenceBundle(
            steps=[InteractionStep(
                summary=f"GET {path} with malformed input -> {resp.status_code} leaking '{signature}'",
                request=f"GET {path}?aegisprobe={_PROBE_VALUE}",
                response=f"{resp.status_code} … contains error signature '{signature}'",
            )],
            canary=Canary(kind=CanaryKind.SYNTHETIC_MARKER, value=signature,
                          note="framework/DB error signature in response"),
            observed="verbose error / stack trace disclosed to the client",
            expected="generic error page; internals not leaked",
            confidence=0.7,
            replay_ref=f"replay://{ctx.host}{path}/error-disclosure",
        )
        candidate = Candidate(
            asset=ctx.host, route=path_of(path), parameter="aegisprobe",
            action=self.action, worker="detector:error_disclosure",
            observed="stack trace / internal error disclosed", expected="no internal detail in errors",
            impact="information disclosure aiding further attacks", cwe=self.cwe,
            confidence=0.7, evidence_id=evidence.evidence_id,
            p_exploit=0.5, business_impact=0.5, asset_criticality=0.5,
        )
        return candidate, evidence
