"""Surface analyzer findings into the reporting flow.

The analytical detectors (auth-posture, HTTP hardening, client-side script, JS
secrets) run over artifacts a scan already collected. :func:`surface_candidates`
runs them and converts each finding into a report :class:`~aegis.model.Candidate`
— a hypothesis carrying a CWE, confidence, and a redacted location — so a scan
surfaces them automatically. Every candidate is unverified (candidate != finding)
and never carries a raw secret.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from aegis.model import Candidate

from .auth_posture import AuthPosture, analyze_auth_differential
from .client_analysis import ClientIssue, analyze_client_script
from .http_hardening import HardeningIssue, analyze_response_hardening
from .js_secrets import analyze_javascript_secrets

_HARDENING_CWE = {
    HardeningIssue.MISSING_NOSNIFF: "CWE-79",
    HardeningIssue.DANGEROUS_UPLOAD_CONTENT_TYPE: "CWE-79",
    HardeningIssue.MISSING_CSP: "CWE-79",
    HardeningIssue.UNSAFE_INLINE_CSP: "CWE-79",
    HardeningIssue.MISSING_FRAME_PROTECTION: "CWE-1021",
    HardeningIssue.CREDENTIALED_WILDCARD_CORS: "CWE-942",
    HardeningIssue.CREDENTIALED_REFLECTED_CORS: "CWE-942",
    HardeningIssue.CACHEABLE_PRIVATE_CONTENT: "CWE-525",
}
_JS_SECRET_CWE = "CWE-798"
_CLIENT_CWE = "CWE-346"


def _host(url: str) -> str:
    return (urlsplit(url).hostname or url or "").lower()


def _path(url: str) -> str:
    return urlsplit(url).path or "/"


def surface_candidates(
    *, hardening_responses=(), scripts=(), auth_observations=(), scope_hosts=(),
) -> list[Candidate]:
    """Run the analytical analyzers over collected artifacts; return candidates."""
    candidates: list[Candidate] = []

    for resp in hardening_responses:
        url = resp.get("url", "")
        for f in analyze_response_hardening(
            url=url, headers=resp.get("headers", {}), content_type=resp.get("content_type"),
            request_origin=resp.get("request_origin"), authenticated=resp.get("authenticated", False),
            upload=resp.get("upload", False), is_form=resp.get("is_form", False),
        ):
            candidates.append(Candidate(
                asset=_host(url), route=_path(url), action="passive_discovery",
                worker="analyzer:hardening", observed=f.detail,
                expected="secure response headers / content type", cwe=_HARDENING_CWE[f.issue],
                confidence=f.confidence, p_exploit=f.confidence, business_impact=0.5))

    for script in scripts:
        url = script.get("url", "")
        text = script.get("text", "")
        for f in analyze_client_script(text, url):
            candidates.append(Candidate(
                asset=_host(url), action="passive_discovery", worker="analyzer:client_script",
                code_location=f"{url}:{f.line}", observed=f"{f.issue.value}: {f.snippet}",
                expected="origin-validated messaging / anchored allowlist", cwe=_CLIENT_CWE,
                confidence=f.confidence, p_exploit=f.confidence))
        for f in analyze_javascript_secrets(text, url, scope_hosts=scope_hosts):
            candidates.append(Candidate(
                asset=_host(url), action="passive_discovery", worker="analyzer:js_secrets",
                code_location=f"{url}:{f.line}",
                observed=f"{f.category} in {'first-party' if f.first_party else 'third-party'} JS ({f.context})",
                expected="no credentials in client-delivered code", cwe=_JS_SECRET_CWE,
                confidence=f.confidence, p_exploit=f.confidence,
                business_impact=0.9 if f.first_party else 0.4))

    for anomaly in analyze_auth_differential(auth_observations):
        cwe = "CWE-306" if anomaly.posture is not AuthPosture.ENFORCED else "CWE-284"
        candidates.append(Candidate(
            asset=anomaly.host, route=anomaly.path, action="authenticated_testing",
            worker="analyzer:auth_posture", observed=anomaly.reason,
            expected="consistent authentication across the API family", cwe=cwe,
            confidence=anomaly.confidence, p_exploit=anomaly.confidence, business_impact=0.85))

    return candidates
