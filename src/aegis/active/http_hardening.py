"""HTTP response-hardening analysis (report-corpus driven).

Many corpus findings are *enabled* by a missing or wrong response header rather
than a single bug: an SVG/HTML upload served with an executable content-type and
no ``nosniff`` (stored XSS), a payment form with no framing protection (the CSS
card skimmer), a credentialed wildcard/reflected CORS policy on a sensitive API,
``Cache-Control: public`` on gated content (paywall bypass), or a CSP that permits
``'unsafe-inline'``. This classifies those postures from a response already
observed during authorized discovery — purely analytical, no traffic of its own.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

# Content types that execute script if a browser renders them.
_EXECUTABLE_TYPES = ("text/html", "application/xhtml+xml", "image/svg+xml")


class HardeningIssue(str, Enum):
    MISSING_NOSNIFF = "missing_nosniff"
    DANGEROUS_UPLOAD_CONTENT_TYPE = "dangerous_upload_content_type"
    MISSING_CSP = "missing_csp"
    UNSAFE_INLINE_CSP = "unsafe_inline_csp"
    MISSING_FRAME_PROTECTION = "missing_frame_protection"
    CREDENTIALED_WILDCARD_CORS = "credentialed_wildcard_cors"
    CREDENTIALED_REFLECTED_CORS = "credentialed_reflected_cors"
    CACHEABLE_PRIVATE_CONTENT = "cacheable_private_content"


@dataclass(frozen=True)
class HardeningFinding:
    issue: HardeningIssue
    url: str
    detail: str
    confidence: float


def analyze_response_hardening(
    *, url: str, headers: dict, content_type: str | None = None, request_origin: str | None = None,
    authenticated: bool = False, upload: bool = False, is_form: bool = False,
) -> list[HardeningFinding]:
    h = {k.lower(): v for k, v in (headers or {}).items()}
    ctype = (content_type or h.get("content-type", "")).split(";")[0].strip().lower()
    findings: list[HardeningFinding] = []

    def add(issue, detail, confidence):
        findings.append(HardeningFinding(issue, url, detail, confidence))

    # --- user-content / upload sniffing ---
    if upload:
        if h.get("x-content-type-options", "").lower() != "nosniff":
            add(HardeningIssue.MISSING_NOSNIFF,
                "user-upload response lacks X-Content-Type-Options: nosniff", 0.6)
        if ctype in _EXECUTABLE_TYPES:
            add(HardeningIssue.DANGEROUS_UPLOAD_CONTENT_TYPE,
                f"user upload served as executable content-type {ctype!r}", 0.85)

    # --- CORS: only dangerous when credentials are allowed ---
    acao = h.get("access-control-allow-origin", "")
    acac = h.get("access-control-allow-credentials", "").lower() == "true"
    if acac and acao == "*":
        add(HardeningIssue.CREDENTIALED_WILDCARD_CORS,
            "Access-Control-Allow-Credentials: true with wildcard origin", 0.7)
    elif acac and request_origin and acao == request_origin:
        add(HardeningIssue.CREDENTIALED_REFLECTED_CORS,
            f"credentialed CORS reflects arbitrary origin {request_origin!r}", 0.85)

    # --- HTML documents: CSP + framing ---
    if ctype in ("text/html", "application/xhtml+xml"):
        csp = h.get("content-security-policy", "")
        if not csp:
            add(HardeningIssue.MISSING_CSP, "HTML response has no Content-Security-Policy", 0.5)
        elif "unsafe-inline" in csp and "script-src" in csp:
            add(HardeningIssue.UNSAFE_INLINE_CSP, "CSP permits 'unsafe-inline' scripts", 0.6)
        if is_form and not h.get("x-frame-options") and "frame-ancestors" not in csp:
            add(HardeningIssue.MISSING_FRAME_PROTECTION,
                "sensitive/form page allows framing (no X-Frame-Options / frame-ancestors)", 0.7)

    # --- gated content that is cacheable in shared caches ---
    if authenticated and "public" in h.get("cache-control", "").lower():
        add(HardeningIssue.CACHEABLE_PRIVATE_CONTENT,
            "authenticated/gated content marked Cache-Control: public", 0.65)

    return findings
