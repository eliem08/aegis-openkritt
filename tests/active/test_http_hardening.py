"""HTTP response-hardening analysis (report-corpus driven)."""

from __future__ import annotations

from aegis.active import HardeningIssue, analyze_response_hardening

URL = "https://app.example.test/x"


def issues(**kw):
    return {f.issue for f in analyze_response_hardening(url=URL, **kw)}


# --- upload / sniffing (presigned-upload stored XSS) -------------------------

def test_svg_upload_without_nosniff_is_flagged():
    found = issues(headers={"Content-Type": "image/svg+xml"}, upload=True)
    assert HardeningIssue.DANGEROUS_UPLOAD_CONTENT_TYPE in found
    assert HardeningIssue.MISSING_NOSNIFF in found


def test_upload_with_nosniff_and_safe_type_is_clean():
    found = issues(headers={"Content-Type": "image/png", "X-Content-Type-Options": "nosniff"},
                   upload=True)
    assert found == set()


# --- CORS (credentialed) -----------------------------------------------------

def test_credentialed_wildcard_cors_is_flagged():
    found = issues(headers={"Access-Control-Allow-Origin": "*",
                            "Access-Control-Allow-Credentials": "true"})
    assert HardeningIssue.CREDENTIALED_WILDCARD_CORS in found


def test_credentialed_reflected_origin_is_flagged():
    found = issues(headers={"Access-Control-Allow-Origin": "https://evil.test",
                            "Access-Control-Allow-Credentials": "true"},
                   request_origin="https://evil.test")
    assert HardeningIssue.CREDENTIALED_REFLECTED_CORS in found


def test_wildcard_cors_without_credentials_is_not_flagged():
    assert issues(headers={"Access-Control-Allow-Origin": "*"}) == set()


# --- HTML CSP + framing (card skimmer / cookie consent) ----------------------

def test_html_without_csp_is_flagged():
    assert HardeningIssue.MISSING_CSP in issues(headers={"Content-Type": "text/html"})


def test_unsafe_inline_csp_is_flagged():
    found = issues(headers={"Content-Type": "text/html",
                            "Content-Security-Policy": "script-src 'self' 'unsafe-inline'"})
    assert HardeningIssue.UNSAFE_INLINE_CSP in found


def test_payment_form_without_framing_protection_is_flagged():
    found = issues(headers={"Content-Type": "text/html",
                            "Content-Security-Policy": "default-src 'self'"}, is_form=True)
    assert HardeningIssue.MISSING_FRAME_PROTECTION in found


def test_form_with_frame_ancestors_is_protected():
    found = issues(headers={"Content-Type": "text/html",
                            "Content-Security-Policy": "frame-ancestors 'self'"}, is_form=True)
    assert HardeningIssue.MISSING_FRAME_PROTECTION not in found


# --- cacheable gated content (paywall bypass) --------------------------------

def test_authenticated_public_cache_is_flagged():
    found = issues(headers={"Content-Type": "application/json", "Cache-Control": "public, max-age=3600"},
                   authenticated=True)
    assert HardeningIssue.CACHEABLE_PRIVATE_CONTENT in found


def test_private_cache_on_gated_content_is_clean():
    found = issues(headers={"Content-Type": "application/json", "Cache-Control": "private, no-store"},
                   authenticated=True)
    assert HardeningIssue.CACHEABLE_PRIVATE_CONTENT not in found
