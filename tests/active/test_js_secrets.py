"""High-value secrets in first-party JavaScript (report-corpus driven)."""

from __future__ import annotations

from aegis.active import analyze_javascript_secrets

SCOPE = ["app.example.test", "*.example.test"]
AWS = "AKIAIOSFODNN7EXAMPLE"
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.dozjgNryP4J3jVmNHl0w5N"
RSA = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n-----END RSA PRIVATE KEY-----"

BUNDLE = f"""
const config = {{ region: 'us-east-1' }};
const API_TOKEN = "{AWS}";
function auth() {{ return "Bearer {JWT}"; }}
export const clean = 42;
"""


def bundle_url(host="app.example.test"):
    return f"https://{host}/static/app.9f2c.js"


# --- detection ---------------------------------------------------------------

def test_first_party_bundle_credentials_are_found_with_high_confidence():
    findings = analyze_javascript_secrets(BUNDLE, bundle_url(), scope_hosts=SCOPE)
    categories = {f.category for f in findings}
    assert "credential" in categories and "session_token" in categories
    assert all(f.first_party and f.confidence >= 0.9 for f in findings)
    # line numbers point at the offending lines
    assert any(f.line == 3 for f in findings)


def test_private_key_in_a_bundle_is_flagged():
    findings = analyze_javascript_secrets(f"var k = `{RSA}`;", bundle_url(), scope_hosts=SCOPE)
    assert any(f.category == "private_key" for f in findings)


def test_raw_secret_never_appears_in_a_finding():
    findings = analyze_javascript_secrets(BUNDLE, bundle_url(), scope_hosts=SCOPE)
    blob = str([vars(f) for f in findings])
    assert AWS not in blob and JWT not in blob


def test_third_party_bundle_is_lower_confidence():
    findings = analyze_javascript_secrets(BUNDLE, bundle_url("cdn.thirdparty.test"), scope_hosts=SCOPE)
    assert findings and all(not f.first_party and f.confidence < 0.6 for f in findings)


def test_clean_javascript_has_no_findings():
    clean = "export function add(a, b) { return a + b; }\nconst x = [1,2,3];"
    assert analyze_javascript_secrets(clean, bundle_url(), scope_hosts=SCOPE) == []


def test_emails_and_pii_are_not_reported_as_js_secrets():
    # user-content categories are handled elsewhere; only credentials/tokens/keys here
    js = "const support = 'help@example.test'; const ok = true;"
    assert analyze_javascript_secrets(js, bundle_url(), scope_hosts=SCOPE) == []


def test_no_scope_treats_bundle_as_first_party():
    findings = analyze_javascript_secrets(f'var t="{AWS}";', bundle_url())
    assert findings and findings[0].first_party
