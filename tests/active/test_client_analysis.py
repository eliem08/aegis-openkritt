"""Client-side script analysis (report-corpus driven)."""

from __future__ import annotations

from aegis.active import ClientIssue, analyze_client_script

URL = "https://app.example.test/static/app.js"


def issues(js):
    return {f.issue for f in analyze_client_script(js, URL)}


# --- postMessage wildcard target ---------------------------------------------

def test_wildcard_postmessage_target_is_flagged():
    js = "opener.postMessage(loginSuccessMessage, '*');"
    assert ClientIssue.POSTMESSAGE_WILDCARD_TARGET in issues(js)


def test_scoped_postMessage_target_is_clean():
    js = "opener.postMessage(msg, Config.DashboardUrl);"
    assert ClientIssue.POSTMESSAGE_WILDCARD_TARGET not in issues(js)


# --- message listener without origin check -----------------------------------

def test_message_listener_without_origin_check_is_flagged():
    js = "window.addEventListener('message', function(e){ init(e.data); });"
    assert ClientIssue.MESSAGE_LISTENER_NO_ORIGIN_CHECK in issues(js)


def test_message_listener_with_origin_check_is_clean():
    js = ("window.addEventListener('message', function(e){\n"
          "  if (e.origin !== 'https://app.example.test') return;\n"
          "  init(e.data);\n});")
    assert ClientIssue.MESSAGE_LISTENER_NO_ORIGIN_CHECK not in issues(js)


# --- unanchored host allowlist -----------------------------------------------

def test_substring_host_check_is_flagged():
    for js in ("if (location.hostname.indexOf('example.com') !== -1) allow();",
               "if (origin.includes('trusted.test')) proceed();"):
        assert ClientIssue.UNANCHORED_HOST_CHECK in issues(js)


def test_anchored_host_check_is_clean():
    js = "if (location.hostname === 'app.example.test') allow();"
    assert ClientIssue.UNANCHORED_HOST_CHECK not in issues(js)


def test_endswith_host_check_is_not_flagged():
    # endsWith on a dotted suffix is a common safe pattern, not the substring bug.
    js = "if (host.endsWith('.example.test')) allow();"
    assert ClientIssue.UNANCHORED_HOST_CHECK not in issues(js)


# --- provenance --------------------------------------------------------------

def test_findings_carry_line_and_source():
    findings = analyze_client_script("a=1;\nopener.postMessage(m, '*');", URL)
    assert findings[0].line == 2 and findings[0].source_url == URL


def test_clean_script_has_no_findings():
    assert analyze_client_script("export const add = (a,b) => a+b;", URL) == []
