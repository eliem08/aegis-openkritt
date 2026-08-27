import pytest

from aegis.policy import ScopeGuard, normalize_host


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("api.example.test", "api.example.test"),
        ("API.Example.Test", "api.example.test"),
        ("https://api.example.test/v1/users?x=1", "api.example.test"),
        ("api.example.test:8443", "api.example.test"),
        ("http://api.example.test.", "api.example.test"),
        ("//app.example.test/path", "app.example.test"),
    ],
)
def test_normalize_host(raw, expected):
    assert normalize_host(raw) == expected


@pytest.mark.parametrize("bad", ["", "   ", None])
def test_normalize_host_rejects_empty(bad):
    with pytest.raises(ValueError):
        normalize_host(bad)


def test_exact_match_only():
    guard = ScopeGuard(["api.example.test"])
    assert guard.is_allowed("api.example.test")
    assert guard.is_allowed("https://api.example.test/v1")
    assert not guard.is_allowed("evil.example.test")
    assert not guard.is_allowed("api.example.test.evil.com")


def test_exact_url_allowlist_entry_is_normalized_to_its_host():
    guard = ScopeGuard(["https://gitlab.com/gitlab-org/gitlab"])

    result = guard.evaluate("https://gitlab.com/gitlab-org/gitlab")

    assert result.in_scope is True
    assert result.host == "gitlab.com"
    assert result.matched_rule == "gitlab.com"


def test_wildcard_matches_subdomains_not_apex():
    guard = ScopeGuard(["*.example.test"])
    assert guard.is_allowed("a.example.test")
    assert guard.is_allowed("a.b.example.test")
    assert not guard.is_allowed("example.test")  # apex must be listed explicitly


def test_unparseable_destination_is_out_of_scope():
    guard = ScopeGuard(["api.example.test"])
    result = guard.evaluate("!!!not a host!!!")
    # It parses "!!!not" as a host-ish token but it won't be in the allowlist.
    assert not result.in_scope


def test_from_authorization():
    guard = ScopeGuard.from_authorization(["api.example.test", "app.example.test"])
    assert guard.size == 2
    assert guard.is_allowed("app.example.test")
