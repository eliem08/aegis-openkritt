"""Scope allowlist enforcement, including every refusal path.

These are the tests that matter most: an out-of-scope request is the mistake that
gets a researcher banned, so the refusal path is asserted from as many angles as
the guard can be approached from.
"""

import json

import pytest

from aegis.arsenal.assets.scope import (
    MAX_CIDR_HOSTS,
    OutOfScopeError,
    ScopeFileError,
    build_allowlist,
    load_allowlist,
)


@pytest.fixture
def allowlist():
    return build_allowlist(
        program="acme",
        in_scope=["*.acme.com", "acme.com", "api.acme.io", "203.0.113.0/24",
                  "2001:db8::/64"],
        out_of_scope=["admin.acme.com", "*.internal.acme.com", "203.0.113.5"],
    )


@pytest.mark.parametrize(
    "destination",
    ["acme.com", "https://www.acme.com/path", "deep.sub.acme.com", "api.acme.io:8443",
     "http://203.0.113.10", "2001:db8::1"],
)
def test_in_scope_destinations_are_allowed(allowlist, destination):
    assert allowlist.is_allowed(destination)


@pytest.mark.parametrize(
    "destination,expected_fragment",
    [
        ("evil.com", "no allowlist entry"),
        ("acme.com.evil.com", "no allowlist entry"),
        ("notacme.com", "no allowlist entry"),
        ("203.0.114.1", "no allowlist entry"),
        ("2001:db9::1", "no allowlist entry"),
        ("admin.acme.com", "explicitly listed out of scope"),
        ("secrets.internal.acme.com", "explicitly listed out of scope"),
        ("203.0.113.5", "explicitly listed out of scope"),
        ("", "empty destination"),
        ("   ", "empty destination"),
    ],
)
def test_out_of_scope_destinations_are_refused_with_a_reason(
    allowlist, destination, expected_fragment,
):
    decision = allowlist.evaluate(destination)
    assert not decision.allowed
    assert expected_fragment in decision.reason


def test_exclusions_override_a_matching_wildcard(allowlist):
    assert allowlist.is_allowed("shop.acme.com")
    assert not allowlist.is_allowed("admin.acme.com")


def test_wildcard_does_not_cover_the_apex_unless_listed():
    narrow = build_allowlist(program="x", in_scope=["*.example.com"])
    assert narrow.is_allowed("a.example.com")
    assert not narrow.is_allowed("example.com")


def test_require_raises_on_refusal(allowlist):
    allowlist.require("acme.com")
    with pytest.raises(OutOfScopeError) as info:
        allowlist.require("evil.com")
    assert info.value.destination == "evil.com"


def test_hostname_is_never_resolved_into_a_cidr_match():
    # A CIDR entry must not authorize a *hostname* that happens to resolve into it:
    # DNS is attacker-influenced and a resolver answer is not authorization.
    only_network = build_allowlist(program="x", in_scope=["203.0.113.0/24"])
    assert only_network.is_allowed("203.0.113.7")
    assert not only_network.is_allowed("localhost")
    assert not only_network.is_allowed("acme.com")


def test_empty_allowlist_is_refused_at_construction():
    with pytest.raises(ScopeFileError):
        build_allowlist(program="x", in_scope=[])


@pytest.mark.parametrize("entry", ["*", "any", "all", "*.*"])
def test_catch_all_entries_are_refused(entry):
    with pytest.raises(ScopeFileError):
        build_allowlist(program="x", in_scope=[entry])


def test_malformed_entries_raise_rather_than_being_dropped_silently():
    with pytest.raises(ScopeFileError):
        build_allowlist(program="x", in_scope=["203.0.113.0/99"])
    with pytest.raises(ScopeFileError):
        build_allowlist(program="x", in_scope=["*."])


def test_cidr_expansion_is_scope_checked_and_budget_capped(allowlist):
    hosts = allowlist.expand_network("203.0.113.0/30")
    assert "203.0.113.1" in hosts
    with pytest.raises(OutOfScopeError):
        allowlist.expand_network("198.51.100.0/30")
    wide = build_allowlist(program="x", in_scope=["10.0.0.0/8"])
    with pytest.raises(OutOfScopeError) as info:
        wide.expand_network("10.0.0.0/8")
    assert str(MAX_CIDR_HOSTS) in str(info.value)


def test_load_json_scope_file(tmp_path):
    path = tmp_path / "scope.json"
    path.write_text(json.dumps({
        "program": "acme-bbp",
        "in_scope": ["*.acme.com"],
        "out_of_scope": ["admin.acme.com"],
        "notes": {"engagement_url": "https://example.invalid/acme"},
    }), encoding="utf-8")
    allowlist = load_allowlist(path)
    assert allowlist.program == "acme-bbp"
    assert allowlist.is_allowed("www.acme.com")
    assert not allowlist.is_allowed("admin.acme.com")
    assert allowlist.document()["notes"]["engagement_url"]


def test_load_text_scope_file_with_comments_and_exclusions(tmp_path):
    path = tmp_path / "acme.txt"
    path.write_text(
        "# acme program scope\n*.acme.com\napi.acme.io\n!admin.acme.com\n\n",
        encoding="utf-8",
    )
    allowlist = load_allowlist(path)
    assert allowlist.program == "acme"
    assert allowlist.is_allowed("api.acme.io")
    assert not allowlist.is_allowed("admin.acme.com")


def test_missing_or_empty_scope_file_is_an_error(tmp_path):
    with pytest.raises(ScopeFileError):
        load_allowlist(tmp_path / "absent.json")
    empty = tmp_path / "empty.json"
    empty.write_text("   ", encoding="utf-8")
    with pytest.raises(ScopeFileError):
        load_allowlist(empty)


def test_invalid_json_scope_file_is_an_error(tmp_path):
    path = tmp_path / "broken.json"
    path.write_text('{"program": "x", ', encoding="utf-8")
    with pytest.raises(ScopeFileError):
        load_allowlist(path)


def test_document_is_serializable_and_lists_both_sides(allowlist):
    document = allowlist.document()
    json.dumps(document)
    assert "*.acme.com" in document["in_scope"]["wildcards"]
    assert "admin.acme.com" in document["out_of_scope"]["hosts"]
    assert document["entry_count"] == allowlist.size
