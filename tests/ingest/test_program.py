import pytest

from aegis.ingest import (
    AssetType,
    ProgramRules,
    ScopeAsset,
    classify_asset_type,
    identifier_to_host,
    parse_policy_constraints,
)
from aegis.ingest.program import DEFAULT_PERMITTED_ACTIONS


@pytest.mark.parametrize(
    "raw,ident,expected",
    [
        ("URL", "api.example.com", AssetType.URL),
        ("URL", "*.example.com", AssetType.WILDCARD),
        ("CIDR", "10.0.0.0/24", AssetType.CIDR),
        ("GOOGLE_PLAY_APP_ID", "com.x.app", AssetType.ANDROID),
        ("SOMETHING_NEW", "x", AssetType.OTHER),
    ],
)
def test_classify_asset_type(raw, ident, expected):
    assert classify_asset_type(raw, ident) == expected


@pytest.mark.parametrize(
    "ident,expected",
    [
        ("api.example.com", "api.example.com"),
        ("https://api.example.com/graphql?x=1", "api.example.com"),
        ("*.example.com", "*.example.com"),
        ("API.Example.com:8443", "api.example.com"),
        ("", None),
    ],
)
def test_identifier_to_host(ident, expected):
    assert identifier_to_host(ident) == expected


def test_scope_asset_predicates():
    a = ScopeAsset(identifier="*.example.com", asset_type=AssetType.WILDCARD)
    assert a.is_web and a.is_wildcard
    assert a.host() == "*.example.com"
    cidr = ScopeAsset(identifier="10.0.0.0/24", asset_type=AssetType.CIDR)
    assert not cidr.is_web
    assert cidr.host() is None


def test_policy_detects_no_automation():
    c = parse_policy_constraints("Automated scanning is prohibited. Manual testing only.")
    assert c["automation_allowed"] is False


def test_policy_detects_no_ai():
    c = parse_policy_constraints("AI-generated reports are not accepted.")
    assert c["ai_allowed"] is False


def test_policy_parses_rate():
    c = parse_policy_constraints("Please limit to 5 requests per second.")
    assert c["rate_limit_rps"] == 5.0


def test_policy_default_allows_but_notes_caution():
    c = parse_policy_constraints("Test our assets and report responsibly.")
    assert c["automation_allowed"] is True
    assert c["ai_allowed"] is True
    assert any("heuristic" in n for n in c["notes"])


def _rules(**kw) -> ProgramRules:
    base = dict(
        handle="acme",
        in_scope=[
            ScopeAsset(identifier="api.acme.test", asset_type=AssetType.URL, eligible_for_submission=True),
            ScopeAsset(identifier="*.acme.test", asset_type=AssetType.WILDCARD, eligible_for_submission=True),
            ScopeAsset(identifier="10.0.0.0/24", asset_type=AssetType.CIDR, eligible_for_submission=True),
            ScopeAsset(identifier="dupe.acme.test", asset_type=AssetType.URL, eligible_for_submission=False),
        ],
        out_of_scope=[ScopeAsset(identifier="legacy.acme.test", asset_type=AssetType.URL, eligible_for_submission=False)],
    )
    base.update(kw)
    return ProgramRules(**base)


def test_scope_guard_entries_web_and_eligible_only():
    rules = _rules()
    assert rules.scope_guard_entries() == ["api.acme.test", "*.acme.test"]  # CIDR + ineligible excluded
    assert rules.out_of_scope_hosts() == ["legacy.acme.test"]


def test_authorization_draft_when_automation_allowed():
    rules = _rules(automation_allowed=True)
    draft = rules.to_authorization_draft(
        customer_id="c", authorization_id="a1",
        valid_from="2026-08-01T00:00:00Z", valid_until="2026-09-01T00:00:00Z",
    )
    assert draft["targets"] == ["api.acme.test", "*.acme.test"]
    assert draft["permitted_actions"] == DEFAULT_PERMITTED_ACTIONS
    assert draft["environment"] == "approved-production"
    assert draft["_meta"]["unsigned"] is True


def test_authorization_draft_blocks_when_automation_forbidden():
    rules = _rules(automation_allowed=False)
    draft = rules.to_authorization_draft(
        customer_id="c", authorization_id="a1",
        valid_from="2026-08-01T00:00:00Z", valid_until="2026-09-01T00:00:00Z",
    )
    assert draft["permitted_actions"] == []
    assert any("prohibit automated" in c for c in draft["_meta"]["conflicts"])
    assert rules.testable_by_automation is False


def test_rate_default_when_unparsed():
    rules = _rules(rate_limit_rps=None)
    draft = rules.to_authorization_draft(
        customer_id="c", authorization_id="a1",
        valid_from="2026-08-01T00:00:00Z", valid_until="2026-09-01T00:00:00Z",
    )
    assert draft["rate_limits"]["requests_per_second"] == 2.0
