from datetime import datetime, timezone

import pytest

from aegis.ingest.source import SourceFormatError, map_platform_export


def _document():
    return {
        "retrieved_at": "2026-08-03T12:00:00Z",
        "authorization_expires_at": "2099-08-04T12:00:00Z",
        "programs": [{
            "handle": "example",
            "name": "Example",
            "offers_bounties": True,
            "policy": "Automated testing is not allowed. No AI-generated reports.",
            "scope": [
                {
                    "target": "https://api.example.test",
                    "type": "URL",
                    "in_scope": True,
                    "eligible_for_bounty": True,
                },
                {"target": "https://old.example.test", "type": "URL", "in_scope": False},
            ],
        }],
    }


@pytest.mark.parametrize("platform", ["bugcrowd", "intigriti"])
def test_user_export_maps_scope_policy_and_provenance(platform):
    snapshot = map_platform_export(_document(), platform=platform)[0]
    assert snapshot.rules.platform == platform
    assert snapshot.rules.in_scope[0].identifier == "https://api.example.test"
    assert snapshot.rules.out_of_scope[0].identifier == "https://old.example.test"
    assert snapshot.rules.automation_allowed is False
    assert snapshot.rules.ai_allowed is False
    assert snapshot.rules.offers_bounties is True
    assert len(snapshot.source_hash) == 64
    assert snapshot.expired is False


def test_export_requires_explicit_timezone_and_authorization_expiry():
    document = _document()
    document.pop("authorization_expires_at")
    with pytest.raises(SourceFormatError, match="authorization_expires_at"):
        map_platform_export(document, platform="bugcrowd")
    document = _document()
    document["retrieved_at"] = "2026-08-03T12:00:00"
    with pytest.raises(SourceFormatError, match="timezone"):
        map_platform_export(document, platform="intigriti")


def test_unknown_platform_and_ambiguous_scope_fail_closed():
    with pytest.raises(SourceFormatError, match="unsupported"):
        map_platform_export(_document(), platform="unknown")
    document = _document()
    document["programs"][0]["scope"] = [{}]
    with pytest.raises(SourceFormatError, match="target"):
        map_platform_export(document, platform="bugcrowd")
