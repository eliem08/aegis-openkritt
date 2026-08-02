from aegis.knowledge import Severity, map_hacktivity, map_hacktivity_report

GRAPHQL_NODE = {
    "id": "Z2lkOi8v...",
    "databaseId": "900001",
    "title": "IDOR on invoices",
    "substate": "resolved",
    "severity_rating": "high",
    "weakness": {"name": "Insecure Direct Object Reference (IDOR)", "external_id": "CWE-639"},
    "structured_scope": {"asset_type": "URL", "asset_identifier": "api.acme.test"},
    "team": {"handle": "acme", "name": "Acme"},
    "total_awarded_amount": "2500.0",
    "disclosed_at": "2025-11-02T00:00:00Z",
    "url": "https://hackerone.com/reports/900001",
}

FLAT = {
    "report_id": "42",
    "title": "XSS",
    "cwe": "CWE-79",
    "severity": "medium",
    "asset_type": "url",
    "asset_identifier": "www.acme.test",
    "program": "acme",
    "bounty": 500,
}


def test_map_graphql_node():
    r = map_hacktivity_report(GRAPHQL_NODE)
    assert r.report_id == "Z2lkOi8v..."
    assert r.program == "acme"
    assert r.cwe == "CWE-639"
    assert r.severity == Severity.HIGH
    assert r.asset_type == "url"  # normalized lowercase
    assert r.asset_identifier == "api.acme.test"
    assert r.bounty == 2500.0
    assert r.disclosed_at is not None


def test_map_flat_shape():
    r = map_hacktivity_report(FLAT)
    assert r.report_id == "42"
    assert r.cwe == "CWE-79"
    assert r.severity == Severity.MEDIUM
    assert r.program == "acme"


def test_map_many():
    out = map_hacktivity([GRAPHQL_NODE, FLAT])
    assert len(out) == 2
    assert {r.cwe for r in out} == {"CWE-639", "CWE-79"}


def test_map_tolerates_missing_fields():
    r = map_hacktivity_report({"id": "x"})
    assert r.report_id == "x"
    assert r.cwe == ""
    assert r.severity == Severity.NONE
