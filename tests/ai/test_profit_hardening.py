from __future__ import annotations

from aegis.ai.auto_hunt import HuntOutcome, HuntTarget
from aegis.ai.candidate_reduction import reduce_candidates
from aegis.ai.program_connectors import HackerOneConnector


def _scanner_row(*, path: str, tool: str = "gitleaks", confidence: float = 0.95):
    return {
        "source": f"aegis:tool:{tool}",
        "severity": "high",
        "confidence": confidence,
        "scanner_metadata": {"rule_id": "CWE-798", "cwe": "CWE-798"},
        "json_answer": {
            "vulnerability_type": "CWE-798",
            "file_path": path,
            "line": 12,
            "summary": "credential-like value",
        },
    }


def test_real_deployment_secret_is_not_suppressed():
    reduction = reduce_candidates([_scanner_row(path=".github/workflows/deploy.yml")])
    assert len(reduction.survivors) == 1
    assert reduction.survivors[0].path_class == "deploy"


def test_example_secret_is_still_suppressed():
    reduction = reduce_candidates([_scanner_row(path="config/app.env.example")])
    assert len(reduction.survivors) == 0
    assert "placeholder" in reduction.suppressed[0].reason


def test_scanners_only_shape_cannot_claim_confirmed():
    outcome = HuntOutcome(
        target=HuntTarget("acme/repo"),
        confirmed=2,
        findings=[
            {"origin": "scanner", "engine": "semgrep", "reproduction": None},
            {"origin": "scanner", "engine": "gitleaks", "reproduction": None},
        ],
    )
    assert outcome.confirmed == 0
    assert outcome.candidates == 2


def test_hackerone_paginates_scopes_and_separates_bounty_assets(monkeypatch):
    monkeypatch.setenv("HACKERONE_API_USERNAME", "u")
    monkeypatch.setenv("HACKERONE_API_TOKEN", "t")
    monkeypatch.setenv("AEGIS_H1_FETCH_SCOPES", "1")

    connector = HackerOneConnector()

    def fake_fetch(url, headers=None):
        if url.endswith("programs?page[size]=100"):
            return {
                "data": [{"attributes": {
                    "handle": "acme",
                    "submission_state": "open",
                    "offers_bounties": True,
                    "policy": "policy",
                }}],
                "links": {"next": None},
            }
        if "structured_scopes" in url and "page[size]=100" in url:
            return {
                "data": [
                    {"attributes": {
                        "asset_identifier": "https://github.com/acme/paid",
                        "eligible_for_submission": True,
                        "eligible_for_bounty": True,
                    }},
                    {"attributes": {
                        "asset_identifier": "https://github.com/acme/unpaid",
                        "eligible_for_submission": True,
                        "eligible_for_bounty": False,
                    }},
                ],
                "links": {"next": "https://next.example/scopes"},
            }
        if url == "https://next.example/scopes":
            return {
                "data": [{"attributes": {
                    "asset_identifier": "https://github.com/acme/excluded",
                    "eligible_for_submission": False,
                    "eligible_for_bounty": False,
                }}],
                "links": {"next": None},
            }
        raise AssertionError(url)

    connector.fetch_json = fake_fetch
    programs = connector.fetch()
    assert len(programs) == 1
    program = programs[0]
    assert program.targets == ["acme/paid", "acme/unpaid"]
    assert program.bounty_eligibility_known is True
    assert program.bounty_eligible_targets == ["acme/paid"]
    assert "acme/excluded" in program.out_of_scope
    assert program.scope_retrieved_at
