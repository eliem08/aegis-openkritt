from __future__ import annotations

from aegis.ai import target_authorization as ta
from aegis.ai.auto_hunt import HuntOutcome, HuntTarget
from aegis.ai.candidate_reduction import reduce_candidates
from aegis.ai.program_connectors import HackerOneConnector
from aegis.ai.registry import Program, save_registry


def _scanner_row(*, path: str, tool: str = "gitleaks", confidence: float = 0.95,
                 rule: str = "CWE-798", line: int = 12):
    return {
        "source": f"aegis:tool:{tool}",
        "severity": "high",
        "confidence": confidence,
        "scanner_metadata": {"rule_id": rule, "cwe": "CWE-798" if rule == "CWE-798" else ""},
        "json_answer": {
            "vulnerability_type": "CWE-798" if rule == "CWE-798" else rule,
            "file_path": path,
            "line": line,
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


def test_bandit_and_detect_secrets_do_not_self_corroborate_same_weak_family():
    rows = [
        _scanner_row(path="src/a.py", tool="detect-secrets", confidence=0.68, line=33),
        _scanner_row(path="src/a.py", tool="bandit", confidence=0.0, rule="B105", line=33),
    ]
    reduction = reduce_candidates(rows)
    assert reduction.survivors == []
    assert len(reduction.suppressed) == 2
    assert all(c.corroborators == 1 for c in reduction.suppressed)


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


def test_known_bounty_ineligible_asset_stays_unpaid_in_authorization(tmp_path):
    now = ta._now().isoformat()
    registry = tmp_path / "programs.json"
    save_registry([
        Program(
            handle="acme",
            platform="hackerone",
            targets=["acme/unpaid"],
            bounty_eligible_targets=[],
            bounty_eligibility_known=True,
            reward_ceiling=5000,
            active=True,
            source_retrieved_at=now,
            scope_retrieved_at=now,
        )
    ], registry)
    decision = ta.authorize(
        "acme/unpaid", registry_path=registry, ledger_path=tmp_path / "ledger.json", owned=[]
    )
    assert decision.allowed is True
    assert decision.record is not None
    assert decision.record.bounty_eligible is False


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
