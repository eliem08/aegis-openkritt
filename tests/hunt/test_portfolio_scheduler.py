from decimal import Decimal

from aegis.ai.agentic_os import AuthorizationEnvelope, Budget, mint_execution_grant
from aegis.hunt import HuntConfig, HuntOrchestrator
from aegis.hunt.portfolio import plan_portfolio
from aegis.integrations.repo_pipeline import PipelineResult, RepoTarget
from aegis.learn import OutcomeStore, SubmissionLedger
from aegis.policy.signing import HmacSignatureVerifier


def program(handle, repos):
    return PipelineResult(
        handle=handle,
        repos=[RepoTarget(repo_full=repo, identifier=repo, eligible_for_bounty=True)
               for repo in repos],
    )


def test_known_payout_expected_value_wins_capacity_without_fabricated_amounts():
    decisions = plan_portfolio(
        [program("large", ["org/large"]), program("small", ["org/small"]),
         program("unknown", ["org/unknown"])],
        capacity=1,
        expected_bounties={"large": Decimal("1000"), "small": Decimal("10")},
        exploration_fraction=0,
    )
    selected = [decision for decision in decisions if decision.selected]
    assert [decision.handle for decision in selected] == ["large"]
    unknown = next(decision for decision in decisions if decision.handle == "unknown")
    assert unknown.score.missing_bounty is True
    assert unknown.score.gross_expected_value == Decimal("0")


class H1:
    def __init__(self):
        self.submitted = False

    def get_program(self, handle):
        return {"data": {"attributes": {"handle": handle, "policy": ""}}}

    def get_structured_scopes(self, handle):
        return [
            {"attributes": {
                "asset_type": "SOURCE_CODE",
                "asset_identifier": f"https://github.com/{handle}/{index}",
                "eligible_for_submission": True,
                "eligible_for_bounty": True,
                "max_severity": "high",
            }}
            for index in range(3)
        ]

    def list_my_reports(self):
        return []


class Scanner:
    def __init__(self):
        self.created = []

    def list_workflows(self):
        return [{"id": "workflow"}]

    def list_post_scripts(self):
        return [{"id": "post", "content": ""}]

    def list_severity_rankers(self):
        return [{"id": "ranker", "content": ""}]

    def create_scan(self, payload):
        self.created.append(payload)
        return {"id": f"scan-{len(self.created)}"}

    def import_candidates(self, scan_id, **kwargs):
        return []


def test_three_pass_scheduler_launches_only_allocated_repo_and_explains_dry_costs():
    h1 = H1()
    scanner = Scanner()
    verifier = HmacSignatureVerifier({"grant": "portfolio-test"})
    budget = Budget(max_cost_usd=100, max_requests=100, max_human_minutes=100)
    grant = mint_execution_grant(
        type("Allowed", (), {"allowed": True})(),
        scope_digest="scope:acme",
        budget=budget,
        verifier=verifier,
        network=True,
        external_model_egress=True,
    )
    config = HuntConfig(
        model="deepseek-v4-flash",
        only_handles=("acme",),
        dry_run=False,
        portfolio_capacity=1,
        expected_bounties={"acme": Decimal("1000")},
        exploration_fraction=0,
        authorizations={
            "acme": AuthorizationEnvelope(
                scope_digest="scope:acme", budget=budget, grant=grant,
            )
        },
        grant_verifier=verifier,
    )
    report = HuntOrchestrator(
        h1, scanner, OutcomeStore(), SubmissionLedger(), config=config,
    ).cycle()
    summary = report.summary()
    assert summary["passes"] == ["discovery", "portfolio_allocation", "verification"]
    assert summary["repos_in_scope"] == 3
    assert summary["portfolio_selected"] == 1
    assert summary["portfolio_skipped"] == 2
    assert summary["scans_launched_this_cycle"] == 1
    assert len(scanner.created) == 1
    assert scanner.created[0]["repo_full"] == "acme/0"
    assert Decimal(summary["estimated_selected_cost_usd"]) > 0
    assert Decimal(summary["expected_selected_net_value_usd"]) > 0
    assert h1.submitted is False
