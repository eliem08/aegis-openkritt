from pathlib import Path

import pytest

from aegis.ai.reproduction_first import (
    AuthorizationObservation,
    BenchmarkGate,
    BenchmarkResult,
    FindingStage,
    GraphAnalysisAdapter,
    IdentityContext,
    NormalizedFinding,
    OfflineOsvSnapshot,
    OpenApiOperation,
    PatchSignal,
    RepositoryProfile,
    ScannerCapability,
    ScannerCapabilityRegistry,
    StatefulApiPlan,
    deduplicate_findings,
    evaluate_cross_user_exposure,
    infer_variant_query,
    order_api_operations,
)


DIGEST = "sha256:" + "a" * 64


def test_scanner_registry_requires_digest_and_selects_by_profile() -> None:
    registry = ScannerCapabilityRegistry(
        [
            ScannerCapability(
                name="semgrep",
                image="semgrep/semgrep",
                digest=DIGEST,
                languages=("python",),
            )
        ]
    )
    plans = registry.plan(RepositoryProfile(("Python",), ()), "/repo")
    assert [plan.capability.name for plan in plans] == ["semgrep"]
    assert plans[0].network is False
    assert plans[0].read_only_repo is True
    assert len(plans[0].provenance_digest) == 64

    with pytest.raises(ValueError):
        ScannerCapability(name="bad", image="tool:latest", digest="latest")


def test_finding_stage_cannot_skip_reproduction_evidence() -> None:
    finding = NormalizedFinding(
        scanner="semgrep",
        rule_id="rule",
        fingerprint="abc",
        path="app.py",
        line=4,
        weakness="CWE-918",
        confidence=0.8,
    )
    validated = finding.promote(FindingStage.SOURCE_VALIDATED)
    assert validated.stage is FindingStage.SOURCE_VALIDATED
    with pytest.raises(ValueError):
        validated.promote(FindingStage.LOCALLY_REPRODUCED)


def test_deduplication_keeps_strongest_observation() -> None:
    weak = NormalizedFinding("a", "r1", "same", "a.py", 1, "CWE-89", 0.4)
    strong = NormalizedFinding("b", "r2", "same", "a.py", 1, "CWE-89", 0.9)
    assert deduplicate_findings([weak, strong]) == [strong]


def test_offline_osv_snapshot_verifies_digest(tmp_path: Path) -> None:
    database = tmp_path / "osv.db"
    database.write_bytes(b"offline snapshot")
    import hashlib

    sha256 = hashlib.sha256(database.read_bytes()).hexdigest()
    snapshot = OfflineOsvSnapshot(str(database), sha256, "2026-08-07T00:00:00Z", ("PyPI",))
    assert snapshot.verify() is True


def test_graph_plan_is_local_and_normalizes_path() -> None:
    plan = GraphAnalysisAdapter.plan("/repo", engine="joern")
    assert plan.local_only is True
    flow = GraphAnalysisAdapter.normalize(
        "joern",
        {
            "source": "request.args.url",
            "sink": "requests.get",
            "path": ["routes.py:10", "http.py:20"],
            "entrypoint_reachable": True,
            "confidence": 0.91,
        },
    )
    assert flow.entrypoint_reachable is True
    assert flow.confidence == 0.91


def test_cross_user_canary_is_deterministic_authorization_oracle() -> None:
    user_a = IdentityContext("a", "user", canary="owner-a-canary")
    user_b = IdentityContext("b", "user", canary="owner-b-canary")
    result = evaluate_cross_user_exposure(
        AuthorizationObservation(
            requester=user_b,
            owner=user_a,
            status_code=200,
            returned_markers=("owner-a-canary",),
        )
    )
    assert result.reproduced is True


def test_stateful_api_orders_producer_before_consumer() -> None:
    create = OpenApiOperation("create", "POST", "/objects", produces=("object_id",))
    read = OpenApiOperation("read", "GET", "/objects/{id}", consumes=("object_id",))
    ordered = order_api_operations([read, create])
    assert ordered == (create, read)
    plan = StatefulApiPlan(ordered, mode="fuzz-lean", request_budget=25)
    assert plan.local_only is True


def test_variant_query_infers_guard_regression_search() -> None:
    query = infer_variant_query(
        [
            PatchSignal(
                file="routes.py",
                added_guard="require_owner",
                object_type="invoice",
                route_family="billing",
            )
        ]
    )
    assert "authorization" in query.weakness_hint
    assert "require_owner" in query.structural_terms
    assert query.target_areas == ("billing",)


def test_benchmark_gate_values_reproduction_over_alert_volume() -> None:
    result = BenchmarkResult(
        detected=10,
        reproduced=7,
        false_positives=1,
        bounty_value_usd=2000,
        duplicate_adjusted_value_usd=900,
        model_cost_usd=20,
        scanner_cost_usd=15,
        human_review_minutes=60,
    )
    gate = BenchmarkGate(
        min_precision=0.8,
        min_reproduction_rate=0.6,
        max_cost_per_reproduced=10,
        min_duplicate_adjusted_value=500,
    )
    assert gate.accepts(result) is True
