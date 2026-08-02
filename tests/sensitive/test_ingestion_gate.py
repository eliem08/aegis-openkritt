"""Sensitive data cannot pass the ingestion boundary (Phase 4).

The normalizer classifies each candidate before it enters the graph, and the
coordinator quarantines a task whose output trips the classifier — so a sensitive
value never reaches the asset graph, an artifact, or a report.
"""

from __future__ import annotations

from datetime import datetime, timezone

from aegis.adapters import AdapterEvent, EventKind, FakeDiscoveryAdapter
from aegis.api.persistence import SqliteRepository
from aegis.api.reservations import ReservationService
from aegis.api.store import EngagementRecord
from aegis.graph import SENSITIVE, Normalizer
from aegis.policy.scope import ScopeGuard
from aegis.scheduler import ScanConfig, ScanCoordinator, StageSpec, TaskSpec
from aegis.sensitive import SensitiveDataClassifier

NOW = datetime(2026, 8, 2, tzinfo=timezone.utc)
AWS = "AKIAIOSFODNN7EXAMPLE"


def event(kind, data, target="api.example.test"):
    return AdapterEvent(kind=kind, source="fake", observed_at=NOW, target=target,
                        task_id="tk", adapter_version="1", data=data)


# --- normalizer gate ---------------------------------------------------------

def test_sensitive_candidate_is_not_stored():
    norm = Normalizer(scope=ScopeGuard(["api.example.test"]), engagement_id="e", scan_id="s",
                      classifier=SensitiveDataClassifier())
    result = norm.normalize([
        event(EventKind.ROUTE, {"method": "GET", "path": "/x", "leaked": AWS})])
    assert result.assets == {} and result.sensitive is True
    assert any(r.reason == SENSITIVE for r in result.rejections)
    # only a redacted classification is retained
    assert result.sensitive_classifications[0]["category"] == "credential"
    assert AWS not in str(result.sensitive_classifications)


def test_clean_candidate_passes_the_gate():
    norm = Normalizer(scope=ScopeGuard(["api.example.test"]), engagement_id="e", scan_id="s",
                      classifier=SensitiveDataClassifier())
    result = norm.normalize([event(EventKind.ROUTE, {"method": "GET", "path": "/health"})])
    assert result.assets and result.sensitive is False


def test_without_a_classifier_the_gate_is_inactive():
    norm = Normalizer(scope=ScopeGuard(["api.example.test"]), engagement_id="e", scan_id="s")
    result = norm.normalize([event(EventKind.ROUTE, {"method": "GET", "path": "/x", "leaked": AWS})])
    assert result.assets and result.sensitive is False   # opt-in gate


# --- coordinator integration -------------------------------------------------

def repo_with_engagement(tmp_path):
    repo = SqliteRepository(str(tmp_path / "sens.db"))
    repo.save_engagement(EngagementRecord(
        id="eng-1", authorization={"customer_id": "t"}, status="active", created_at=NOW))
    return repo


def coordinator(repo, targets=("api.example.test", "leak.example.test")):
    return ScanCoordinator(
        repository=repo, reservations=ReservationService(repo),
        adapters={"fake-discovery": FakeDiscoveryAdapter()},
        config=ScanConfig(tenant_id="t", engagement_id="eng-1", scope_targets=tuple(targets)))


def test_coordinator_quarantines_a_task_that_leaks_sensitive_data(tmp_path):
    repo = repo_with_engagement(tmp_path)
    coord = coordinator(repo)
    scan_id = coord.plan_scan(
        [StageSpec("recon", "discovery")],
        [TaskSpec("fake-discovery", "leak.example.test", "recon")])

    step = coord.run_scan(scan_id)[0]
    assert step.outcome == "quarantined" and "sensitive" in step.reason

    task = repo.tasks_for_scan(scan_id)[0]
    assert task.status == "quarantined"
    # escalation raised, report blocked, and only redacted classifications stored
    assert task.result_summary["escalation"] == "operator_review_required"
    assert task.result_summary["report_blocked"] is True
    assert AWS not in str(task.result_summary)
    # nothing sensitive reached the graph
    assert repo.assets_for_engagement("eng-1") == []
    assert repo.observations_for_scan(scan_id) == []


def test_a_clean_target_still_succeeds(tmp_path):
    repo = repo_with_engagement(tmp_path)
    coord = coordinator(repo)
    scan_id = coord.plan_scan(
        [StageSpec("recon", "discovery")],
        [TaskSpec("fake-discovery", "api.example.test", "recon")])
    step = coord.run_scan(scan_id)[0]
    assert step.outcome == "succeeded" and repo.assets_for_engagement("eng-1")


def test_tenant_marker_triggers_quarantine(tmp_path):
    repo = repo_with_engagement(tmp_path)
    coord = ScanCoordinator(
        repository=repo, reservations=ReservationService(repo),
        adapters={"fake-discovery": FakeDiscoveryAdapter()},
        config=ScanConfig(tenant_id="t", engagement_id="eng-1",
                          scope_targets=("api.example.test",), sensitive_markers=("nginx",)))
    # "nginx" is a tenant-configured marker here, so the technology event trips it.
    scan_id = coord.plan_scan(
        [StageSpec("recon", "discovery")],
        [TaskSpec("fake-discovery", "api.example.test", "recon")])
    step = coord.run_scan(scan_id)[0]
    assert step.outcome == "quarantined"
