from __future__ import annotations

import hashlib

from aegis.ai.active_runtime import ActiveExecutionResult, run_active_plan
from aegis.ai.agentic_os import AuthorizationEnvelope, Budget, EvidenceRef
from aegis.graph import Asset, AssetKind


class RecordingDesyncExecutor:
    def __init__(self):
        self.calls = []

    def execute(self, task, context):
        self.calls.append((task, context))
        digest = hashlib.sha256(
            f"{task.detector}:{','.join(task.targets)}".encode("utf-8")
        ).hexdigest()
        return ActiveExecutionResult(
            status="observed",
            evidence=(
                EvidenceRef(
                    evidence_id=f"runtime:{digest[:16]}",
                    kind="http_desync_differential",
                    digest=digest,
                    summary="bounded authorized parser differential observed",
                ),
            ),
            requests_used=2,
            metadata={"detector": task.detector},
        )


def _desync_route():
    return Asset(
        engagement_id="eng",
        asset_key="route:POST api.example/upload",
        kind=AssetKind.ROUTE,
        attributes={
            "method": "POST",
            "path": "/upload",
            "host": "api.example",
            "client_protocol": "h2",
            "upstream_protocol": "http/1.1",
            "intermediary_chain": ["edge", "reverse-proxy"],
            "connection_reused": True,
            "response_desync_signal": True,
            "discovery_source": "authorized-protocol-observer",
        },
    )


def _approved_envelope(max_requests=10):
    return AuthorizationEnvelope(
        scope_digest="scope",
        network_allowed=True,
        state_change_allowed=True,
        human_approval=True,
        budget=Budget(max_requests=max_requests, max_cost_usd=1.0),
    )


def test_asset_to_desync_plan_to_policy_to_executor_to_evidence():
    executor = RecordingDesyncExecutor()
    report = run_active_plan(
        [_desync_route()],
        _approved_envelope(),
        executors={"http_desync": executor},
        enabled={"http_desync"},
    )

    assert report.plan.has("http_desync")
    assert len(executor.calls) == 1
    run = report.runs[0]
    assert run.decision.approved is True
    assert run.executed is True
    assert run.result.status == "observed"
    assert run.result.evidence[0].kind == "http_desync_differential"
    assert report.summary()["evidence"] == 1
    assert report.summary()["requests_used"] == 2


def test_active_runtime_is_fail_closed_without_executor():
    report = run_active_plan(
        [_desync_route()],
        _approved_envelope(),
        executors={},
        enabled={"http_desync"},
    )
    run = report.runs[0]
    assert run.decision.approved is True
    assert run.executed is False
    assert run.runtime_reason == "executor_missing"
    assert report.summary()["executor_missing"] == 1


def test_active_runtime_never_dispatches_policy_blocked_desync():
    executor = RecordingDesyncExecutor()
    report = run_active_plan(
        [_desync_route()],
        AuthorizationEnvelope(scope_digest="scope", budget=Budget(max_requests=10)),
        executors={"http_desync": executor},
        enabled={"http_desync"},
    )
    assert executor.calls == []
    assert report.runs[0].decision.approved is False
    assert report.runs[0].executed is False


def test_cumulative_budget_is_enforced_across_active_tasks():
    # One http_desync task estimates >=2 requests. With only one request available it is blocked
    # before an executor can run, even though an executor is registered.
    executor = RecordingDesyncExecutor()
    report = run_active_plan(
        [_desync_route()],
        _approved_envelope(max_requests=1),
        executors={"http_desync": executor},
        enabled={"http_desync"},
    )
    assert executor.calls == []
    assert report.runs[0].decision.approved is False
    assert "request budget" in report.runs[0].decision.reason
