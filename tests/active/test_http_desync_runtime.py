from __future__ import annotations

from aegis.active.http_desync_runtime import (
    DesyncValidationResult,
    HttpDesyncExecutor,
)
from aegis.ai.active_runtime import run_active_plan
from aegis.ai.agentic_os import AuthorizationEnvelope, Budget
from aegis.graph import Asset, AssetKind


class Validator:
    def __init__(self):
        self.calls = []

    def validate(self, *, route: str, family: str, max_requests: int):
        self.calls.append((route, family, max_requests))
        return DesyncValidationResult(
            route=route,
            family=family,
            observed=True,
            reproducible=True,
            requests_used=2,
            summary="independent bounded differential repeated",
            observation_digest="obs-123",
        )


def test_desync_executor_is_reached_from_asset_graph_and_returns_canonical_evidence():
    asset = Asset(
        engagement_id="eng",
        asset_key="route:POST api.example/upload",
        kind=AssetKind.ROUTE,
        attributes={
            "method": "POST",
            "path": "/upload",
            "host": "api.example",
            "client_protocol": "h2",
            "upstream_protocol": "http/1.1",
            "intermediary_chain": ["edge", "origin-proxy"],
            "connection_reused": True,
            "response_desync_signal": True,
        },
    )
    validator = Validator()
    executor = HttpDesyncExecutor(validator)
    authorization = AuthorizationEnvelope(
        scope_digest="scope",
        network_allowed=True,
        state_change_allowed=True,
        human_approval=True,
        budget=Budget(max_requests=6, max_cost_usd=1.0),
    )

    report = run_active_plan(
        [asset],
        authorization,
        executors={"http_desync": executor},
        enabled={"http_desync"},
    )

    assert validator.calls
    run = report.runs[0]
    assert run.executed is True
    assert run.result.status == "reproduced"
    assert run.result.requests_used == 2
    assert run.result.evidence
    assert run.result.evidence[0].kind == "http_desync_reproduced"
