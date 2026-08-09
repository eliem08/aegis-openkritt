from datetime import UTC, datetime, timedelta

import pytest

from aegis.ai.agentic_os import (
    AuthorizationEnvelope,
    Budget,
    SecurityKnowledgeGraph,
    mint_execution_grant,
    process_grant_verifier,
)
from aegis.ai.jarvis.asset_execution_ticket import CapabilityAvailability
from aegis.ai.jarvis.hunter_acquisition import HunterArtifactAcquirer
from aegis.ai.jarvis.hunter_dispatcher import HunterCapabilityDispatcher
from aegis.ai.jarvis.hunter_phase_a import HunterIntelligencePhaseA
from aegis.ai.jarvis.mission_capabilities import CapabilityDisposition
from aegis.ai.jarvis.mission_scheduler import MissionScheduler, MissionTask
from aegis.ai.jarvis.recon_intelligence import CertificateRecord
from aegis.ai.jarvis.state_store import JarvisStateStore
from aegis.ai.jarvis.universal_runtime import UniversalMissionRuntime
from aegis.ingest.program import AssetType, ProgramRules, ScopeAsset

NOW = datetime(2026, 8, 9, 12, tzinfo=UTC)


class Fetcher:
    def __init__(self, rows):
        self.rows = rows
        self.calls = []

    def get(self, url):
        self.calls.append(url)
        return self.rows[url]


class CT:
    def __init__(self, records):
        self.records = records
        self.calls = []

    def query(self, domain):
        self.calls.append(domain)
        return self.records


def _authorization(*, network=True):
    verifier = process_grant_verifier()
    budget = Budget(max_cost_usd=2, max_requests=20, max_human_minutes=2)
    grant = mint_execution_grant(
        type("AllowedPolicyDecision", (), {"allowed": True})(),
        scope_digest="scope:phase-a", budget=budget, verifier=verifier, network=network,
    )
    return verifier, AuthorizationEnvelope(
        scope_digest="scope:phase-a", budget=budget, grant=grant
    )


def _program():
    return ProgramRules(handle="phase-a-live", in_scope=(ScopeAsset(
        identifier="https://*.example.test", asset_type=AssetType.WILDCARD,
    ),))


def _certificate():
    return CertificateRecord(
        "fingerprint", ("app.example.test", "new.example.test"), "issuer", "subject",
        "serial", NOW, NOW + timedelta(days=90), NOW,
    )


def test_automatic_html_script_source_map_and_ct_acquisition_feed_phase_a():
    fetcher = Fetcher({
        "https://app.example.test/": (
            200, {"content-type": "text/html"},
            b'<html><script src="/static/app.js"></script></html>',
        ),
        "https://app.example.test/static/app.js": (
            200, {"content-type": "application/javascript"},
            b"const api='/api/import';//# sourceMappingURL=app.js.map",
        ),
        "https://app.example.test/static/app.js.map": (
            200, {"content-type": "application/json"},
            b'{"version":3,"sources":["src/app.ts"],"sourcesContent":["const x=1"]}',
        ),
    })
    ct = CT((_certificate(),))
    verifier, authorization = _authorization()
    acquirer = HunterArtifactAcquirer(
        fetcher=fetcher, ct_provider=ct, grant_verifier=verifier
    )
    acquired, phase = HunterIntelligencePhaseA().run_with_acquisition(
        acquirer=acquirer, authorization=authorization,
        page_urls=("https://app.example.test/",), ct_domains=("example.test",),
        program=_program(), scope_digest="scope:phase-a",
        authorization_id="auth:phase-a", graph=SecurityKnowledgeGraph(),
        capacity=20, exploration_fraction=1.0,
    )
    assert "https://app.example.test/static/app.js" in acquired.bundles
    assert "https://app.example.test/static/app.js.map" in acquired.source_maps
    assert acquired.certificates == (_certificate(),)
    assert {row.status for row in acquired.statuses} == {"READY"}
    assert phase.javascript and phase.certificate_signals


def test_acquisition_fails_closed_without_grant_or_on_out_of_scope_script():
    verifier, _authorization_ok = _authorization()
    acquirer = HunterArtifactAcquirer(
        fetcher=Fetcher({
            "https://app.example.test/": (
                200, {}, b'<script src="https://evil.invalid/app.js"></script>'
            ),
        }), grant_verifier=verifier,
    )
    with pytest.raises(PermissionError, match="network grant"):
        acquirer.acquire(
            page_urls=("https://app.example.test/",), ct_domains=(),
            scope_hosts={"*.example.test"},
            authorization=AuthorizationEnvelope(scope_digest="scope:phase-a"),
        )
    _, authorization = _authorization()
    with pytest.raises(PermissionError, match="outside confirmed scope"):
        acquirer.acquire(
            page_urls=("https://app.example.test/",), ct_domains=(),
            scope_hosts={"*.example.test"}, authorization=authorization,
        )


def test_missing_acquisition_backends_are_explicitly_unavailable():
    verifier, authorization = _authorization()
    result = HunterArtifactAcquirer(grant_verifier=verifier).acquire(
        page_urls=(), ct_domains=(), scope_hosts={"*.example.test"},
        authorization=authorization,
    )
    assert {row.status for row in result.statuses} == {"UNAVAILABLE"}
    assert result.bundles == {} and result.certificates == ()


def test_internal_dispatcher_requires_exact_registered_networkless_capability():
    dispatcher = HunterCapabilityDispatcher()
    with pytest.raises(ValueError):
        dispatcher.register("jarvis:research:*", lambda *_: None)
    dispatcher.register("jarvis:research:test", lambda task, _plan, _auth: task.task_id)
    assert dispatcher.has("jarvis:research:test")
    with pytest.raises(PermissionError):
        dispatcher.dispatch(
            MissionTask("dynamic", "research", "x", risk="controlled_state_change",
                        executor_capability="jarvis:research:test"),
            None,  # type: ignore[arg-type]
            AuthorizationEnvelope(scope_digest="scope"),
        )


def test_universal_runtime_preserves_and_dispatches_internal_hunter_capability(tmp_path):
    phase = HunterIntelligencePhaseA().run(
        program=_program(), scope_digest="scope:phase-a", authorization_id="auth:phase-a",
        graph=SecurityKnowledgeGraph(),
        bundles={"https://app.example.test/app.js": "const api='/api/import';"},
        capacity=20, exploration_fraction=1.0,
    )
    opportunity = next(row for row in phase.opportunities
                       if row.metadata["worker_capability"].startswith("jarvis:"))
    calls = []
    verifier, authorization = _authorization(network=False)
    dispatcher = HunterCapabilityDispatcher({
        opportunity.metadata["worker_capability"]:
            lambda task, _plan, _auth: calls.append(task.task_id)
    })
    with JarvisStateStore(tmp_path / "jarvis.db") as store:
        runtime = UniversalMissionRuntime(
            MissionScheduler(store), grant_verifier=verifier,
            mission_task_executors=dispatcher.runtime_executors(),
        )
        mission = runtime.prepare(opportunity, availability=CapabilityAvailability())
        assert mission.tasks[0].executor_capability == opportunity.metadata["worker_capability"]
        result = runtime.execute_first(
            mission, authorization=authorization, availability=CapabilityAvailability()
        )
    assert result.disposition is CapabilityDisposition.READY
    assert calls == [mission.tasks[0].task_id]
