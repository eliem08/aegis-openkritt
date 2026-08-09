from datetime import UTC, datetime, timedelta

from aegis.ai.agentic_os import SecurityKnowledgeGraph
from aegis.ai.jarvis.hunter_phase_c import HunterIntelligencePhaseC
from aegis.ai.jarvis.mission_scheduler import TaskState
from aegis.ai.jarvis.url_consumer_intelligence import (
    CallbackObservation,
    ConsumerDelivery,
    ServerSideURLConsumerAgent,
    URLConsumerOutcome,
    URLConsumerProbe,
    surface_from_route,
)
from aegis.ingest.program import ProgramRules

NOW = datetime(2026, 8, 9, 12, tzinfo=UTC)
DOMAIN = "oast.aegis.internal"


def _surface(*, authorized=True, delivery=ConsumerDelivery.SYNCHRONOUS):
    return surface_from_route(
        route="/api/pdf/import", parameter="source_url", authorized=authorized,
        evidence=("openapi:/api/pdf/import:source_url",), delivery=delivery,
    )


def _probe(surface=None, *, callback_host="p1.oast.aegis.internal", delay=1,
           polling_complete=True, redirect=(), dns=()):
    surface = surface or _surface()
    callback = CallbackObservation(
        callback_host, "https", "203.0.113.8", NOW + timedelta(seconds=delay), "oast:i1"
    )
    return URLConsumerProbe(
        "probe-1", surface, "p1.oast.aegis.internal", DOMAIN, NOW,
        callbacks=(callback,), redirect_chain=redirect, dns_resolution_sequence=dns,
        polling_complete=polling_complete, evidence=("request:capture",),
    )


def test_exact_private_oast_match_confirms_synchronous_url_consumer():
    verdict = ServerSideURLConsumerAgent().analyze(_probe())
    assert verdict.outcome is URLConsumerOutcome.CALLBACK_CONFIRMED
    assert verdict.confidence == 0.98
    assert verdict.callback_delay_seconds == 1
    assert "oast:i1" in verdict.evidence


def test_async_delayed_callback_and_redirect_dns_behavior_are_classified():
    surface = _surface(delivery=ConsumerDelivery.ASYNCHRONOUS)
    verdict = ServerSideURLConsumerAgent().analyze(_probe(
        surface, delay=30,
        redirect=("https://redirect.test/start", "https://p1.oast.aegis.internal/end"),
        dns=(("203.0.113.1",), ("203.0.113.2",)),
    ))
    assert verdict.outcome is URLConsumerOutcome.DELAYED_CALLBACK_CONFIRMED
    assert verdict.redirect_behavior == "followed"
    assert verdict.dns_behavior == "changed_across_resolution"


def test_foreign_or_unmatched_callback_never_confirms():
    foreign = ServerSideURLConsumerAgent().analyze(_probe(callback_host="attacker.invalid"))
    assert foreign.outcome is URLConsumerOutcome.NO_CALLBACK_OBSERVED
    wrong_zone = URLConsumerProbe(
        "probe-public", _surface(), "p1.interact.sh", DOMAIN, NOW,
        callbacks=(CallbackObservation(
            "p1.interact.sh", "dns", "203.0.113.9", NOW, "foreign:i1"
        ),), polling_complete=True,
    )
    verdict = ServerSideURLConsumerAgent().analyze(wrong_zone)
    assert verdict.outcome is URLConsumerOutcome.INCONCLUSIVE
    assert "not under" in verdict.reason


def test_open_polling_window_and_unconfirmed_scope_fail_closed():
    open_probe = URLConsumerProbe(
        "open", _surface(), "p1.oast.aegis.internal", DOMAIN, NOW,
        polling_complete=False,
    )
    assert ServerSideURLConsumerAgent().analyze(open_probe).outcome is (
        URLConsumerOutcome.INCONCLUSIVE
    )
    inferred = URLConsumerProbe(
        "inferred", _surface(authorized=False), "p1.oast.aegis.internal", DOMAIN, NOW,
        callbacks=(CallbackObservation(
            "p1.oast.aegis.internal", "dns", "203.0.113.9", NOW, "oast:i2"
        ),), polling_complete=True,
    )
    assert ServerSideURLConsumerAgent().analyze(inferred).outcome is (
        URLConsumerOutcome.INCONCLUSIVE
    )


def test_phase_c_covers_discovered_surface_and_compiles_confirmed_callback():
    graph = SecurityKnowledgeGraph()
    result = HunterIntelligencePhaseC().run(
        program=ProgramRules(handle="ssrf-lab"), scope_digest="scope:ssrf",
        authorization_id="auth:ssrf", asset_locator="https://api.example.test",
        graph=graph, probes=(_probe(),), private_oast_available=True,
        capacity=10, exploration_fraction=1.0,
    )
    assert len(result.verdicts) == len(result.opportunities) == len(result.missions) == 1
    opportunity = result.opportunities[0]
    assert opportunity.estimated_payout_usd is None
    assert opportunity.prerequisite_state == "ready"
    assert opportunity.metadata["technique"] == "ssrf_url_consumer"
    mission = result.missions[0]
    assert mission.tasks[0].executor_capability == "dynamic:server-url-consumer"
    assert mission.tasks[0].expected_requests == 1
    assert mission.tasks[0].state is TaskState.PENDING
    assert graph.nodes[opportunity.opportunity_id]["kind"] == "hunt_opportunity"


def test_phase_c_missing_oast_and_inferred_surface_wait_without_fake_success():
    inferred = _surface(authorized=False)
    result = HunterIntelligencePhaseC().run(
        program=ProgramRules(handle="ssrf-lab"), scope_digest="scope:ssrf",
        authorization_id="auth:ssrf", asset_locator="https://inferred.invalid",
        graph=SecurityKnowledgeGraph(), surfaces=(inferred,), private_oast_available=False,
        capacity=10, exploration_fraction=1.0,
    )
    assert result.opportunities[0].prerequisite_state == "scope_confirmation_required"
    assert all(task.state is TaskState.WAITING_FOR_PREREQUISITE
               for task in result.missions[0].tasks)


def test_no_callback_is_negative_control_not_detection():
    surface = _surface()
    probe = URLConsumerProbe(
        "no-hit", surface, "p1.oast.aegis.internal", DOMAIN, NOW,
        polling_complete=True, evidence=("poll-window:complete",),
    )
    result = HunterIntelligencePhaseC().run(
        program=ProgramRules(handle="ssrf-lab"), scope_digest="scope:ssrf",
        authorization_id="auth:ssrf", asset_locator="https://api.example.test",
        graph=SecurityKnowledgeGraph(), probes=(probe,), private_oast_available=True,
    )
    assert result.verdicts[0].outcome is URLConsumerOutcome.NO_CALLBACK_OBSERVED
    assert result.opportunities == ()
