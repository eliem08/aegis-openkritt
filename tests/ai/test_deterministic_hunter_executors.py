from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from aegis.ai.agentic_os import (
    AuthorizationEnvelope,
    Budget,
    mint_execution_grant,
    process_grant_verifier,
)
from aegis.ai.jarvis.deterministic_hunter_executors import (
    DeterministicHunterExecutorProvider,
)
from aegis.ai.jarvis.javascript_intelligence import JSDiscoveryKind
from aegis.ai.jarvis.mission_scheduler import MissionPlan, MissionTask

SCOPE = "scope:internal"


def _authorization():
    verifier = process_grant_verifier()
    budget = Budget(max_cost_usd=1, max_requests=0, max_human_minutes=2)
    grant = mint_execution_grant(
        type("AllowedPolicyDecision", (), {"allowed": True})(),
        scope_digest=SCOPE, budget=budget, verifier=verifier,
        network=False, state_change=False, human_approval=True,
    )
    return verifier, AuthorizationEnvelope(scope_digest=SCOPE, budget=budget, grant=grant)


def _task(capability, payload):
    return MissionTask(
        "task:internal", "research", "deterministic analysis", risk="offline",
        executor_capability=capability,
        payload={"provenance_evidence": ["artifact-sha256:" + "a" * 64], **payload},
    )


def _run(capability, payload):
    verifier, authorization = _authorization()
    provider = DeterministicHunterExecutorProvider(grant_verifier=verifier)
    task = _task(capability, payload)
    result = provider.runtime_executors()[capability](
        task, MissionPlan("mission:internal", SCOPE, "analyze", (task,)), authorization,
    )
    return result, provider, task, authorization


def test_javascript_and_source_map_capabilities_dispatch_existing_agents():
    payload = {
        "bundles": {
            "https://app.example.test/app.js": (
                "const api='/api/v1/items';//# sourceMappingURL=app.js.map"
            ),
        },
        "source_maps": {
            "https://app.example.test/app.js.map": {
                "version": 3, "sources": ["src/admin.ts"],
                "sourcesContent": ["const hidden='/api/admin/import';"],
            },
        },
        "scope_hosts": ["app.example.test"],
    }
    routes, _, _, _ = _run(DeterministicHunterExecutorProvider.JS_ROUTE, payload)
    maps, _, _, _ = _run(DeterministicHunterExecutorProvider.SOURCE_MAP, payload)
    assert any(row.kind is JSDiscoveryKind.API_ENDPOINT for row in routes)
    assert any(row.kind is JSDiscoveryKind.SOURCE_MODULE for row in maps)
    assert all(row.evidence_digest for row in (*routes, *maps))


def test_public_identifier_and_certificate_dispatch_preserve_inferred_scope():
    public, _, _, _ = _run(DeterministicHunterExecutorProvider.PUBLIC_IDENTIFIERS, {
        "bundles": {
            "https://app.example.test/a.js": "gtag('config','G-SHARED123');",
            "https://outside.invalid/b.js": "gtag('config','G-SHARED123');",
        },
        "scope_hosts": ["app.example.test"],
    })
    assert len(public) == 1 and public[0].target_authorized is False

    now = datetime(2026, 8, 10, tzinfo=UTC)
    certs, _, _, _ = _run(DeterministicHunterExecutorProvider.CERTIFICATE_CLUSTER, {
        "certificates": [{
            "fingerprint": "f" * 64,
            "sans": ["app.example.test", "outside.invalid"],
            "issuer": "Example CA", "subject": "app.example.test", "serial": "1",
            "not_before": now.isoformat(), "not_after": (now + timedelta(days=90)).isoformat(),
            "observed_at": now.isoformat(),
        }],
        "scope_hosts": ["app.example.test"],
    })
    assert len(certs) == 1 and certs[0].target_authorized is False


def test_exploit_chain_dispatch_preserves_nullable_payout_and_prerequisites():
    chains, _, _, _ = _run(DeterministicHunterExecutorProvider.EXPLOIT_CHAIN, {
        "initial_capabilities": ["url_input"],
        "capabilities": [
            {
                "capability_id": "ssrf", "technique": "ssrf",
                "requires": ["url_input"], "produces": ["internal_read"],
                "confidence": 0.9, "evidence": ["evidence:ssrf"], "authorized": True,
            },
            {
                "capability_id": "credential", "technique": "credential",
                "requires": ["internal_read"], "produces": ["cloud_identity"],
                "confidence": 0.8, "evidence": ["evidence:credential"], "authorized": True,
            },
        ],
    })
    assert len(chains) == 1
    assert chains[0].expected_payout_usd is None and chains[0].expected_net_usd is None


def test_internal_dispatch_requires_provenance_and_exact_signed_grant():
    verifier, authorization = _authorization()
    provider = DeterministicHunterExecutorProvider(grant_verifier=verifier)
    task = MissionTask(
        "task:missing", "research", "analyze", risk="offline",
        executor_capability=provider.JS_ROUTE,
        payload={"bundles": {"https://app.example.test/a.js": "'/api/x'"}},
    )
    plan = MissionPlan("mission:missing", SCOPE, "analyze", (task,))
    with pytest.raises(RuntimeError, match="provenance evidence"):
        provider.runtime_executors()[provider.JS_ROUTE](task, plan, authorization)
    with pytest.raises(PermissionError, match="exact verified grant"):
        provider.runtime_executors()[provider.JS_ROUTE](
            task, plan, AuthorizationEnvelope(scope_digest=SCOPE, budget=authorization.budget),
        )
