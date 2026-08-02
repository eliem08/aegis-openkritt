"""The five Phase 2 discovery adapters, against golden fixtures recorded for each
pinned tool version.

Each adapter is checked for the discipline its spec section demands: provenance,
caps, scope, wildcard suppression, zero target traffic, typed observations,
bounded crawl queues, and false-positive discipline on secret candidates.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegis.adapters import (
    PARSER_INCOMPATIBLE,
    PROVIDER_ERROR,
    QUOTA_EXHAUSTED,
    TARGET_UNREACHABLE,
    CustomMatcher,
    EventKind,
    ExecutionEnvelope,
    GauAdapter,
    GauConfig,
    HeadlessNotPermitted,
    HttpProbeAdapter,
    HttpProbeConfig,
    JsluiceAdapter,
    JsluiceConfig,
    KatanaAdapter,
    KatanaConfig,
    SubfinderAdapter,
    SubfinderConfig,
    ToolUnavailable,
    discovery_adapters,
)
from aegis.process import ProcessOutcome, ProcessResult

FIXTURES = Path(__file__).parent / "fixtures"
# Stand-in path: the real pinned binaries are a deployment concern, so command
# construction is asserted on argv rather than by executing anything.
STUB = "/opt/aegis/tools/stub"


def fixture(name: str) -> list[str]:
    return (FIXTURES / name).read_text(encoding="utf-8").strip().splitlines()


def envelope_for(adapter, target="example.test", **kw) -> ExecutionEnvelope:
    m = adapter.manifest
    return ExecutionEnvelope.for_manifest(
        m, tenant_id="t", engagement_id="e", scan_id="s", stage_id="st", task_id="tk",
        target=target, scope_digest="d", idempotency_key="k", **kw,
    )


def run(adapter, fixture_name, target="example.test"):
    """Parse a whole golden fixture, returning the typed events."""
    env = envelope_for(adapter, target)
    return [e for line in fixture(fixture_name) if (e := adapter.parse_line(line, env)) is not None]


def ok_result():
    return ProcessResult(outcome=ProcessOutcome.SUCCEEDED, exit_code=0)


def by_kind(events, kind):
    return [e for e in events if e.kind == kind]


# --- pinning discipline (all adapters) ---------------------------------------

def test_unpinned_binary_refuses_to_run():
    # No digest pinned yet -> the adapter will not build a command at all.
    with pytest.raises(ToolUnavailable, match="no pinned checksum"):
        SubfinderAdapter(executable="/usr/bin/subfinder").build_command(
            envelope_for(SubfinderAdapter(allow_unpinned=True)))


def test_pinned_binary_with_a_wrong_checksum_is_refused(tmp_path):
    import dataclasses

    from aegis.process import BinaryVerificationError

    binary = tmp_path / "subfinder"
    binary.write_bytes(b"not the pinned release")

    adapter = SubfinderAdapter(str(binary))
    adapter.manifest = dataclasses.replace(SubfinderAdapter.manifest, executable_digest="00" * 32)
    with pytest.raises(BinaryVerificationError):
        adapter.build_command(envelope_for(adapter))


def test_registry_exposes_all_five_discovery_adapters():
    registry = discovery_adapters(allow_unpinned=True)
    assert sorted(registry) == ["gau", "http-probe", "jsluice", "katana", "subfinder"]
    assert all(a.manifest.license == "MIT" for a in registry.values())


@pytest.mark.parametrize("factory", [
    SubfinderAdapter, GauAdapter, HttpProbeAdapter, KatanaAdapter, JsluiceAdapter])
def test_malformed_output_blocks_the_adapter_version(factory):
    adapter = factory(allow_unpinned=True)
    event = adapter.parse_line("{not json", envelope_for(adapter))
    assert event.kind == EventKind.DIAGNOSTIC
    assert event.data["code"] == PARSER_INCOMPATIBLE and event.data["blocking"] is True


# --- subfinder ---------------------------------------------------------------

def subfinder(**cfg):
    return SubfinderAdapter(STUB, allow_unpinned=True, config=SubfinderConfig(**cfg))


def test_subfinder_records_the_provider_on_every_result():
    events = by_kind(run(subfinder(), "subfinder-2.6.6.jsonl"), EventKind.ASSET)
    providers = {e.data["provider"] for e in events}
    assert providers == {"crtsh", "dnsdumpster"}  # virustotal's only hit was a dedup
    assert all(e.data["asset_type"] == "domain" for e in events)


def test_subfinder_rejects_out_of_parent_scope_and_wildcards():
    events = run(subfinder(), "subfinder-2.6.6.jsonl")
    codes = [e.data.get("code") for e in by_kind(events, EventKind.DIAGNOSTIC)]
    assert "out_of_parent_scope" in codes          # evil.other-domain.test
    assert codes.count("wildcard_suppressed") == 2  # literal *. and wildcard:true
    hosts = {e.data["identifier"] for e in by_kind(events, EventKind.ASSET)}
    assert "evil.other-domain.test" not in hosts and not any(h.startswith("*") for h in hosts)


def test_subfinder_deduplicates_case_and_trailing_dot():
    hosts = [e.data["identifier"] for e in by_kind(run(subfinder(), "subfinder-2.6.6.jsonl"), EventKind.ASSET)]
    assert hosts.count("api.example.test") == 1  # "API.Example.Test." folded in


def test_subfinder_provider_failure_is_a_diagnostic():
    diags = by_kind(run(subfinder(), "subfinder-2.6.6.jsonl"), EventKind.DIAGNOSTIC)
    failure = next(d for d in diags if d.data.get("code") == PROVIDER_ERROR)
    assert failure.data["provider"] == "shodan" and failure.data["blocking"] is False


def test_subfinder_enforces_global_and_per_provider_caps():
    capped = subfinder(max_results=1)
    codes = [e.data.get("code") for e in by_kind(run(capped, "subfinder-2.6.6.jsonl"), EventKind.DIAGNOSTIC)]
    assert QUOTA_EXHAUSTED in codes

    per_provider = subfinder(max_results_per_provider=1)
    assets = by_kind(run(per_provider, "subfinder-2.6.6.jsonl"), EventKind.ASSET)
    assert sum(1 for a in assets if a.data["provider"] == "crtsh") == 1


def test_subfinder_reports_partial_coverage_honestly():
    adapter = subfinder(min_provider_coverage=5)   # more providers than the fixture has
    run(adapter, "subfinder-2.6.6.jsonl")
    terminal = adapter.interpret_result(ok_result(), envelope_for(adapter))
    assert terminal.data["coverage"] == "partial" and terminal.data["status"] == "partial"
    assert terminal.data["providers_failed"] == ["shodan"]


# --- gau ---------------------------------------------------------------------

def gau(**cfg):
    return GauAdapter(STUB, allow_unpinned=True, config=GauConfig(**cfg))


def test_gau_never_requests_the_target():
    adapter = gau()
    assert adapter.manifest.network_profile == "passive-provider"
    argv = adapter.build_command(envelope_for(adapter, "example.test"))
    # Only the target *name* is passed as a query argument; no URL is fetched.
    assert argv[-1] == "example.test" and not any(a.startswith("http") for a in argv)


def test_gau_records_provider_and_original_timestamp():
    events = by_kind(run(gau(), "gau-2.2.4.jsonl"), EventKind.ASSET)
    first = events[0]
    assert first.data["provider"] == "wayback"
    assert first.data["original_observed_at"].startswith("2024-01-15T10:30:00")
    assert first.data["historical"] is True


def test_gau_keeps_parameter_names_in_the_url():
    urls = [e.data["identifier"] for e in by_kind(run(gau(), "gau-2.2.4.jsonl"), EventKind.ASSET)]
    assert any("id=" in u and "debug=" in u for u in urls)  # names survive to the normalizer


def test_gau_filters_static_extensions_and_statuses():
    events = by_kind(run(gau(), "gau-2.2.4.jsonl"), EventKind.ASSET)
    urls = [e.data["identifier"] for e in events]
    assert not any(u.endswith((".png", ".css")) for u in urls)

    only_200 = gau(include_status=(200,))
    urls = [e.data["identifier"] for e in by_kind(run(only_200, "gau-2.2.4.jsonl"), EventKind.ASSET)]
    assert not any("/admin" in u for u in urls)  # the 403 is filtered out


def test_gau_reports_providers_without_results():
    adapter = gau()
    run(adapter, "gau-2.2.4.jsonl")
    terminal = adapter.interpret_result(ok_result(), envelope_for(adapter))
    assert "urlscan" in terminal.data["providers_without_results"]
    assert terminal.data["coverage"] == "partial"


# --- http probe --------------------------------------------------------------

def probe(**cfg):
    return HttpProbeAdapter(STUB, allow_unpinned=True, config=HttpProbeConfig(**cfg))


def test_probe_emits_typed_service_observations():
    events = by_kind(run(probe(), "http-probe-1.6.9.jsonl"), EventKind.SERVICE)
    assert len(events) == 1
    d = events[0].data
    assert (d["status"], d["port"], d["scheme"]) == (200, 443, "https")
    assert d["ip"] == "93.184.216.34" and d["cname"] == "edge.example.test"
    assert d["cdn"] == "cloudflare" and d["asn"] == "AS15133"
    assert d["tls"]["tls_version"] == "tls13" and d["title"] == "API"
    assert d["technologies"] == ["nginx:1.25", "OpenAPI"]
    assert d["vhost"] is True and d["websocket"] is False


def test_probe_hashes_are_stable_and_typed():
    d = by_kind(run(probe(), "http-probe-1.6.9.jsonl"), EventKind.SERVICE)[0].data
    assert d["body_hash"] == "aaaa1111" and d["header_hash"] == "bbbb2222"


def test_probe_failure_carries_an_explicit_retry_reason():
    diag = by_kind(run(probe(retries=3), "http-probe-1.6.9.jsonl"), EventKind.DIAGNOSTIC)[0]
    assert diag.data["code"] == TARGET_UNREACHABLE
    assert diag.data["message"] == "connection refused" and diag.data["retries"] == 3


def test_probe_uses_safe_methods_only_and_never_service_mode():
    with pytest.raises(ValueError):
        probe(method="POST")
    argv = probe().build_command(envelope_for(probe()))
    # httpx's server/service mode must never be reachable through this adapter.
    assert not any(flag in argv for flag in ("-service", "-server", "-mhttp"))
    assert "-x" in argv and argv[argv.index("-x") + 1] == "GET"


# --- katana ------------------------------------------------------------------

def katana(**cfg):
    return KatanaAdapter(STUB, allow_unpinned=True, config=KatanaConfig(**cfg))


def test_katana_headless_is_refused_until_phase_4():
    with pytest.raises(HeadlessNotPermitted):
        katana(headless=True)
    assert "-headless=false" in katana().build_command(envelope_for(katana()))


def test_katana_records_parent_url_and_discovery_source():
    routes = by_kind(run(katana(), "katana-1.1.0.jsonl", "api.example.test"), EventKind.ROUTE)
    first = routes[0]
    assert first.data["parent_url"] == "https://api.example.test/"
    assert first.data["discovery_source"] == "a"
    assert first.data["parameters"] == [{"name": "id", "location": "query"}]


def test_katana_deduplicates_canonical_urls_and_identical_pages():
    routes = by_kind(run(katana(), "katana-1.1.0.jsonl", "api.example.test"), EventKind.ROUTE)
    paths = [r.data["path"] for r in routes]
    # /v1/users?id=1 and ?id=2 are one canonical route; /dup repeats body hash h1
    assert paths.count("/v1/users") == 1 and "/dup" not in paths


def test_katana_avoids_logout_and_out_of_scope_urls():
    events = run(katana(), "katana-1.1.0.jsonl", "api.example.test")
    codes = [e.data.get("code") for e in by_kind(events, EventKind.DIAGNOSTIC)]
    assert "logout_avoided" in codes and "out_of_scope_url" in codes
    paths = [r.data["path"] for r in by_kind(events, EventKind.ROUTE)]
    assert "/logout" not in paths


def test_katana_respects_page_and_form_budgets():
    routes = by_kind(run(katana(max_pages=1), "katana-1.1.0.jsonl", "api.example.test"), EventKind.ROUTE)
    assert len(routes) == 1

    no_forms = katana(max_forms=0)
    events = run(no_forms, "katana-1.1.0.jsonl", "api.example.test")
    assert not any(r.data.get("form") for r in by_kind(events, EventKind.ROUTE))


def test_katana_backs_off_an_unhealthy_host():
    adapter = katana(unhealthy_host_threshold=2)
    env = envelope_for(adapter, "api.example.test")
    line = json.dumps({"request": {"method": "GET", "endpoint": "https://api.example.test/x"},
                       "response": {"status_code": 503}})
    assert adapter.parse_line(line, env) is None            # first failure: counted
    event = adapter.parse_line(line, env)                    # second: backs off
    assert event.data["code"] == TARGET_UNREACHABLE and "api.example.test" in adapter._backed_off


# --- jsluice -----------------------------------------------------------------

def jsluice(**cfg):
    return JsluiceAdapter(STUB, allow_unpinned=True, config=JsluiceConfig(**cfg))


def test_jsluice_extracts_endpoints_with_source_location():
    routes = by_kind(run(jsluice(), "jsluice-urls-0.0.3.jsonl", "api.example.test"), EventKind.ROUTE)
    first = routes[0]
    assert first.data["path"] == "/api/v2/orders"
    assert first.data["source_file"] == "app.js" and first.data["source_line"] == 42
    assert {p["name"] for p in first.data["parameters"]} == {"page", "limit"}


def test_jsluice_marks_body_parameters_and_lowers_assembled_url_confidence():
    routes = by_kind(run(jsluice(), "jsluice-urls-0.0.3.jsonl", "api.example.test"), EventKind.ROUTE)
    checkout = next(r for r in routes if r.data["path"] == "/api/v2/checkout")
    assert {p["location"] for p in checkout.data["parameters"]} == {"body"}
    assembled = next(r for r in routes if r.data["discovery_source"] == "concatenation")
    assert assembled.confidence < 1.0   # built from variables, so a weaker signal


def test_jsluice_suppresses_generic_matchers_by_default():
    adapter = jsluice(mode="secrets")
    events = run(adapter, "jsluice-secrets-0.0.3.jsonl", "api.example.test")
    kinds = {e.data["kind_hint"] for e in by_kind(events, EventKind.SECRET_CANDIDATE)}
    assert "gcp-api-key" in kinds
    assert "generic-api-key" not in kinds and "high-entropy-string" not in kinds
    assert adapter._suppressed == 2


def test_jsluice_can_enable_generic_matchers_explicitly():
    adapter = jsluice(mode="secrets", enable_generic_matchers=True)
    events = by_kind(run(adapter, "jsluice-secrets-0.0.3.jsonl", "api.example.test"),
                     EventKind.SECRET_CANDIDATE)
    assert {"generic-api-key", "high-entropy-string"} <= {e.data["kind_hint"] for e in events}


def test_jsluice_honours_approved_custom_matchers():
    matcher = CustomMatcher(identifier="acme-internal-token", pattern="acme_live_[a-z]+", severity="critical")
    adapter = jsluice(mode="secrets", custom_matchers=(matcher,))
    events = by_kind(run(adapter, "jsluice-secrets-0.0.3.jsonl", "api.example.test"),
                     EventKind.SECRET_CANDIDATE)
    custom = next(e for e in events if e.data["kind_hint"] == "acme-internal-token")
    assert custom.data["severity"] == "critical" and custom.data["matcher"] == "custom"
    assert "--patterns" in adapter.build_command(envelope_for(adapter))


def test_jsluice_never_marks_a_candidate_verified():
    events = by_kind(run(jsluice(mode="secrets"), "jsluice-secrets-0.0.3.jsonl", "api.example.test"),
                     EventKind.SECRET_CANDIDATE)
    assert events and all(e.data["verified"] is False and e.confidence < 1.0 for e in events)


@pytest.mark.parametrize("bad", [{"mode": "everything"}])
def test_jsluice_rejects_an_unknown_mode(bad):
    with pytest.raises(ValueError):
        jsluice(**bad)


def test_custom_matcher_requires_identifier_and_valid_severity():
    with pytest.raises(ValueError):
        CustomMatcher(identifier="", pattern="x")
    with pytest.raises(ValueError):
        CustomMatcher(identifier="x", pattern="y", severity="apocalyptic")
