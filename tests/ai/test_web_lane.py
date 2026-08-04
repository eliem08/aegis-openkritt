"""End-to-end web-lane runner: authorization gate + staged assembly."""

from __future__ import annotations

import pytest

from aegis.ai.web_lane import ScopeError, WebLaneRunner, WebScope


def test_refuses_unauthorized_scope():
    runner = WebLaneRunner({})
    with pytest.raises(ScopeError, match="authorized"):
        runner.run(WebScope(seed="example.com", authorized=False))


def test_refuses_empty_seed():
    with pytest.raises(ScopeError, match="no seed"):
        WebLaneRunner({}).run(WebScope(seed="", authorized=True))


def test_scope_permits_seed_and_subdomains_but_not_others():
    s = WebScope(seed="example.com", authorized=True)
    assert s.permits("example.com") and s.permits("api.example.com")
    assert not s.permits("evil.com") and not s.permits("notexample.com")


def test_scope_allowlist_confines_to_listed_hosts():
    s = WebScope(seed="example.com", hosts=frozenset({"api.example.com"}), authorized=True)
    assert s.permits("api.example.com")
    assert not s.permits("other.example.com")               # allowlist wins over subdomain rule


def test_runs_stages_in_order_and_collects():
    order = []
    def recon(scope, r): order.append("recon"); r.subdomains += ["api.example.com", "evil.com"]
    def probe(scope, r): order.append("probe"); r.live += [{"url": "https://api.example.com/"}]
    def detect(scope, r): order.append("detect"); r.findings += [
        {"url": "https://api.example.com/x", "title": "IDOR"},
        {"url": "https://evil.com/x", "title": "out of scope"}]
    runner = WebLaneRunner({"recon": recon, "probe": probe, "detect": detect})
    result = runner.run(WebScope(seed="example.com", authorized=True))
    assert order == ["recon", "probe", "detect"]            # canonical order
    assert result.stages_run == ["recon", "probe", "detect"]
    # out-of-scope host filtered from subdomains AND findings (defence in depth)
    assert result.subdomains == ["api.example.com"]
    assert [f["title"] for f in result.findings] == ["IDOR"]


def test_stage_error_is_isolated():
    def recon(scope, r): raise RuntimeError("subfinder missing")
    def probe(scope, r): r.live += [{"url": "https://example.com/"}]
    result = WebLaneRunner({"recon": recon, "probe": probe}).run(
        WebScope(seed="example.com", authorized=True))
    assert "recon" not in result.stages_run and "probe" in result.stages_run
    assert any("subfinder missing" in n for n in result.notes)


def test_events_emitted():
    events = []
    WebLaneRunner({"recon": lambda s, r: None},
                  on_event=lambda k, d: events.append(k)).run(
        WebScope(seed="example.com", authorized=True))
    assert "stage_start" in events and events[-1] == "completed"
