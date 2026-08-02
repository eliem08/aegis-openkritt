"""Dalfox adapter (Phase 3) — guarded reflected/DOM XSS.

Blind/stored modes are refused without authorization + OAST; findings are
candidates; session loss stops a host instead of scanning its login page; and the
run reports a distinct clean/finding/cancelled/truncated/error/session-loss
outcome.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegis.adapters import (
    DalfoxAdapter,
    DalfoxConfig,
    DalfoxOutcome,
    DangerousModeNotAuthorized,
    EventKind,
    ExecutionEnvelope,
)
from aegis.process import ProcessOutcome, ProcessResult

FIXTURES = Path(__file__).parent / "fixtures"
STUB = "/opt/aegis/tools/dalfox"


def dalfox(**cfg):
    return DalfoxAdapter(STUB, allow_unpinned=True, config=DalfoxConfig(**cfg))


def envelope(adapter, target="app.example.test"):
    return ExecutionEnvelope.for_manifest(
        adapter.manifest, tenant_id="t", engagement_id="e", scan_id="s", stage_id="st",
        task_id="tk", target=target, scope_digest="d", idempotency_key="k",
    )


def run_fixture(adapter, name="dalfox-2.9.1.jsonl", target="app.example.test"):
    env = envelope(adapter, target)
    lines = (FIXTURES / name).read_text(encoding="utf-8").strip().splitlines()
    return [e for line in lines if (e := adapter.parse_line(line, env)) is not None]


def result(outcome=ProcessOutcome.SUCCEEDED, truncated=False):
    return ProcessResult(outcome=outcome, exit_code=0 if outcome == ProcessOutcome.SUCCEEDED else 1,
                         truncated=truncated)


def kinds(events, kind):
    return [e for e in events if e.kind == kind]


# --- mode gating -------------------------------------------------------------

def test_default_is_reflected_and_dom_only():
    assert dalfox().modes == ("reflected", "dom")


def test_blind_mode_requires_an_oast_endpoint():
    with pytest.raises(DangerousModeNotAuthorized):
        dalfox(blind=True)
    with pytest.raises(DangerousModeNotAuthorized):
        dalfox(stored=True)


def test_blind_mode_is_allowed_with_authorization_and_oast():
    a = dalfox(blind=True, oast_url="https://oast.aegis.internal/abc")
    assert "blind" in a.modes
    argv = a.build_command(envelope(a))
    assert "--blind" in argv and "https://oast.aegis.internal/abc" in argv


def test_command_keeps_raw_traffic_out_by_default():
    argv = dalfox().build_command(envelope(dalfox()))
    assert "--output-request" not in argv and "--output-response" not in argv
    assert "--only-poc" in argv
    # and bounds are applied
    assert "--worker" in argv and "--timeout" in argv


def test_rate_limit_becomes_a_delay():
    argv = dalfox(rate_limit=10).build_command(envelope(dalfox()))
    assert "--delay" in argv and argv[argv.index("--delay") + 1] == "100"


# --- finding parsing ---------------------------------------------------------

def test_reflected_and_verified_findings_are_candidates():
    a = dalfox()
    findings = kinds(run_fixture(a), EventKind.FINDING)
    by_param = {f.data["param"]: f for f in findings}
    assert set(by_param) == {"q", "name", "ref"}
    assert by_param["name"].data["subtype"] == "dom" and by_param["name"].data["severity"] == "high"
    assert by_param["q"].data["subtype"] == "reflected"
    # dalfox's own "V" is still only a candidate for us
    assert all(f.data["verified"] is False and f.confidence < 1.0 for f in findings)
    assert by_param["name"].confidence > by_param["q"].confidence   # V > R


def test_errors_become_diagnostics_not_findings():
    a = dalfox()
    diags = kinds(run_fixture(a), EventKind.DIAGNOSTIC)
    assert any(d.data["code"] == "target_error" for d in diags)


def test_raw_request_response_is_opt_in_and_redacted():
    a = dalfox(include_request_response=True)
    env = envelope(a)
    line = json.dumps({
        "type": "R", "param": "q", "data": "https://app.example.test/s?q=x",
        "payload": "<script>", "request": {"Cookie": "session=secret-value", "url": "/s"},
        "response": {"set-cookie": "session=secret-value", "status": 200},
    })
    finding = a.parse_line(line, env)
    assert finding.data["evidence_quarantined"] is True
    assert "secret-value" not in json.dumps(finding.data)   # redacted before leaving


# --- session loss ------------------------------------------------------------

def test_session_loss_stops_the_host_and_suppresses_its_findings():
    a = dalfox()
    env = envelope(a, "app.example.test")
    lines = [
        json.dumps({"type": "R", "param": "q", "data": "https://app.example.test/s?q=1",
                    "payload": "<x>"}),
        json.dumps({"type": "log", "message": "redirected to /login", "data": "https://app.example.test/x"}),
        json.dumps({"type": "R", "param": "u", "data": "https://app.example.test/login?u=1",
                    "payload": "<x>"}),   # should be suppressed
    ]
    events = [e for line in lines if (e := a.parse_line(line, env)) is not None]
    findings = kinds(events, EventKind.FINDING)
    assert [f.data["param"] for f in findings] == ["q"]          # only the pre-loss finding
    assert any(d.data["code"] == "session_lost" for d in kinds(events, EventKind.DIAGNOSTIC))
    assert a._suppressed == 1


def test_session_loss_without_findings_is_a_session_lost_outcome():
    a = dalfox()
    env = envelope(a)
    a.parse_line(json.dumps({"type": "log", "message": "please sign in",
                             "data": "https://app.example.test/login"}), env)
    terminal = a.interpret_result(result(), env)
    assert terminal.data["outcome"] == DalfoxOutcome.SESSION_LOST.value


# --- outcomes ----------------------------------------------------------------

def test_findings_outcome():
    a = dalfox()
    run_fixture(a)
    assert a.interpret_result(result(), envelope(a)).data["outcome"] == "finding"


def test_clean_outcome_when_nothing_found():
    a = dalfox()
    a.parse_line(json.dumps({"type": "log", "message": "done"}), envelope(a))
    assert a.interpret_result(result(), envelope(a)).data["outcome"] == "clean"


@pytest.mark.parametrize("oc,truncated,expected", [
    (ProcessOutcome.CANCELLED, False, "cancelled"),
    (ProcessOutcome.OUTPUT_LIMIT, False, "truncated"),
    (ProcessOutcome.TIMED_OUT, False, "truncated"),
    (ProcessOutcome.FAILED, False, "error"),
    (ProcessOutcome.SUCCEEDED, True, "truncated"),
])
def test_process_outcomes_map_to_distinct_states(oc, truncated, expected):
    a = dalfox()
    terminal = a.interpret_result(result(oc, truncated), envelope(a))
    assert terminal.data["outcome"] == expected


# --- resume ------------------------------------------------------------------

def test_resume_state_records_completed_targets():
    a = dalfox()
    run_fixture(a, target="app.example.test")
    state = a.resume_state()
    assert "app.example.test" in state["completed"] and state["findings"] == 3


def test_resume_from_prior_state_skips_completed_targets():
    a = DalfoxAdapter(STUB, allow_unpinned=True, resume_from={"completed": ["done.example.test"]})
    assert a.already_done("done.example.test")
    assert not a.already_done("new.example.test")


# --- SARIF -------------------------------------------------------------------

def test_sarif_output_is_parsed_into_findings():
    a = dalfox(output_format="sarif")
    sarif = json.dumps({
        "runs": [{
            "results": [
                {"ruleId": "reflected-xss", "level": "error",
                 "message": {"text": "reflected parameter q"},
                 "locations": [{"physicalLocation": {"artifactLocation": {
                     "uri": "https://app.example.test/s?q=1"}}}]},
            ]
        }]
    })
    events = a.parse_sarif(sarif, envelope(a))
    assert len(events) == 1 and events[0].kind == EventKind.FINDING
    assert events[0].data["severity"] == "high" and events[0].data["verified"] is False
    assert events[0].data["matched_at"].endswith("q=1")


# --- capability --------------------------------------------------------------

def test_capability_and_profile_are_active_testing():
    assert DalfoxAdapter.manifest.capability_tier == "xss_reflection"
    assert DalfoxAdapter.manifest.network_profile == "target-mutation"


def test_findings_are_not_assets():
    from aegis.graph import Normalizer
    from aegis.policy.scope import ScopeGuard

    a = dalfox()
    findings = kinds(run_fixture(a), EventKind.FINDING)
    res = Normalizer(scope=ScopeGuard(["app.example.test"]),
                     engagement_id="e", scan_id="s").normalize(findings)
    assert res.assets == {}
