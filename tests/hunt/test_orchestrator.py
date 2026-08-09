"""The automatic hunter: discover -> (arm?) scan -> collect -> learn, on a loop.

Fakes for both clients — no network. The boundaries are asserted: dry-run launches
nothing, the scope gate is honored, and nothing ever submits.
"""

from __future__ import annotations

from aegis.hunt import HuntConfig, HuntOrchestrator
from aegis.learn import OutcomeStore, SubmissionLedger
from aegis.model import Candidate

REPO_SCOPE = [{"attributes": {"asset_type": "SOURCE_CODE",
                              "asset_identifier": "https://github.com/acme/api",
                              "eligible_for_submission": True,
                              "eligible_for_bounty": True, "max_severity": "high"}}]


class FakeH1:
    def __init__(self, programs, scopes_by_handle, policy_by_handle=None, reports=None):
        self._programs = programs
        self._scopes = scopes_by_handle
        self._policy = policy_by_handle or {}
        self._reports = reports or []
        self.submitted = False           # tripwire: nothing here may ever submit

    def list_programs(self):
        return self._programs

    def get_program(self, handle):
        return {"data": {"attributes": {"handle": handle, "policy": self._policy.get(handle, "")}}}

    def get_structured_scopes(self, handle):
        return self._scopes.get(handle, [])

    def list_my_reports(self):
        return self._reports

    def close(self):
        pass


class FakeOK:
    def __init__(self, findings=None):
        self._findings = findings or {}
        self.created = []

    def list_workflows(self): return [{"id": "1"}]
    def list_post_scripts(self): return [{"id": "2", "content": "c"}]
    def list_severity_rankers(self): return [{"id": "3", "content": "# r"}]

    def create_scan(self, payload):
        sid = str(900 + len(self.created))
        self.created.append(payload)
        return {"id": sid}

    def import_candidates(self, scan_id, **kw):
        return self._findings.get(str(scan_id), [])

    def close(self):
        pass


def _orch(h1, ok, **cfg):
    return HuntOrchestrator(h1, ok, OutcomeStore(), SubmissionLedger(),
                            config=HuntConfig(model="claude-x", **cfg))


# --- dry-run plans, launches nothing ----------------------------------------

def test_dry_run_plans_without_launching():
    h1 = FakeH1([{"attributes": {"handle": "acme"}}], {"acme": REPO_SCOPE})
    ok = FakeOK()
    report = _orch(h1, ok, dry_run=True).cycle()
    s = report.summary()
    assert s["dry_run"] is True and s["repos_in_scope"] == 1
    assert s["scans_launched_this_cycle"] == 0 and ok.created == []   # nothing launched


# --- armed launches and collects --------------------------------------------

def test_armed_launches_scans_and_collects_findings():
    h1 = FakeH1([{"attributes": {"handle": "acme"}}], {"acme": REPO_SCOPE})
    ok = FakeOK(findings={"900": [Candidate(asset="acme/api", worker="integration:openkritt",
                                            cwe="CWE-841")]})
    orch = _orch(h1, ok, dry_run=False, expected_bounties={"acme": 1000})
    report = orch.cycle()
    s = report.summary()
    assert s["scans_launched_this_cycle"] == 1 and len(ok.created) == 1
    assert s["findings"] == 1                                          # collected into the console
    assert report.console["items"][0]["cwe"] == "CWE-841"


# --- scope gate is honored --------------------------------------------------

def test_program_forbidding_automation_is_gated_out():
    # forcing an automation-forbidden program in (bypassing auto-select) still gates
    # it at the pipeline level -> nothing is launched.
    h1 = FakeH1([{"attributes": {"handle": "noauto"}}], {"noauto": REPO_SCOPE},
                policy_by_handle={"noauto": "Automated scanning and automated tools are prohibited."})
    ok = FakeOK()
    report = _orch(h1, ok, dry_run=False, only_handles=("noauto",)).cycle()
    assert "noauto" in report.summary()["programs_gated_out"]
    assert ok.created == []                                            # gated -> never launched


# --- caps -------------------------------------------------------------------

def test_caps_limit_programs_and_repos():
    programs = [{"attributes": {"handle": f"p{i}"}} for i in range(10)]
    scopes = {f"p{i}": [{"attributes": {"asset_type": "SOURCE_CODE",
                        "asset_identifier": f"https://github.com/p{i}/{j}", "eligible_for_submission": True,
                        "eligible_for_bounty": True, "max_severity": "high"}}
                        for j in range(10)] for i in range(10)}
    h1 = FakeH1(programs, scopes)
    ok = FakeOK()
    report = _orch(
        h1,
        ok,
        dry_run=False,
        max_programs=2,
        max_repos_per_program=2,
        expected_bounties={"p0": 1000, "p1": 1000},
    ).cycle()
    assert report.summary()["programs_considered"] == 2               # program cap
    assert len(ok.created) == 4                                        # 2 programs x 2 repos


# --- the loop + no-submit invariant -----------------------------------------

def test_run_yields_one_report_per_cycle():
    h1 = FakeH1([{"attributes": {"handle": "acme"}}], {"acme": REPO_SCOPE})
    reports = list(_orch(h1, FakeOK(), dry_run=True).run(cycles=3, sleep=lambda s: None))
    assert len(reports) == 3


def test_hunter_never_submits():
    h1 = FakeH1([{"attributes": {"handle": "acme"}}], {"acme": REPO_SCOPE},
                reports=[{"id": "1", "attributes": {"state": "resolved"}}])
    _orch(h1, FakeOK(), dry_run=False).cycle()
    assert h1.submitted is False        # the hunter only reads HackerOne, never submits


# --- two-stage (wide/narrow) ------------------------------------------------

def _hi_finding():
    from aegis.model import Candidate
    return Candidate(asset="acme/api", worker="integration:openkritt", cwe="CWE-89",
                     code_location="src/db.js:10", confidence=0.9, p_exploit=0.9,
                     business_impact=0.9)


class TwoStageOK(FakeOK):
    """Records create_scan payloads so we can see the verify (stage-2) launch."""
    def __init__(self, findings=None):
        super().__init__(findings=findings)
        self.payloads = []
        self._next = 900
    def list_workflows(self): return [{"id": "4"}]
    def create_scan(self, payload):
        self.payloads.append(payload)
        self._next += 1
        return {"id": str(self._next)}


def test_two_stage_promotes_high_priority_candidate_to_verify(monkeypatch):
    # stage-1 scan (id 901) returns a high-priority finding; verify must launch on Opus
    ok = TwoStageOK()
    orch = HuntOrchestrator(
        FakeH1([{"attributes": {"handle": "acme"}}], {"acme": REPO_SCOPE}),
        ok, OutcomeStore(), SubmissionLedger(),
        config=HuntConfig(model="claude-sonnet-5", dry_run=False,
                          verify_model="claude-opus-5", verify_threshold=0.1))
    # seed a completed stage-1 scan with a finding
    orch._tracked = {"901": {"repo_full": "acme/api", "handle": "acme", "stage": 1, "model": "claude-sonnet-5"}}
    ok._findings = {"901": [_hi_finding()]}
    n = orch._promote({"901": ok._findings["901"]}, orch._cfg)
    assert n == 1
    verify = [p for p in ok.payloads if p["model"] == "claude-opus-5"]
    assert verify and verify[0]["repo_scope"] == "src/db.js"        # scoped to the file
    assert verify[0]["thinkingEffort"] == "high"
    assert any(m.get("stage") == 2 for m in orch._tracked.values())  # verify tracked


def test_two_stage_skips_low_priority_and_is_idempotent():
    from aegis.model import Candidate
    ok = TwoStageOK()
    orch = HuntOrchestrator(
        FakeH1([{"attributes": {"handle": "acme"}}], {"acme": REPO_SCOPE}),
        ok, OutcomeStore(), SubmissionLedger(),
        config=HuntConfig(model="claude-sonnet-5", dry_run=False,
                          verify_model="claude-opus-5", verify_threshold=0.9))
    orch._tracked = {"901": {"repo_full": "acme/api", "handle": "acme", "stage": 1, "model": "s"}}
    low = Candidate(asset="a", worker="integration:openkritt", cwe="CWE-1",
                    confidence=0.1, p_exploit=0.1, business_impact=0.1)
    assert orch._promote({"901": [low]}, orch._cfg) == 0             # below threshold -> skip
    # high one promotes once, then never again (idempotent by fingerprint)
    orch._cfg.verify_threshold = 0.1
    hi = _hi_finding()
    assert orch._promote({"901": [hi]}, orch._cfg) == 1
    assert orch._promote({"901": [hi]}, orch._cfg) == 0
