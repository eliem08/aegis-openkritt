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
    orch = _orch(h1, ok, dry_run=False)
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
    report = _orch(h1, ok, dry_run=False, max_programs=2, max_repos_per_program=2).cycle()
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
