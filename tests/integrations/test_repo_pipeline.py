"""HackerOne program -> open·kritt scan -> console, for code-repo programs.

Scope extraction is gated by the program's automation/AI policy; scan launch uses
open·kritt's real create-scan contract; findings merge into one console model.
Both clients are fakes — no network.
"""

from __future__ import annotations

import pytest

from aegis.ingest.program import AssetType, ProgramRules, ScopeAsset
from aegis.integrations.repo_pipeline import (
    PipelineError,
    ScanTemplate,
    build_scan_payload,
    console_for_scans,
    discover_scan_template,
    launch_repo_scans,
    repos_in_scope,
    run_repo_pipeline,
)


def _rules(**kw):
    base = dict(handle="acme", name="Acme", in_scope=[
        ScopeAsset(identifier="https://github.com/acme/api", asset_type=AssetType.SOURCE_CODE,
                   raw_asset_type="SOURCE_CODE"),
        ScopeAsset(identifier="acme/web", asset_type=AssetType.SOURCE_CODE, raw_asset_type="SOURCE_CODE"),
        ScopeAsset(identifier="*.acme.com", asset_type=AssetType.WILDCARD, raw_asset_type="URL"),
    ])
    base.update(kw)
    return ProgramRules(**base)


class FakeOK:
    def __init__(self, findings=None, created_id="900"):
        self._findings = findings or {}
        self._id = created_id
        self.payloads = []

    def list_workflows(self): return [{"id": "1", "name": "wf"}]
    def list_post_scripts(self): return [{"id": "2", "name": "ps", "content": "..."}]
    def list_severity_rankers(self): return [{"id": "3", "name": "sr", "content": "# ranker rules"}]

    def create_scan(self, payload):
        self.payloads.append(payload)
        return {"id": self._id}

    def import_candidates(self, scan_id, **kw):
        return self._findings.get(str(scan_id), [])


class FakeH1:
    def __init__(self, scopes, policy=""):
        self._scopes = scopes
        self._policy = policy

    def get_program(self, handle):
        return {"data": {"attributes": {"handle": handle, "policy": self._policy}}}

    def get_structured_scopes(self, handle):
        return self._scopes


# --- scope -> repos ---------------------------------------------------------

def test_extracts_in_scope_repos_and_ignores_web():
    scope = repos_in_scope(_rules())
    fulls = [r.repo_full for r in scope.repos]
    assert fulls == ["acme/api", "acme/web"]           # github url + bare org/repo; wildcard ignored
    assert not scope.gated


def test_gated_when_automation_forbidden():
    scope = repos_in_scope(_rules(automation_allowed=False))
    assert scope.gated and "automated" in scope.reason and scope.repos == []


def test_gated_when_ai_forbidden():
    scope = repos_in_scope(_rules(ai_allowed=False))
    assert scope.gated and "AI" in scope.reason


def test_bounty_only_keeps_paying_repos():
    rules = ProgramRules(handle="acme", in_scope=[
        ScopeAsset(identifier="acme/paid", asset_type=AssetType.SOURCE_CODE,
                   raw_asset_type="SOURCE_CODE", eligible_for_bounty=True, max_severity="critical"),
        ScopeAsset(identifier="acme/vdp", asset_type=AssetType.SOURCE_CODE,
                   raw_asset_type="SOURCE_CODE", eligible_for_bounty=False)])
    both = repos_in_scope(rules)
    paid = repos_in_scope(rules, bounty_only=True)
    assert {r.repo_full for r in both.repos} == {"acme/paid", "acme/vdp"}
    assert [r.repo_full for r in paid.repos] == ["acme/paid"]
    assert paid.repos[0].max_severity == "critical" and paid.repos[0].eligible_for_bounty


def test_no_repos_reported_cleanly():
    web_only = ProgramRules(handle="x", in_scope=[
        ScopeAsset(identifier="app.x.com", asset_type=AssetType.URL, raw_asset_type="URL")])
    scope = repos_in_scope(web_only)
    assert not scope.gated and scope.repos == [] and "no in-scope" in scope.reason


# --- launch -----------------------------------------------------------------

def _template():
    return ScanTemplate(workflow_id="1", post_script_id="2", severity_ranker="# r", model="claude-x")


def test_scan_payload_matches_openkritt_contract():
    from aegis.integrations.repo_pipeline import RepoTarget
    p = build_scan_payload(RepoTarget(repo_full="acme/api", identifier="…"), _template())
    assert p["workflowId"] == "1" and p["postScriptId"] == "2"
    assert p["repo_kind"] == "remote" and p["repo_full"] == "acme/api"
    assert p["harness"] == "claude-code" and p["model"] == "claude-x"
    assert p["severity_ranker"] == "# r" and p["launchPolicy"] == "queue"


def test_launch_records_scan_ids_and_errors():
    ok = FakeOK(created_id="777")
    launches = launch_repo_scans(ok, repos_in_scope(_rules()).repos, _template())
    assert [l.scan_id for l in launches] == ["777", "777"]
    assert all(l.ok for l in launches) and len(ok.payloads) == 2


def test_discover_template_fills_from_backend():
    t = discover_scan_template(FakeOK(), model="claude-x")
    assert t.workflow_id == "1" and t.post_script_id == "2" and t.severity_ranker == "# ranker rules"


def test_launch_falls_back_when_primary_model_unavailable():
    from aegis.integrations.repo_pipeline import RepoTarget

    class Flaky(FakeOK):
        def create_scan(self, payload):
            if payload["model"] == "claude-opus-5":
                raise RuntimeError("model at capacity")     # primary unavailable
            return {"id": "42"}

    t = ScanTemplate(workflow_id="1", post_script_id="2", severity_ranker="# r",
                     model="claude-opus-5", fallback_models=("claude-opus-4-8", "claude-sonnet-5"))
    [launch] = launch_repo_scans(Flaky(), [RepoTarget(repo_full="a/b", identifier="…")], t)
    assert launch.ok and launch.scan_id == "42" and launch.model == "claude-opus-4-8"


def test_launch_reports_error_when_all_models_fail():
    from aegis.integrations.repo_pipeline import RepoTarget

    class Down(FakeOK):
        def create_scan(self, payload):
            raise RuntimeError("nope")

    t = ScanTemplate(workflow_id="1", post_script_id="2", severity_ranker="# r",
                     model="claude-opus-5", fallback_models=("claude-opus-4-8",))
    [launch] = launch_repo_scans(Down(), [RepoTarget(repo_full="a/b", identifier="…")], t)
    assert not launch.ok and "claude-opus-4-8" in launch.error       # last model tried is reported


def test_discover_auto_derives_fallbacks_from_catalog():
    class WithCatalog(FakeOK):
        def list_models(self, provider="claude"):
            return ["claude-opus-5", "claude-opus-4-8", "claude-sonnet-5"]

    t = discover_scan_template(WithCatalog(), model="claude-opus-5")
    assert t.fallback_models == ("claude-opus-4-8", "claude-sonnet-5")   # primary excluded
    assert t.models == ["claude-opus-5", "claude-opus-4-8", "claude-sonnet-5"]


def test_discover_template_raises_without_resources():
    class Empty(FakeOK):
        def list_workflows(self): return []
    with pytest.raises(PipelineError):
        discover_scan_template(Empty(), model="claude-x")


# --- collect ----------------------------------------------------------------

def test_console_merges_multiple_scans():
    from aegis.model import Candidate
    ok = FakeOK(findings={
        "900": [Candidate(asset="acme/api", worker="integration:openkritt", cwe="CWE-841")],
        "901": [Candidate(asset="acme/web", worker="integration:openkritt", cwe="CWE-284")]})
    model = console_for_scans(ok, ["900", "901"])
    assert model["totals"]["candidates"] == 2 and model["scan_ids"] == ["900", "901"]


# --- end to end -------------------------------------------------------------

def test_run_pipeline_launches_scans_for_repo_scope():
    scopes = [{"attributes": {"asset_type": "SOURCE_CODE",
                              "asset_identifier": "https://github.com/acme/api",
                              "eligible_for_submission": True}}]
    result = run_repo_pipeline(FakeH1(scopes), FakeOK(created_id="55"), "acme", model="claude-x")
    assert not result.gated
    assert [r.repo_full for r in result.repos] == ["acme/api"]
    assert result.scan_ids == ["55"]
