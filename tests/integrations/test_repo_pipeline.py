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


def test_discover_fills_required_extra_keys_and_prefers_default_workflow():
    from aegis.integrations.repo_pipeline import RepoTarget, build_scan_payload, resolve_extra

    class WithWorkflows(FakeOK):
        def list_workflows(self):
            return [{"id": "1"}, {"id": "2", "isDefault": True}]      # default is #2
        def get_workflow(self, wid):
            return {"id": wid, "steps": [{"content": "analyze {{extra.bug_bounty_url}} for {{repo_full}}"}]}
        def list_post_scripts(self):
            return [{"id": "9", "content": "report to {{extra.bug_bounty_url}}"}]

    t = discover_scan_template(WithWorkflows(), model="claude-opus-5")
    assert t.workflow_id == "2"                                        # default preferred over first
    assert t.required_extra_keys == ("bug_bounty_url",)
    extra = resolve_extra(t.required_extra_keys, handle="cloudflare",
                          repo=RepoTarget(repo_full="cloudflare/workerd", identifier="…"))
    assert extra["bug_bounty_url"] == "https://hackerone.com/cloudflare"
    payload = build_scan_payload(RepoTarget(repo_full="cloudflare/workerd", identifier="…"), t,
                                 model="claude-opus-5", extra=extra)
    assert payload["extra"]["bug_bounty_url"] == "https://hackerone.com/cloudflare"


def test_launch_fills_extra_so_the_payload_validates():
    from aegis.integrations.repo_pipeline import RepoTarget
    seen = {}

    class Capture(FakeOK):
        def create_scan(self, payload):
            seen.update(payload)
            return {"id": "77"}

    t = ScanTemplate(workflow_id="1", post_script_id="2", severity_ranker="# r",
                     model="claude-opus-5", required_extra_keys=("bug_bounty_url",))
    launch_repo_scans(Capture(), [RepoTarget(repo_full="acme/api", identifier="…")], t, handle="acme")
    assert seen["extra"] == {"bug_bounty_url": "https://hackerone.com/acme"}


def test_launch_error_surfaces_the_http_body():
    import httpx
    from aegis.integrations.repo_pipeline import RepoTarget

    class Rejecting(FakeOK):
        def create_scan(self, payload):
            req = httpx.Request("POST", "http://x/api/scans")
            resp = httpx.Response(422, json={"error": "Validation failed."}, request=req)
            raise httpx.HTTPStatusError("422", request=req, response=resp)

    t = ScanTemplate(workflow_id="1", post_script_id="2", severity_ranker="# r", model="m")
    [launch] = launch_repo_scans(Rejecting(), [RepoTarget(repo_full="a/b", identifier="…")], t)
    assert not launch.ok and "422" in launch.error and "Validation failed" in launch.error


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


# --- DeepSeek via OpenRouter fallback ---------------------------------------

def test_with_deepseek_fallback_appends_openrouter_model():
    from aegis.integrations.repo_pipeline import DEEPSEEK_MODEL, with_deepseek_fallback

    base = ScanTemplate(workflow_id="1", post_script_id="2", severity_ranker="# r",
                        model="claude-opus-5", fallback_models=("claude-sonnet-5",))
    t = with_deepseek_fallback(base)
    assert t.models == ["claude-opus-5", "claude-sonnet-5", DEEPSEEK_MODEL]
    assert t.model_providers[DEEPSEEK_MODEL] == "openrouter"
    # original template untouched
    assert DEEPSEEK_MODEL not in base.fallback_models


def test_deepseek_fallback_payload_uses_openrouter_provider():
    from aegis.integrations.repo_pipeline import DEEPSEEK_MODEL, RepoTarget, with_deepseek_fallback

    base = ScanTemplate(workflow_id="1", post_script_id="2", severity_ranker="# r",
                        model="claude-opus-5", model_provider="claude")
    t = with_deepseek_fallback(base)
    payload = build_scan_payload(RepoTarget(repo_full="a/b", identifier="a/b"), t, model=DEEPSEEK_MODEL)
    assert payload["model"] == DEEPSEEK_MODEL and payload["model_provider"] == "openrouter"
    # the primary model still gets the original provider
    primary_payload = build_scan_payload(RepoTarget(repo_full="a/b", identifier="a/b"), t, model="claude-opus-5")
    assert primary_payload["model_provider"] == "claude"


def test_launch_falls_back_to_deepseek_when_claude_models_fail():
    from aegis.integrations.repo_pipeline import DEEPSEEK_MODEL, RepoTarget, with_deepseek_fallback

    class Flaky(FakeOK):
        def create_scan(self, payload):
            if payload["model"] != DEEPSEEK_MODEL:
                raise RuntimeError("no capacity")
            return {"id": "55"}

    t = with_deepseek_fallback(ScanTemplate(workflow_id="1", post_script_id="2", severity_ranker="# r",
                                            model="claude-opus-5", fallback_models=("claude-sonnet-5",)))
    [launch] = launch_repo_scans(Flaky(), [RepoTarget(repo_full="a/b", identifier="a/b")], t)
    assert launch.ok and launch.model == DEEPSEEK_MODEL
