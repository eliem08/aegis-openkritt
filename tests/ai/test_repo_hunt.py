"""Autonomous repository hunting: deterministic selection + bounded analysis."""

from __future__ import annotations

from aegis.ai.agents.contracts import AgentKind
from aegis.ai.repo_hunt import RepoHuntConfig, hunt_repository, score_path, select_files


# --- deterministic file selection -------------------------------------------

def test_skips_non_production_code():
    for path in [
        "pkg/auth/token_test.go", "test/auth/login.go", "examples/auth/demo.go",
        "vendor/x/auth.go", "third_party/auth/session.go", "pkg/auth/mocks/token.go",
        "pkg/api/types_generated.go", "docs/auth.md",
    ]:
        assert score_path(path) is None, path


def test_skips_files_without_a_security_signal():
    assert score_path("pkg/util/strings.go") is None
    assert score_path("cmd/main.go") is None


def test_scores_auth_highest_and_maps_agent_kinds():
    auth = score_path("pkg/auth/session.go")
    rbac = score_path("pkg/rbac/authorizer.go")
    crypto = score_path("pkg/crypto/signature.go")
    assert auth and rbac and crypto
    assert auth[0] > rbac[0] > crypto[0]              # auth 10 > authz 9 > crypto 8
    assert auth[1] is AgentKind.AUTHENTICATION
    assert rbac[1] is AgentKind.AUTHORIZATION
    assert crypto[1] is AgentKind.SECRETS_CRYPTO


def test_solidity_is_always_contract_reviewed():
    result = score_path("contracts/token/Vault.sol")
    assert result and result[1] is AgentKind.SMART_CONTRACT


def test_selection_is_bounded_and_deterministic():
    paths = [f"pkg/auth/file{i}.go" for i in range(50)] + ["pkg/util/x.go"]
    first = select_files(paths, RepoHuntConfig(max_files=5))
    second = select_files(paths, RepoHuntConfig(max_files=5))
    assert len(first) == 5
    assert [f.path for f in first] == [f.path for f in second]     # reproducible
    assert all("util" not in f.path for f in first)                # unscored excluded


def test_subpath_restricts_selection():
    paths = ["pkg/auth/a.go", "cmd/auth/b.go"]
    selected = select_files(paths, RepoHuntConfig(subpath="pkg/"))
    assert [f.path for f in selected] == ["pkg/auth/a.go"]


# --- bounded analysis over a fake fetcher/client -----------------------------

class FakeFetcher:
    def __init__(self, files):
        self._files = files
        self.reads = []

    def list_paths(self, repository):
        return list(self._files), "abc123def456"

    def read(self, repository, path):
        self.reads.append(path)
        return self._files[path]


class FakeClient:
    """Returns one valid hypothesis per call, in the runner's expected schema."""
    def __init__(self):
        self.calls = 0

    def complete_json(self, messages, **kwargs):
        self.calls += 1
        import json as _json
        task = _json.loads(messages[1]["content"].split("\n", 1)[1])
        path = task["source_slices"][0]["path"]
        return {"hypotheses": [{
            "weakness": "CWE-287", "title": "missing check", "file_path": path,
            "line": 10, "rationale": "no guard on the request path",
            "confidence": 0.6,
            "entry_point": "POST /api/v1/session with an attacker-supplied token",
            "attacker": "unauthenticated remote user",
            "impact": "authentication is bypassed for any account",
            "severity": "high",
            "verification": {"method": "static_analysis",
                             "expected_observation": "review the cited lines",
                             "maximum_requests": 0},
        }]}


def test_hunt_analyzes_only_selected_files_and_shapes_a_report(tmp_path):
    files = {
        "pkg/auth/session.go": "package auth\n",
        "pkg/rbac/authorizer.go": "package rbac\n",
        "pkg/util/strings.go": "package util\n",      # no signal -> never analyzed
        "pkg/auth/session_test.go": "package auth\n",  # test -> never analyzed
    }
    fetcher, client = FakeFetcher(files), FakeClient()
    result = hunt_repository(fetcher, client, "acme/repo",
                             config=RepoHuntConfig(max_files=10), pin_dir=tmp_path)

    analyzed = {f.path for f in result.selected}
    assert analyzed == {"pkg/auth/session.go", "pkg/rbac/authorizer.go"}
    assert client.calls == 2
    assert len(result.hypotheses) == 2

    report = result.report()
    assert report["scan"]["repository"] == "acme/repo"
    assert report["scan"]["commit"] == "abc123def456"
    row = report["vulnerabilities"][0]
    assert row["json_answer"]["vulnerability_type"] == "CWE-287"
    assert row["source"] == "aegis:deepseek-platform"
    # reviewed sources are pinned for later citation validation
    assert (tmp_path / "pkg/auth/session.go").is_file()


def test_hunt_records_failures_without_aborting(tmp_path):
    class Flaky(FakeFetcher):
        def read(self, repository, path):
            if "rbac" in path:
                raise RuntimeError("boom")
            return super().read(repository, path)

    files = {"pkg/auth/session.go": "package auth\n", "pkg/rbac/authorizer.go": "x"}
    result = hunt_repository(Flaky(files), FakeClient(), "acme/repo",
                             config=RepoHuntConfig(max_files=10), pin_dir=tmp_path)
    assert len(result.hypotheses) == 1                     # the healthy file still ran
    assert any("rbac" in failure for failure in result.failures)


# --- reachability bar + cross-file context ----------------------------------

def _hyp(path, **over):
    base = {
        "weakness": "CWE-287", "title": "t", "file_path": path, "line": 10,
        "rationale": "r", "confidence": 0.6,
        "entry_point": "POST /login", "attacker": "anonymous", "impact": "auth bypass",
        "severity": "high",
        "verification": {"method": "static_analysis", "expected_observation": "o",
                         "maximum_requests": 0},
    }
    base.update(over)
    return base


class ScriptedClient:
    """Returns whatever hypotheses the test scripts, per call."""
    def __init__(self, batches):
        self._batches = list(batches)
        self.tasks = []

    def complete_json(self, messages, **kwargs):
        import json as _json
        self.tasks.append(_json.loads(messages[1]["content"].split("\n", 1)[1]))
        return {"hypotheses": self._batches.pop(0) if self._batches else []}


def test_hypothesis_without_entry_point_or_impact_is_dropped(tmp_path):
    files = {"pkg/auth/session.go": "package auth\n"}
    client = ScriptedClient([[
        _hyp("pkg/auth/session.go"),                                    # complete -> kept
        _hyp("pkg/auth/session.go", line=20, entry_point="", impact=""),  # hardening -> dropped
        _hyp("pkg/auth/session.go", line=30, impact=""),                 # no impact -> dropped
    ]])
    result = hunt_repository(FakeFetcher(files), client, "acme/repo",
                             config=RepoHuntConfig(max_files=5), pin_dir=tmp_path)
    assert len(result.hypotheses) == 1
    assert result.hypotheses[0]["json_answer"]["line"] == 10


def test_reachability_bar_can_be_disabled(tmp_path):
    files = {"pkg/auth/session.go": "package auth\n"}
    client = ScriptedClient([[_hyp("pkg/auth/session.go", entry_point="", impact="")]])
    result = hunt_repository(
        FakeFetcher(files), client, "acme/repo",
        config=RepoHuntConfig(max_files=5, require_reachability=False), pin_dir=tmp_path)
    assert len(result.hypotheses) == 1


def test_model_severity_and_attacker_reach_the_report(tmp_path):
    files = {"pkg/auth/session.go": "package auth\n"}
    client = ScriptedClient([[_hyp("pkg/auth/session.go", severity="critical",
                                   attacker="unauthenticated remote user")]])
    result = hunt_repository(FakeFetcher(files), client, "acme/repo",
                             config=RepoHuntConfig(max_files=5), pin_dir=tmp_path)
    row = result.hypotheses[0]
    assert row["severity"] == "critical"                     # not hardcoded medium
    assert row["json_answer"]["malicious_actor"] == "unauthenticated remote user"
    assert row["json_answer"]["impact"] == "auth bypass"


def test_bundle_supplies_neighbour_files_as_context(tmp_path):
    files = {
        "pkg/auth/session.go": "package auth\n",
        "pkg/auth/token.go": "package auth\n",
        "pkg/auth/handler.go": "package auth\n",
    }
    client = ScriptedClient([[_hyp("pkg/auth/session.go")]])
    result = hunt_repository(FakeFetcher(files), client, "acme/repo",
                             config=RepoHuntConfig(max_files=1, context_files=2), pin_dir=tmp_path)
    primary = result.selected[0].path
    paths = [s["path"] for s in client.tasks[0]["source_slices"]]
    assert paths[0] == primary                                # primary first
    assert len(paths) == 3                                    # + 2 context neighbours
    assert set(paths) == set(files)                           # neighbours came from the package


def test_findings_in_context_files_are_not_reported(tmp_path):
    # a neighbour is read-only evidence; a hypothesis about it belongs to that file's own turn
    files = {"pkg/auth/session.go": "package auth\n", "pkg/auth/token.go": "package auth\n"}
    client = ScriptedClient([[_hyp("pkg/auth/token.go")]])   # claims the CONTEXT file
    result = hunt_repository(FakeFetcher(files), client, "acme/repo",
                             config=RepoHuntConfig(max_files=1, context_files=1), pin_dir=tmp_path)
    assert result.hypotheses == []


def test_duplicate_hypotheses_are_collapsed(tmp_path):
    files = {"pkg/auth/session.go": "package auth\n", "pkg/auth/token.go": "package auth\n"}
    # both files report the same weakness at the same line of their own primary
    client = ScriptedClient([
        [_hyp("pkg/auth/session.go", line=10)],
        [_hyp("pkg/auth/token.go", line=10)],
    ])
    result = hunt_repository(FakeFetcher(files), client, "acme/repo",
                             config=RepoHuntConfig(max_files=2, context_files=0), pin_dir=tmp_path)
    assert len(result.hypotheses) == 2       # different files -> both kept

    client2 = ScriptedClient([[_hyp("pkg/auth/session.go"), _hyp("pkg/auth/session.go")]])
    result2 = hunt_repository(FakeFetcher({"pkg/auth/session.go": "x\n"}), client2, "acme/repo",
                              config=RepoHuntConfig(max_files=1), pin_dir=tmp_path)
    assert len(result2.hypotheses) == 1      # same file+line+weakness -> collapsed
