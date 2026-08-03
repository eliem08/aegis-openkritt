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
