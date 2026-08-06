"""Program-scope intake: prompt priming + out-of-scope dependency filtering."""

from __future__ import annotations

from pathlib import Path

from aegis.ai.scope import (
    dependency_artifact,
    deps_declared_out,
    filter_out_of_scope,
    load_scope,
    scope_prompt,
)


def test_dependency_artifact_matches_lockfiles():
    for p in ("package-lock.json", "a/b/package-lock.json", "go.sum", "src/go.mod",
              "Cargo.lock", "yarn.lock", "composer.lock", "Gemfile.lock"):
        assert dependency_artifact(p), p
    for p in ("contracts/SSVOperators.sol", "core/Db.php", "src/index.js", "go.sumx"):
        assert not dependency_artifact(p), p


def test_dependency_artifact_handles_backslashes():
    assert dependency_artifact("reports\\clones\\x\\package-lock.json")


def test_filter_splits_kept_and_dropped():
    rows = [
        {"location": "contracts/modules/SSVOperators.sol:12"},
        {"location": "package-lock.json:0"},                       # the undici-style hit
        {"json_answer": {"file_path": "go.sum"}},                  # nested location
        {"file_path": "core/logic.php"},
    ]
    kept, dropped = filter_out_of_scope(rows)
    assert len(kept) == 2 and len(dropped) == 2
    locs = {r.get("location") or r.get("file_path") for r in kept}
    assert "package-lock.json:0" not in str(locs)


def test_scope_prompt_empty_when_no_scope():
    assert scope_prompt("") == ""


def test_scope_prompt_includes_text_and_guardrail():
    p = scope_prompt("In scope: contracts/**. Out: dependencies, tests.")
    assert "PROGRAM SCOPE" in p and "contracts/**" in p
    assert "only report" in p.lower()


def test_load_scope_reads_file(tmp_path: Path):
    f = tmp_path / "scope.md"
    f.write_text("In scope: contracts/core/*.sol", encoding="utf-8")
    assert "contracts/core" in load_scope(str(f))


def test_load_scope_passes_inline_text():
    assert load_scope("In scope: everything") == "In scope: everything"


def test_load_scope_bounds_length():
    assert len(load_scope("x" * 20000)) == 8000


def test_deps_declared_out_detects_phrase():
    assert deps_declared_out("Third-party dependencies are out of scope.")
    assert deps_declared_out("Issues in libraries are excluded")
    assert not deps_declared_out("Reentrancy in the vault is in scope")
