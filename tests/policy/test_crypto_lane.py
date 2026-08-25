"""Tests for the crypto-lane orchestrator (pipeline mocked; no Slither/Mythril needed)."""

from __future__ import annotations

import pytest

from aegis.ai.jarvis.contract_static_pipeline import ContractStaticReport
from aegis.ai.jarvis.crypto_lane import (
    discover_solidity_sources,
    run_crypto_lane,
)


@pytest.fixture
def repo(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "Vault.sol").write_text("contract Vault {}")
    (tmp_path / "src" / "Token.sol").write_text("contract Token {}")
    (tmp_path / "node_modules" / "dep").mkdir(parents=True)
    (tmp_path / "node_modules" / "dep" / "Dep.sol").write_text("contract Dep {}")
    (tmp_path / "test").mkdir()
    (tmp_path / "test" / "Vault.t.sol").write_text("contract VaultTest {}")
    return tmp_path


def _mock_runner(candidates_per_file=1, raise_on=None):
    def runner(source, *, scope_digest, **kw):
        if raise_on and str(source).endswith(raise_on):
            raise RuntimeError("slither exploded")
        cands = [{
            "json_answer": {
                "vulnerability_type": "reentrancy", "file_path": str(source),
                "line": 10, "summary": "reentrancy in withdraw",
            }
        } for _ in range(candidates_per_file)]
        return ContractStaticReport(str(source), "sha256", scope_digest, candidates=cands)
    return runner


def test_discovery_skips_vendored_and_tests(repo):
    found = {p.name for p in discover_solidity_sources(repo)}
    assert found == {"Vault.sol", "Token.sol"}  # Dep.sol (node_modules) + Vault.t.sol excluded


def test_runs_pipeline_over_contract_sources(repo):
    r = run_crypto_lane(repo, scope_digest="sd", pipeline_runner=_mock_runner())
    assert r.pursued and r.lane == "source_crypto"
    assert r.sol_files_found == 2
    assert r.files_scanned == 2
    assert r.candidate_count == 2  # one unique candidate per file


def test_dedupes_identical_candidates(repo):
    # two identical candidates per file, same vuln/line/summary but distinct file_path -> 1 per file
    r = run_crypto_lane(repo, scope_digest="sd", pipeline_runner=_mock_runner(candidates_per_file=2))
    assert r.candidate_count == 2  # deduped within each file's two identical rows


def test_single_file_failure_does_not_abort_sweep(repo):
    r = run_crypto_lane(repo, scope_digest="sd", pipeline_runner=_mock_runner(raise_on="Token.sol"))
    assert r.files_scanned == 1
    assert any("Token.sol" in k for k in r.engine_errors)
    assert r.candidate_count == 1  # Vault.sol still scanned


def test_wrong_lane_is_skipped_not_scanned(repo):
    r = run_crypto_lane(repo, scope_digest="sd", vrt_category="Broken Access Control (BAC)",
                        pipeline_runner=_mock_runner())
    assert not r.pursued
    assert r.files_scanned == 0
    assert r.skipped_reason and "source_crypto" in r.skipped_reason
