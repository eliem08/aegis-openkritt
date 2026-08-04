"""Verified-contract source fetcher (no real explorer calls — transport is mocked)."""

from __future__ import annotations

import json

import httpx
import pytest

from aegis.ai.etherscan_source import EtherscanError, EtherscanSource, _parse_source


def _client(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


def _ok(source_code, name="Vault"):
    def handler(request):
        return httpx.Response(200, json={"status": "1", "message": "OK",
                                         "result": [{"SourceCode": source_code, "ContractName": name}]})
    return handler


# --- source parsing (the three Etherscan shapes) ----------------------------

def test_parse_single_flat_file():
    out = _parse_source("pragma solidity ^0.8.0; contract V {}", fallback_name="Vault")
    assert out == {"Vault.sol": "pragma solidity ^0.8.0; contract V {}"}


def test_parse_multifile_json():
    raw = json.dumps({"sources": {
        "contracts/Vault.sol": {"content": "contract Vault {}"},
        "contracts/lib/Math.sol": {"content": "library Math {}"},
    }})
    out = _parse_source(raw, fallback_name="Vault")
    assert out == {"contracts/Vault.sol": "contract Vault {}",
                   "contracts/lib/Math.sol": "library Math {}"}


def test_parse_double_brace_standard_json_input():
    inner = json.dumps({"sources": {"A.sol": {"content": "contract A {}"}}})
    raw = "{" + inner + "}"                                # the {{...}} wrapper
    out = _parse_source(raw, fallback_name="A")
    assert out == {"A.sol": "contract A {}"}


# --- fetcher over the mocked transport --------------------------------------

def test_list_and_read_verified_source():
    src = EtherscanSource(api_key="k", client=_client(_ok("contract V { uint x; }")))
    paths, commit = src.list_paths("0xabc")
    assert paths == ["Vault.sol"] and commit == ""
    assert "uint x" in src.read("0xabc", "Vault.sol")


def test_missing_api_key_is_actionable():
    src = EtherscanSource(api_key="", client=_client(_ok("x")))
    with pytest.raises(EtherscanError, match="ETHERSCAN_API_KEY"):
        src.list_paths("0xabc")


def test_unverified_contract_raises():
    def handler(request):
        return httpx.Response(200, json={"status": "1", "result": [{"SourceCode": "", "ContractName": ""}]})
    src = EtherscanSource(api_key="k", client=_client(handler))
    with pytest.raises(EtherscanError, match="not verified"):
        src.list_paths("0xabc")


def test_explorer_error_status_raises():
    def handler(request):
        return httpx.Response(200, json={"status": "0", "message": "NOTOK", "result": "rate limit"})
    src = EtherscanSource(api_key="k", client=_client(handler))
    with pytest.raises(EtherscanError, match="no verified source"):
        src.list_paths("0xabc")


def test_source_is_cached_one_call_per_address():
    calls = {"n": 0}
    def handler(request):
        calls["n"] += 1
        return httpx.Response(200, json={"status": "1", "result": [{"SourceCode": "contract V {}", "ContractName": "V"}]})
    src = EtherscanSource(api_key="k", client=_client(handler))
    src.list_paths("0xabc")
    src.read("0xabc", "V.sol")
    assert calls["n"] == 1                                 # cached after first fetch


def test_hunt_pipeline_accepts_the_fetcher_interface():
    # EtherscanSource must be drop-in for hunt_repository (list_paths/read + .sol -> SMART_CONTRACT)
    from aegis.ai.repo_hunt import select_files, RepoHuntConfig
    from aegis.ai.agents.contracts import AgentKind
    src = EtherscanSource(api_key="k", client=_client(_ok(json.dumps({"sources": {
        "Vault.sol": {"content": "contract Vault { function withdraw() external { msg.sender.call{value: 1}(''); } }"},
    }}))))
    paths, _ = src.list_paths("0xabc")
    selected = select_files(paths, RepoHuntConfig())     # default: .sol selectable as a contract
    assert selected and selected[0].kind is AgentKind.SMART_CONTRACT
