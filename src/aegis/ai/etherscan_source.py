"""Verified smart-contract source as a hunt fetcher — the Smart Contract asset lane.

Many bounty programs list SMART_CONTRACT assets as on-chain addresses (Etherscan &
compatible explorers). When the contract is *verified*, its Solidity source is public,
so analyzing it is code review — no live chain interaction, no transactions, nothing
that touches funds. This fetcher pulls the verified source for an address and presents
it through the same ``list_paths``/``read`` interface as the repo sources, so the
existing hunt pipeline (with the SMART_CONTRACT agent kind for .sol) reviews it
unchanged.

Read-only: a single explorer API call for source text. It never sends a transaction,
never interacts with the chain, and never needs a wallet.
"""

from __future__ import annotations

import json
import os

import httpx

# Etherscan's v2 API is multichain behind one key (chainid selects the network).
_V2_BASE = "https://api.etherscan.io/v2/api"


class EtherscanError(RuntimeError):
    """The verified source could not be fetched (bad address, unverified, no key)."""


class EtherscanSource:
    """Fetcher over a verified contract's source, keyed by ``address``.

    ``list_paths(address) -> (paths, "")`` and ``read(address, path) -> str`` mirror
    the repo fetchers so ``hunt_repository`` works without changes.
    """

    def __init__(self, *, api_key: str = "", chainid: int = 1, client: httpx.Client | None = None,
                 timeout: float = 30.0):
        self._api_key = api_key or os.environ.get("ETHERSCAN_API_KEY", "")
        self._chainid = chainid
        self._owns = client is None
        self._client = client or httpx.Client(timeout=timeout)
        self._cache: dict[str, dict[str, str]] = {}

    def _sources(self, address: str) -> dict[str, str]:
        if address in self._cache:
            return self._cache[address]
        if not self._api_key:
            raise EtherscanError(
                "ETHERSCAN_API_KEY is not set — a free Etherscan API key is required to "
                "fetch verified contract source"
            )
        params = {"chainid": self._chainid, "module": "contract",
                  "action": "getsourcecode", "address": address, "apikey": self._api_key}
        try:
            resp = self._client.get(_V2_BASE, params=params)
            resp.raise_for_status()
            body = resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise EtherscanError(f"explorer request failed: {type(exc).__name__}") from exc

        result = body.get("result")
        if body.get("status") == "0" or not isinstance(result, list) or not result:
            note = body.get("result") if isinstance(body.get("result"), str) else body.get("message")
            raise EtherscanError(f"no verified source for {address}: {note}")
        entry = result[0]
        raw = entry.get("SourceCode") or ""
        if not raw.strip():
            raise EtherscanError(f"contract {address} is not verified (no source)")
        name = entry.get("ContractName") or "Contract"
        sources = _parse_source(raw, fallback_name=name)
        self._cache[address] = sources
        return sources

    def list_paths(self, address: str) -> tuple[list[str], str]:
        sources = self._sources(address)
        return sorted(sources), ""              # no commit sha for on-chain source

    def read(self, address: str, path: str) -> str:
        sources = self._sources(address)
        if path not in sources:
            raise EtherscanError(f"{path} not in verified source for {address}")
        return sources[path]

    def close(self) -> None:
        if self._owns:
            self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def _parse_source(raw: str, *, fallback_name: str) -> dict[str, str]:
    """Etherscan returns one of: a single Solidity file; a JSON map of {path: {content}};
    or that JSON wrapped in an extra pair of braces ({{...}}). Normalize all three to a
    {path: source} dict."""
    text = raw.strip()
    # the double-brace standard-json-input wrapper
    if text.startswith("{{") and text.endswith("}}"):
        text = text[1:-1]
    if text.startswith("{"):
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            data = None
        if isinstance(data, dict):
            sources = data.get("sources") if isinstance(data.get("sources"), dict) else data
            out: dict[str, str] = {}
            for path, spec in sources.items():
                if isinstance(spec, dict) and isinstance(spec.get("content"), str):
                    out[_clean_path(path)] = spec["content"]
                elif isinstance(spec, str):
                    out[_clean_path(path)] = spec
            if out:
                return out
    # single flat file
    return {f"{fallback_name}.sol": raw}


def _clean_path(path: str) -> str:
    """Keep a .sol path relative and forward-slashed; drop leading ./ and slashes."""
    p = str(path).replace("\\", "/").lstrip("./").lstrip("/")
    return p if p.endswith(".sol") else p + ".sol" if "." not in p.rsplit("/", 1)[-1] else p
