from __future__ import annotations

import json

import pytest

from aegis.ai.jarvis.ct_provider import CrtShProvider, CTProviderError


class Fetcher:
    def __init__(self, status=200, payload=None):
        self.status = status
        self.payload = payload if payload is not None else []
        self.calls = []

    def get(self, url):
        self.calls.append(url)
        return self.status, {"content-type": "application/json"}, json.dumps(self.payload).encode()


def test_crtsh_provider_normalizes_deduplicates_and_preserves_provenance():
    row = {
        "id": 42, "serial_number": "abc", "issuer_name": "Test CA",
        "common_name": "api.example.test",
        "name_value": "api.example.test\nAPI.EXAMPLE.TEST\nnew.example.test",
        "not_before": "2026-01-01T00:00:00Z", "not_after": "2026-04-01T00:00:00Z",
    }
    fetcher = Fetcher(payload=[row, row])
    records = CrtShProvider(fetcher).query("example.test")
    assert len(records) == 1
    assert records[0].sans == ("api.example.test", "new.example.test")
    assert records[0].source == "crt.sh"
    assert fetcher.calls == ["https://crt.sh/?q=%25.example.test&output=json"]


@pytest.mark.parametrize("domain", ["https://example.test", "bad domain", ""])
def test_crtsh_provider_rejects_invalid_domain_before_fetch(domain):
    fetcher = Fetcher()
    with pytest.raises(CTProviderError, match="invalid CT domain"):
        CrtShProvider(fetcher).query(domain)
    assert fetcher.calls == []


def test_crtsh_provider_failure_and_size_budget_are_explicit():
    with pytest.raises(CTProviderError, match="HTTP 503"):
        CrtShProvider(Fetcher(status=503)).query("example.test")
    with pytest.raises(CTProviderError, match="size budget"):
        CrtShProvider(Fetcher(payload=[{"large": "x" * 100}]), max_response_bytes=10).query(
            "example.test"
        )
