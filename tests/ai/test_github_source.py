"""GitHubSource rate-limit handling and header auth."""

from __future__ import annotations

import httpx
import pytest

from aegis.ai.github_source import GitHubRateLimitError, GitHubSource


def _client(handler):
    return httpx.Client(transport=httpx.MockTransport(handler),
                        headers={"Accept": "application/vnd.github+json"})


def test_rate_limit_403_becomes_actionable_error():
    def handler(request):
        return httpx.Response(403, headers={"x-ratelimit-remaining": "0"},
                              text='{"message":"API rate limit exceeded"}')
    src = GitHubSource(client=_client(handler))
    with pytest.raises(GitHubRateLimitError, match="GITHUB_TOKEN"):
        src.list_paths("acme/repo")


def test_token_sets_authorization_header():
    # the token is applied to the internally-built client's default headers
    src = GitHubSource(token="ght_secret")
    try:
        assert src._client.headers.get("authorization") == "Bearer ght_secret"
    finally:
        src.close()


def test_no_token_sends_no_authorization_header():
    src = GitHubSource()
    try:
        assert "authorization" not in src._client.headers
    finally:
        src.close()


def test_list_paths_parses_tree_and_commit():
    def handler(request):
        if request.url.path.endswith("/repo"):
            return httpx.Response(200, json={"default_branch": "main"})
        if "/commits/" in request.url.path:
            return httpx.Response(200, json={"sha": "abc123"})
        return httpx.Response(200, json={"tree": [
            {"type": "blob", "path": "a.go"}, {"type": "tree", "path": "dir"}]})
    src = GitHubSource(client=_client(handler))
    paths, commit = src.list_paths("acme/repo")
    assert paths == ["a.go"] and commit == "abc123"      # trees excluded, blob kept


def test_non_ratelimit_403_still_raises_http_error():
    def handler(request):
        return httpx.Response(403, headers={"x-ratelimit-remaining": "58"},
                              text='{"message":"Forbidden: private repo"}')
    src = GitHubSource(client=_client(handler))
    with pytest.raises(httpx.HTTPStatusError):
        src.list_paths("acme/repo")
