"""Execution-kernel architecture guards (P0.2 + P0.4).

These are deliberately source-level: they enforce that the *production dispatch path* cannot
regress to unsandboxed execution or optional pinning, independent of runtime behavior.
"""

from __future__ import annotations

from pathlib import Path

_SRC = Path(__file__).resolve().parents[2] / "src" / "aegis" / "ai" / "jarvis"


def test_router_dispatches_offline_cli_through_networkless_sandbox():
    """P0.2: the asset router must route generic offline CLIs through the ticket-verified,
    kernel-networkless sandbox — never the raw local-CLI primitive."""
    src = (_SRC / "asset_execution_router.py").read_text(encoding="utf-8")
    assert "execute_ticketed_networkless_method(" in src, "router must use the networkless sandbox"
    # the raw primitive must NOT be dispatched from the router (it is an internal low-level call)
    assert "execute_local_cli_method(" not in src, "router must not call the raw local-CLI primitive"


def test_networkless_backend_unshares_network():
    """The networkless backend must actually unshare the network namespace (Bubblewrap)."""
    src = (_SRC / "networkless_cli.py").read_text(encoding="utf-8")
    # --unshare-all unshares every namespace (including network); --unshare-net is the narrow form
    assert "--unshare-all" in src or "--unshare-net" in src, "networkless backend must unshare net"


def test_scanner_pins_are_mandatory_in_production(tmp_path, monkeypatch):
    """P0.4: unattended (production/bug-bounty) mode must refuse to run without pinned scanners."""
    from aegis.ai.tool_runtime import load_tool_pins

    monkeypatch.delenv("AEGIS_TOOL_PINS_FILE", raising=False)
    monkeypatch.delenv("AEGIS_TOOL_PINS_REQUIRED", raising=False)
    # development: pins optional
    monkeypatch.delenv("AEGIS_MODE", raising=False)
    assert load_tool_pins() == {}
    # production: no pins file -> fail closed
    monkeypatch.setenv("AEGIS_MODE", "production")
    import pytest
    with pytest.raises(RuntimeError, match="mandatory"):
        load_tool_pins()
    # an explicit pins file satisfies production mode
    pins = tmp_path / "pins.json"
    pins.write_text('{"semgrep": {"version_contains": "1.99"}}', encoding="utf-8")
    monkeypatch.setenv("AEGIS_TOOL_PINS_FILE", str(pins))
    assert "semgrep" in load_tool_pins()


def test_health_probe_env_scrubs_credentials(monkeypatch):
    """P0.4: an innocent `scanner --version` probe must not receive credentials from the parent
    environment (a malicious unpinned binary on PATH could otherwise harvest them)."""
    from aegis.ai.tool_runtime import _health_env

    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "leaked")
    monkeypatch.setenv("HACKERONE_API_TOKEN", "leaked")
    monkeypatch.setenv("GITHUB_TOKEN", "leaked")
    monkeypatch.setenv("HTTP_PROXY", "http://attacker:8080")
    monkeypatch.setenv("PATH_SAFE_MARKER", "ok")  # a non-secret var survives
    env = _health_env()
    assert "AWS_SECRET_ACCESS_KEY" not in env
    assert "HACKERONE_API_TOKEN" not in env
    assert "GITHUB_TOKEN" not in env
    assert env.get("HTTP_PROXY") == "http://127.0.0.1:9"   # proxy pinned to a dead loopback
    assert env.get("PATH_SAFE_MARKER") == "ok"
