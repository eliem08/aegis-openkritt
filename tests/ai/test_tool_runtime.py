from __future__ import annotations

import hashlib

from aegis.ai.tool_bridge import ToolBridge
from aegis.ai.tool_registry import TOOLS
from aegis.ai.tool_runtime import (
    ToolPin,
    ToolRuntimeManager,
    ToolRuntimeStatus,
    provenance,
)


def _binary(tmp_path, content=b"scanner-binary"):
    path = tmp_path / "scanner"
    path.write_bytes(content)
    return path


def test_runtime_ready_records_version_digest_and_provenance(tmp_path):
    path = _binary(tmp_path)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    manager = ToolRuntimeManager(
        resolver=lambda _binary: str(path),
        runner=lambda argv, timeout: (0, "scanner 1.2.3\n", ""),
    )
    record = manager.inspect(name="scanner", binary="scanner", pin=ToolPin(sha256=digest))
    assert record.status is ToolRuntimeStatus.READY
    assert record.version == "scanner 1.2.3"
    assert record.sha256 == digest
    payload = provenance(record, [str(path), "--json", "/repo"])
    assert payload["binary_sha256"] == digest
    assert payload["argv"][-1] == "/repo"


def test_digest_mismatch_quarantines_before_version_probe(tmp_path):
    path = _binary(tmp_path)
    calls = []

    def runner(argv, timeout):
        calls.append(argv)
        return 0, "scanner 1.0", ""

    manager = ToolRuntimeManager(resolver=lambda _binary: str(path), runner=runner)
    record = manager.inspect(name="scanner", binary="scanner", pin=ToolPin(sha256="0" * 64))
    assert record.status is ToolRuntimeStatus.QUARANTINED
    assert calls == []


def test_version_mismatch_is_stale(tmp_path):
    path = _binary(tmp_path)
    manager = ToolRuntimeManager(
        resolver=lambda _binary: str(path),
        runner=lambda argv, timeout: (0, "scanner 1.2.3", ""),
    )
    record = manager.inspect(
        name="scanner", binary="scanner", pin=ToolPin(version_contains="2.0")
    )
    assert record.status is ToolRuntimeStatus.STALE


def test_missing_binary_is_unavailable():
    manager = ToolRuntimeManager(resolver=lambda _binary: None)
    record = manager.inspect(name="scanner", binary="scanner")
    assert record.status is ToolRuntimeStatus.UNAVAILABLE


def test_toolbridge_blocks_unhealthy_runtime_before_scan_target_is_sent(tmp_path):
    semgrep = next(tool for tool in TOOLS if tool.name == "semgrep")
    path = _binary(tmp_path)
    manager = ToolRuntimeManager(
        resolver=lambda _binary: str(path),
        runner=lambda argv, timeout: (1, "", "broken"),
    )
    scan_calls = []

    def scan_runner(argv, timeout):
        scan_calls.append(argv)
        return "{}", ""

    bridge = ToolBridge(
        run=scan_runner,
        runtime_manager=manager,
        require_healthy=True,
    )
    result = bridge.scan("/sensitive-checkout", tools=[semgrep])[0]
    assert result.ran is False
    assert result.runtime["status"] == "stale"
    assert scan_calls == []
    assert "/sensitive-checkout" not in result.error
