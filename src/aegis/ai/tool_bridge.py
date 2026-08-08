"""Run installed OSS scanners on a checkout and fold their findings into Aegis.

Production execution is now health-gated: the exact executable is resolved, version-probed,
SHA-256 fingerprinted and optionally pin-checked before it receives a target. Injected runners
used by tests remain isolated from the host toolchain. Scanner outputs are still candidates only;
Aegis validation/evidence stages decide whether a finding advances.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from .tool_registry import TOOLS, Tool, tools_for
from .tool_runtime import (
    ToolRuntimeManager,
    ToolRuntimeStatus,
    provenance,
    resolve_binary as _runtime_resolve_binary,
)


@dataclass
class ToolResult:
    tool: str
    ran: bool
    findings: list[dict] = field(default_factory=list)
    error: str = ""
    runtime: dict = field(default_factory=dict)


def resolve_binary(binary: str) -> str | None:
    """Compatibility wrapper around the canonical runtime resolver."""
    return _runtime_resolve_binary(binary)


def available_tools(lane: str | None = None) -> list[Tool]:
    """Registry tools whose binary exists; strict health is enforced at execution time."""
    pool = tools_for(lane) if lane else list(TOOLS)
    return [tool for tool in pool if resolve_binary(tool.binary)]


def rules_dir() -> str:
    from pathlib import Path

    return str(Path(__file__).parent / "rules")


def php_stubs_arg() -> str:
    return ""


def psalm_config(checkout_path: str) -> str:
    import os
    import tempfile
    from pathlib import Path

    stubs = os.environ.get("AEGIS_PHP_STUBS", "").strip()
    stub_xml = (
        f'  <stubs><file name="{stubs}"/></stubs>\n'
        if stubs and os.path.isfile(stubs)
        else ""
    )
    target = str(Path(checkout_path).resolve())
    cfg = os.path.join(tempfile.mkdtemp(prefix="aegis-psalm-"), "psalm.xml")
    Path(cfg).write_text(
        '<?xml version="1.0"?>\n'
        '<psalm errorLevel="8" resolveFromConfigFile="false" findUnusedCode="false"'
        ' findUnusedBaselineEntry="false">\n'
        f'  <projectFiles><directory name="{target}"/></projectFiles>\n'
        f'{stub_xml}'
        '</psalm>\n',
        encoding="utf-8",
    )
    return cfg


def _scanner_env() -> dict:
    import os
    import tempfile

    cache = os.path.join(tempfile.gettempdir(), "aegis-scanner-home")
    os.makedirs(os.path.join(cache, ".cache"), exist_ok=True)
    env = dict(os.environ)
    env.update(
        HOME=cache,
        XDG_CACHE_HOME=os.path.join(cache, ".cache"),
        SEMGREP_ENABLE_VERSION_CHECK="0",
        SEMGREP_SEND_METRICS="off",
    )
    return env


def _default_run(argv, timeout):
    import subprocess

    process = subprocess.run(
        argv,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        env=_scanner_env(),
    )
    return process.stdout or "", process.stderr or ""


class ToolBridge:
    """Invoke scanners with production runtime health and provenance checks."""

    def __init__(self, *, run=None, timeout: int = 1200,
                 runtime_manager: ToolRuntimeManager | None = None,
                 require_healthy: bool | None = None) -> None:
        self._run = run or _default_run
        self._timeout = timeout
        self._runtime = runtime_manager or ToolRuntimeManager()
        # Real process execution is strict by default. Injected runners are test/simulation
        # boundaries and do not depend on scanners installed on the CI host.
        self._require_healthy = (run is None) if require_healthy is None else bool(require_healthy)

    def scan(self, checkout_path: str, *, lane: str | None = None,
             tools: list[Tool] | None = None, on_event=None) -> list[ToolResult]:
        import os
        import shlex
        import time

        emit = on_event or (lambda *_: None)
        chosen = tools if tools is not None else available_tools(lane)
        psalmcfg = psalm_config(str(checkout_path)) if any(
            tool.name == "psalm" for tool in chosen
        ) else ""

        def _run_one(tool: Tool) -> ToolResult:
            runtime_record = None
            if self._require_healthy:
                runtime_record = self._runtime.inspect_tool(tool)
                if runtime_record.status is not ToolRuntimeStatus.READY:
                    emit(
                        "scanner",
                        {
                            "tool": tool.name,
                            "state": "blocked",
                            "runtime_status": runtime_record.status.value,
                            "reason": runtime_record.reason,
                        },
                    )
                    return ToolResult(
                        tool=tool.name,
                        ran=False,
                        error=(
                            f"runtime {runtime_record.status.value}: {runtime_record.reason}"
                        )[:240],
                        runtime=runtime_record.as_dict(),
                    )

            emit("scanner", {"tool": tool.name, "state": "run"})
            started = time.monotonic()
            argv = shlex.split(
                tool.cmd.format(
                    target=str(checkout_path),
                    rules=rules_dir(),
                    phpstubs=php_stubs_arg(),
                    psalmcfg=psalmcfg,
                )
            )
            if runtime_record is not None:
                argv[0] = runtime_record.resolved_path
            else:
                resolved = resolve_binary(argv[0])
                if resolved:
                    argv[0] = resolved

            try:
                stdout, stderr = self._run(argv, self._timeout)
            except Exception as exc:
                emit(
                    "scanner",
                    {
                        "tool": tool.name,
                        "state": "done",
                        "count": 0,
                        "ms": round((time.monotonic() - started) * 1000),
                        "error": True,
                    },
                )
                return ToolResult(
                    tool=tool.name,
                    ran=False,
                    error=f"{type(exc).__name__}: {exc}"[:200],
                    runtime=runtime_record.as_dict() if runtime_record else {},
                )

            findings = _drop_noise_paths(_parse(tool, stdout))
            runtime_payload = provenance(runtime_record, argv) if runtime_record else {}
            if runtime_payload:
                for row in findings:
                    row["scanner_runtime"] = runtime_payload

            emit(
                "scanner",
                {
                    "tool": tool.name,
                    "state": "done",
                    "count": len(findings),
                    "ms": round((time.monotonic() - started) * 1000),
                    "runtime_status": runtime_record.status.value if runtime_record else "injected",
                },
            )
            return ToolResult(
                tool=tool.name,
                ran=True,
                findings=findings,
                error="" if (findings or not stderr) else stderr[:200],
                runtime=runtime_record.as_dict() if runtime_record else {},
            )

        workers = max(1, int(os.environ.get("AEGIS_SCANNER_CONCURRENCY", "4") or 4))
        if workers > 1 and len(chosen) > 1:
            from concurrent.futures import ThreadPoolExecutor

            with ThreadPoolExecutor(max_workers=workers) as executor:
                return list(executor.map(_run_one, chosen))
        return [_run_one(tool) for tool in chosen]

    def findings(self, results: list[ToolResult]) -> list[dict]:
        rows: list[dict] = []
        for result in results:
            rows.extend(result.findings)
        return rows


def _drop_noise_paths(rows: list[dict]) -> list[dict]:
    try:
        from .repo_hunt import _EXCLUDED
    except Exception:
        return rows
    kept = []
    for row in rows:
        path = str((row.get("json_answer") or {}).get("file_path", "")).replace("\\", "/")
        if path and _EXCLUDED.search(path):
            continue
        kept.append(row)
    return kept


def _parse(tool: Tool, stdout: str) -> list[dict]:
    text = (stdout or "").strip()
    if not text:
        return []
    positions = [position for position in (text.find("{"), text.find("[")) if position >= 0]
    if not positions:
        return []
    start = min(positions)
    try:
        data, _ = json.JSONDecoder().raw_decode(text[start:])
    except json.JSONDecodeError:
        return []
    try:
        return tool.parse(data)
    except Exception:
        return []
