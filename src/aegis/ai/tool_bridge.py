"""Run installed OSS scanners on a checkout and fold their findings into Aegis.

Detects which tools from the registry are on PATH, invokes each on the local checkout,
parses its native JSON via the tool's parser, and returns Aegis candidate rows (all
``unverified`` — Aegis's validator and a human still gate them). Arm's-length: it runs
the installed binary as a separate process and reads its output; no tool source is
embedded.
"""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass, field

from .tool_registry import TOOLS, Tool, tools_for


@dataclass
class ToolResult:
    tool: str
    ran: bool
    findings: list[dict] = field(default_factory=list)
    error: str = ""


def available_tools(lane: str | None = None) -> list[Tool]:
    """Tools from the registry whose binary is installed on PATH (optionally by lane)."""
    pool = tools_for(lane) if lane else list(TOOLS)
    return [t for t in pool if shutil.which(t.binary)]


def _default_run(argv, timeout):
    import subprocess
    p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
    return p.stdout or "", p.stderr or ""


class ToolBridge:
    """Invoke installed scanners on a checkout and collect their findings."""

    def __init__(self, *, run=None, timeout: int = 1200) -> None:
        self._run = run or _default_run
        self._timeout = timeout

    def scan(self, checkout_path: str, *, lane: str | None = None,
             tools: list[Tool] | None = None) -> list[ToolResult]:
        import shlex
        chosen = tools if tools is not None else available_tools(lane)
        results: list[ToolResult] = []
        for tool in chosen:
            argv = shlex.split(tool.cmd.format(target=str(checkout_path)))
            try:
                stdout, stderr = self._run(argv, self._timeout)
            except Exception as exc:
                results.append(ToolResult(tool=tool.name, ran=False,
                                          error=f"{type(exc).__name__}: {exc}"[:200]))
                continue
            findings = _parse(tool, stdout)
            results.append(ToolResult(tool=tool.name, ran=True, findings=findings,
                                      error="" if (findings or not stderr) else stderr[:200]))
        return results

    def findings(self, results: list[ToolResult]) -> list[dict]:
        rows: list[dict] = []
        for r in results:
            rows.extend(r.findings)
        return rows


def _parse(tool: Tool, stdout: str) -> list[dict]:
    text = (stdout or "").strip()
    if not text:
        return []
    # tolerate leading banner text before the JSON body
    for opener in ("{", "["):
        i = text.find(opener)
        if i < 0:
            continue
        try:
            data, _ = json.JSONDecoder().raw_decode(text[i:])
        except json.JSONDecodeError:
            continue
        try:
            return tool.parse(data)
        except Exception:
            return []
    return []
