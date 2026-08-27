"""Source code lane — a thin adapter onto the scanner path the repository already has.

Source review is the arsenal's oldest and strongest lane. Nothing is reimplemented
here: this routes a local checkout through :class:`aegis.ai.tool_bridge.ToolBridge`
(the same bridge ``tool_exercise`` uses for fixtures) so a source asset behaves like
every other asset type at the hunt level while the detection logic stays in one
place.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from aegis.ai.tool_registry import TOOLS

from .context import LaneContext
from .results import (
    Observation,
    TechniqueResult,
    deduplicate,
    executed,
    now,
    unavailable,
    waiting,
)

_SEVERITY_FALLBACK = "medium"


def scanner_sweep(context: LaneContext) -> TechniqueResult:
    """Run the registered deterministic scanners over a local checkout."""
    technique = "source-scanner-sweep"
    started = now()
    root = context.artifact_path
    if root is None or not Path(root).exists():
        return waiting(
            technique, context.asset,
            "no local checkout supplied; clone the repository yourself and pass "
            "--artifact <path> (Aegis does not clone from the hunt command)",
        )
    try:
        from aegis.ai.tool_bridge import ToolBridge
        from aegis.ai.tool_runtime import ToolRuntimeManager
    except ImportError as exc:  # pragma: no cover - the bridge ships with the package
        return unavailable(
            technique, context.asset, f"scanner bridge unavailable: {exc}",
        )

    requested = context.option("tools")
    selected = [
        item for item in TOOLS
        if not requested or item.name in set(str(requested).split(","))
    ]
    bridge = ToolBridge(timeout=600, runtime_manager=ToolRuntimeManager(version_timeout=15.0))
    try:
        outcomes = bridge.scan(str(root), tools=selected)
    except Exception as exc:  # noqa: BLE001 - a scanner crash must not lose the lane
        return unavailable(
            technique, context.asset,
            f"scanner sweep failed: {type(exc).__name__}: {exc}",
        )

    observations: list[Observation] = []
    ran: list[str] = []
    skipped: list[dict[str, Any]] = []
    for outcome in outcomes:
        name = getattr(outcome, "tool", "") or getattr(outcome, "name", "")
        if not getattr(outcome, "ran", False):
            skipped.append({"tool": name, "error": str(getattr(outcome, "error", ""))})
            continue
        ran.append(name)
        for row in getattr(outcome, "findings", ()) or ():
            observations.append(_observation(technique, name, row))
    if not ran:
        return unavailable(
            technique, context.asset,
            "no scanner executed; on Windows most of these run only inside the Linux "
            "arsenal image — build it with "
            "`docker build -f Dockerfile.arsenal -t aegis-arsenal .` and re-run there",
            metadata={"skipped": skipped},
        )
    return executed(
        technique, context.asset, deduplicate(observations), tool=",".join(ran),
        started_at=started,
        metadata={"tools_ran": ran, "tools_skipped": skipped,
                  "raw_finding_count": len(observations)},
    )


def _observation(technique: str, tool: str, row: Any) -> Observation:
    answer = (row or {}).get("json_answer", {}) if isinstance(row, dict) else {}
    severity = str((row or {}).get("severity") or _SEVERITY_FALLBACK).lower()
    if severity not in {"critical", "high", "medium", "low", "info"}:
        severity = _SEVERITY_FALLBACK
    path = str(answer.get("file_path") or "")
    line = answer.get("line") or 0
    return Observation(
        technique, str(answer.get("summary") or answer.get("vulnerability_type") or tool),
        severity, f"{path}:{line}" if path else tool,
        evidence={"tool": tool, "vulnerability_type": str(answer.get("vulnerability_type") or ""),
                  "file_path": path, "line": line,
                  "explanation": str(answer.get("explanation") or "")[:2000]},
        weakness=str(answer.get("vulnerability_type") or ""),
        confidence=str((row or {}).get("validation_status") or "unverified"),
        recommendation="scanner output is a candidate; trace source to sink and find the "
                       "guarded sibling before it becomes a report",
    )


__all__ = ["scanner_sweep"]
