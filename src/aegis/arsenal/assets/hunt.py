"""Route one asset through its techniques and produce an auditable report.

The orchestrator is deliberately thin. It resolves the asset type, checks the asset
itself against the operator's allowlist *before any technique runs*, executes each
registered technique in order, de-duplicates observations across techniques, and
attaches the session's request log to the report. Every technique's outcome appears
in the report — including the ones that could not run and why — because a report
that silently omits a skipped technique reads like coverage that never happened.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from hashlib import sha256
from importlib import import_module
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from ..models import ArsenalCoverageState
from .context import Identity, LaneContext
from .results import Observation, TechniqueResult, deduplicate, unavailable
from .scope import OutOfScopeError, ScopeAllowlist
from .session import HuntSession, InteractionRequired, RateLimit
from .tooling import ToolResolver
from .types import ArsenalAssetType, Technique, classify_identifier, techniques_for

#: Asset types whose techniques act on a local artifact or a generated document and
#: therefore never contact the asset itself. The allowlist pre-check is skipped for
#: these because the "asset" is a file path or an account identifier, not a host.
_OFFLINE_ASSET_TYPES: frozenset[ArsenalAssetType] = frozenset({
    ArsenalAssetType.SOURCE_CODE,
    ArsenalAssetType.EXECUTABLE,
    ArsenalAssetType.SMART_CONTRACT,
    ArsenalAssetType.AWS_ACCOUNT,
    ArsenalAssetType.AZURE_ACCOUNT,
    ArsenalAssetType.OTHER_ASSET,
})

Executor = Callable[[LaneContext], TechniqueResult]


class HuntRefused(PermissionError):
    """The hunt was refused before any technique ran."""


@dataclass(frozen=True, slots=True)
class HuntReport:
    """The complete, auditable outcome of one asset hunt."""

    hunt_id: str
    asset: str
    asset_type: ArsenalAssetType
    program: str
    started_at: str
    finished_at: str
    results: tuple[TechniqueResult, ...]
    observations: tuple[Observation, ...]
    request_log: tuple[Mapping[str, Any], ...]
    scope: Mapping[str, Any]
    read_only: bool
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @property
    def executed_count(self) -> int:
        return sum(item.executed for item in self.results)

    @property
    def has_findings(self) -> bool:
        return bool(self.observations)

    def document(self) -> dict[str, Any]:
        counts: dict[str, int] = {}
        for item in self.results:
            counts[item.state.value] = counts.get(item.state.value, 0) + 1
        severities: dict[str, int] = {}
        for item in self.observations:
            severities[item.severity] = severities.get(item.severity, 0) + 1
        return {
            "schema_version": 1,
            "hunt_id": self.hunt_id,
            "asset": self.asset,
            "asset_type": self.asset_type.value,
            "program": self.program,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "read_only": self.read_only,
            "summary": {
                "techniques_registered": len(self.results),
                "techniques_executed": self.executed_count,
                "technique_states": dict(sorted(counts.items())),
                "observation_count": len(self.observations),
                "observations_by_severity": dict(sorted(severities.items())),
                "requests": summarize_requests_from(self.request_log),
            },
            "scope": dict(self.scope),
            "results": [item.document() for item in self.results],
            "observations": [item.document() for item in self.observations],
            "request_log": [dict(item) for item in self.request_log],
            "metadata": dict(self.metadata),
        }


def summarize_requests_from(log: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    outcomes: dict[str, int] = {}
    for record in log:
        key = str(record.get("outcome") or "unknown")
        outcomes[key] = outcomes.get(key, 0) + 1
    return {"total_attempts": len(log), "outcomes": dict(sorted(outcomes.items()))}


def load_executor(technique: Technique) -> Executor:
    """Resolve a technique's ``module:function`` reference to a callable."""
    module_name, _, function_name = technique.executor.partition(":")
    module = import_module(module_name)
    executor = getattr(module, function_name, None)
    if not callable(executor):
        raise AttributeError(
            f"technique {technique.technique_id!r} names {technique.executor!r}, "
            "which is not callable"
        )
    return executor


def run_hunt(
    *,
    asset: str,
    allowlist: ScopeAllowlist,
    asset_type: ArsenalAssetType | None = None,
    rate_limit: RateLimit | None = None,
    allow_state_change: bool = False,
    artifact_path: str | Path | None = None,
    specification_path: str | Path | None = None,
    policy_documents: Sequence[str | Path] = (),
    identities: Sequence[Identity] = (),
    workspace: str | Path | None = None,
    options: Mapping[str, Any] | None = None,
    log_path: str | Path | None = None,
    only: Sequence[str] = (),
    resolver: ToolResolver | None = None,
    session: HuntSession | None = None,
) -> HuntReport:
    """Execute every technique registered for an asset, fail-closed on scope."""
    started = datetime.now(UTC)
    resolved_type = asset_type or classify_identifier(asset)
    techniques = techniques_for(resolved_type)
    if only:
        wanted = set(only)
        unknown = wanted - {item.technique_id for item in techniques}
        if unknown:
            raise ValueError(
                f"technique(s) {sorted(unknown)} are not registered for "
                f"{resolved_type.value!r}"
            )
        techniques = tuple(item for item in techniques if item.technique_id in wanted)

    hunt_session = session or HuntSession(
        allowlist=allowlist,
        rate_limit=rate_limit or RateLimit(),
        allow_state_change=allow_state_change,
        log_path=log_path,
    )

    # The asset itself is checked before a single technique is constructed. A hunt
    # against an out-of-scope host must never begin, not merely fail at the first
    # request.
    if resolved_type not in _OFFLINE_ASSET_TYPES:
        decision = allowlist.evaluate(asset)
        if not decision.allowed:
            raise HuntRefused(
                f"refusing to hunt {asset!r}: {decision.reason}. Add it to the scope "
                "file only if the program's engagement page lists it as in scope."
            )

    context = LaneContext(
        asset=asset,
        asset_type=resolved_type,
        session=hunt_session,
        resolver=resolver or ToolResolver(),
        artifact_path=Path(artifact_path) if artifact_path else None,
        specification_path=Path(specification_path) if specification_path else None,
        policy_documents=tuple(Path(item) for item in policy_documents),
        identities=tuple(identities),
        workspace=Path(workspace) if workspace else None,
        options=dict(options or {}),
    )

    results: list[TechniqueResult] = []
    for technique in techniques:
        results.append(_run_technique(technique, context))

    observations = deduplicate([
        item for result in results for item in result.observations
    ])
    finished = datetime.now(UTC)
    hunt_id = "hunt-{}-{}".format(
        started.strftime("%Y%m%dT%H%M%SZ"),
        sha256(f"{asset}:{started.isoformat()}".encode()).hexdigest()[:8],
    )
    return HuntReport(
        hunt_id=hunt_id, asset=asset, asset_type=resolved_type,
        program=allowlist.program, started_at=started.isoformat(),
        finished_at=finished.isoformat(), results=tuple(results),
        observations=observations,
        request_log=tuple(item.document() for item in hunt_session.records),
        scope=allowlist.document(), read_only=not allow_state_change,
        metadata={
            "techniques_requested": [item.technique_id for item in techniques],
            "rate_limit": {
                "requests_per_second": hunt_session.rate_limit.requests_per_second,
                "max_requests": hunt_session.rate_limit.max_requests,
            },
            "inputs": context.document(),
        },
    )


def _run_technique(technique: Technique, context: LaneContext) -> TechniqueResult:
    """Execute one technique, turning any failure into an honest UNAVAILABLE result."""
    try:
        executor = load_executor(technique)
    except (ImportError, AttributeError) as exc:
        return unavailable(
            technique.technique_id, context.asset,
            f"technique executor could not be loaded: {type(exc).__name__}: {exc}",
        )
    try:
        result = executor(context)
    except OutOfScopeError as exc:
        return TechniqueResult(
            technique.technique_id, context.asset, ArsenalCoverageState.DENIED_BY_POLICY,
            (), str(exc),
        )
    except InteractionRequired as exc:
        return TechniqueResult(
            technique.technique_id, context.asset,
            ArsenalCoverageState.WAITING_FOR_PREREQUISITE, (), str(exc),
        )
    except Exception as exc:  # noqa: BLE001 - one broken lane must not lose the others
        return unavailable(
            technique.technique_id, context.asset,
            f"technique raised {type(exc).__name__}: {exc}",
        )
    if not isinstance(result, TechniqueResult):
        return unavailable(
            technique.technique_id, context.asset,
            f"technique returned {type(result).__name__}, not a TechniqueResult",
        )
    return result


def write_report(report: HuntReport, path: str | Path) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(report.document(), indent=2, sort_keys=True) + "\n", encoding="utf-8",
    )


def render_markdown(report: HuntReport) -> str:
    """A human-readable summary for the operator's triage pass."""
    document = report.document()
    summary = document["summary"]
    lines = [
        f"# Asset hunt — {report.asset}", "",
        f"- Asset type: `{report.asset_type.value}`",
        f"- Program: `{report.program}`",
        f"- Hunt: `{report.hunt_id}`",
        f"- Mode: {'read-only' if report.read_only else 'STATE-CHANGING (opted in)'}",
        f"- Techniques executed: {summary['techniques_executed']}"
        f"/{summary['techniques_registered']}",
        f"- Outbound attempts: {summary['requests']['total_attempts']}", "",
        "## Technique outcomes", "",
        "| Technique | State | Tool | Reason |", "|---|---|---|---|",
    ]
    for result in report.results:
        reason = (result.reason or "").replace("|", "/").replace("\n", " ")[:160]
        lines.append(
            f"| `{result.technique_id}` | {result.state.value} | "
            f"`{result.tool or '-'}` | {reason} |"
        )
    if report.observations:
        lines.extend(["", "## Observations", ""])
        for item in sorted(report.observations, key=lambda row: row.severity):
            lines.append(f"### [{item.severity}] {item.title}")
            lines.append("")
            lines.append(f"- Subject: `{item.subject}`")
            lines.append(f"- Weakness: `{item.weakness or 'unclassified'}`")
            if item.guarded_sibling:
                lines.append(f"- Guarded sibling: {item.guarded_sibling}")
            if item.recommendation:
                lines.append(f"- Next step: {item.recommendation}")
            lines.append("")
    else:
        lines.extend(["", "No observations. This is not a clean bill of health — check the",
                      "technique table above for lanes that did not execute.", ""])
    return "\n".join(lines) + "\n"


__all__ = [
    "HuntRefused",
    "HuntReport",
    "load_executor",
    "render_markdown",
    "run_hunt",
    "write_report",
]
