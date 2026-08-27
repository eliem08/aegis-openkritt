"""Strictly non-targeting arsenal health and verified-history audit."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from aegis.ai.tool_runtime import ToolRuntimeManager, ToolRuntimeStatus
from aegis.production.operator_manifest import ImmutableRunStore, document_digest

from .inventory import ArsenalInventoryBuilder
from .models import (
    ArsenalAuditReport,
    ArsenalCoverageState,
    CapabilityDefinition,
    CapabilityHealth,
    CapabilityMode,
    HistoricalExecution,
)


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _health(
    definitions: tuple[CapabilityDefinition, ...], manager: ToolRuntimeManager,
) -> tuple[CapabilityHealth, ...]:
    rows: list[CapabilityHealth] = []
    cache: dict[tuple[str, str, str], Any] = {}
    for definition in definitions:
        if definition.conflicts and any(item.blocks_execution for item in definition.conflicts):
            rows.append(CapabilityHealth(
                definition.capability_id, ArsenalCoverageState.BACKEND_UNHEALTHY,
                False, _now(), reason="execution-blocking registry conflict",
            ))
            continue
        if not definition.tool_backends:
            rows.append(CapabilityHealth(
                definition.capability_id, ArsenalCoverageState.UNAVAILABLE, False, _now(),
                reason="implementation registered; current executor health requires assembly",
            ))
            continue
        backend = definition.tool_backends[0]
        key = (backend.tool_name, backend.binary, backend.expected_version)
        if key not in cache:
            cache[key] = manager.inspect(
                name=backend.tool_name, binary=backend.binary,
                version_override="", refresh=False,
            )
        record = cache[key]
        healthy = record.status is ToolRuntimeStatus.READY
        state = (
            ArsenalCoverageState.WAITING_FOR_PREREQUISITE
            if healthy else ArsenalCoverageState.BACKEND_UNHEALTHY
            if record.status in {ToolRuntimeStatus.STALE, ToolRuntimeStatus.QUARANTINED}
            else ArsenalCoverageState.UNAVAILABLE
        )
        rows.append(CapabilityHealth(
            definition.capability_id, state, healthy, record.checked_at,
            tool_name=backend.tool_name, expected_version=backend.expected_version,
            installed_version=record.version, binary_path=record.resolved_path,
            binary_digest=record.sha256, reason=record.reason,
        ))
    return tuple(rows)


def _verify_evidence(path: Path) -> tuple[dict[str, Any], str]:
    document = json.loads(path.read_text(encoding="utf-8"))
    digest = str(document.pop("evidence_digest", ""))
    if not digest or document_digest(document) != digest or path.stem != digest:
        raise ValueError("evidence digest verification failed")
    return document, digest


def _historical_execution(
    runs_dir: str | Path,
) -> tuple[tuple[HistoricalExecution, ...], tuple[dict[str, Any], ...]]:
    root = Path(runs_dir)
    if not root.is_dir():
        return (), ()
    store = ImmutableRunStore(root)
    history: list[HistoricalExecution] = []
    errors: list[dict[str, Any]] = []
    for run_dir in sorted(path for path in root.iterdir() if path.is_dir()):
        run_id = run_dir.name
        try:
            store.verify(run_id)
            manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
            events = store.events(run_id)
        except Exception as exc:
            errors.append({
                "run_id": run_id, "historical_evidence_invalid": True,
                "error_type": type(exc).__name__,
            })
            continue
        mode = (
            CapabilityMode.AUTHORIZED_REAL
            if manifest.get("mode") in {"campaign", "live_canary"}
            else CapabilityMode.FIXTURE
        )
        for event in events:
            if event.event_type not in {"campaign_task_completed", "arsenal_task_completed"}:
                continue
            reference = str(event.detail.get("evidence_ref") or "")
            expected = str(event.detail.get("evidence_digest") or "")
            try:
                evidence, digest = _verify_evidence(run_dir / reference)
                if digest != expected:
                    raise ValueError("event evidence reference digest mismatch")
            except Exception as exc:
                errors.append({
                    "run_id": run_id, "task_id": str(event.detail.get("task_id") or ""),
                    "historical_evidence_invalid": True, "error_type": type(exc).__name__,
                })
                continue
            technique = str(evidence.get("technique") or "")
            capability_id = str(evidence.get("capability_id") or "")
            if not capability_id and technique:
                capability_id = f"hunter:{technique}"
            if not capability_id:
                continue
            recorded_result = str(event.detail.get("result") or "")
            executed = evidence.get("execution_performed") is True
            if recorded_result not in {
                ArsenalCoverageState.EXECUTED_PASS.value,
                ArsenalCoverageState.EXECUTED_FINDING.value,
            } or not executed:
                # Preserve the immutable event/evidence in the run store, but do not
                # reconstruct failed, blocked, or merely planned work as execution coverage.
                continue
            grant = dict(evidence.get("grant") or {})
            if not grant:
                grant = dict(evidence.get("execution_grant_payload") or {})
            constraints = dict(grant.get("constraints") or {})
            state = ArsenalCoverageState(recorded_result)
            finding_ids = tuple(str(item) for item in evidence.get("finding_ids") or ())
            if finding_ids and evidence.get("human_reviewed") is True:
                state = ArsenalCoverageState.EXECUTED_FINDING
            elif state is ArsenalCoverageState.EXECUTED_FINDING:
                # An immutable executor event cannot award finding credit without the
                # canonical human-reviewed finding reference required by the schema.
                state = ArsenalCoverageState.EXECUTED_PASS
            history.append(HistoricalExecution(
                capability_id=capability_id, mode=mode, state=state, run_id=run_id,
                mission_id=str(evidence.get("mission_id") or ""),
                task_id=str(evidence.get("task_id") or ""),
                backend=str(
                    evidence.get("backend") or event.detail.get("backend") or technique
                ),
                backend_version=str(
                    evidence.get("backend_version")
                    or event.detail.get("backend_version")
                    or ""
                ),
                policy_snapshot_digest=str(evidence.get("policy_snapshot_digest") or ""),
                asset=str(evidence.get("asset") or ""),
                authorization_decision=str(constraints.get("decision_digest") or ""),
                operator_approval_id=(str(constraints.get("operator_approval_id"))
                                      if constraints.get("operator_approval_id") else None),
                execution_grant_id=(str(grant.get("nonce")) if grant.get("nonce") else None),
                executed_at=event.observed_at, evidence_digest=digest,
                finding_ids=finding_ids,
            ))
    return tuple(history), tuple(errors)


def build_audit(
    *, runs_dir: str | Path = "reports/operator-runs",
    release_lock_path: str | Path | None = "secrets/scanner-releases.lock.json",
    runtime_manager: ToolRuntimeManager | None = None,
) -> ArsenalAuditReport:
    definitions = ArsenalInventoryBuilder(release_lock_path=release_lock_path).build()
    health = _health(
        definitions, runtime_manager or ToolRuntimeManager(version_timeout=15.0),
    )
    history, errors = _historical_execution(runs_dir)
    return ArsenalAuditReport(1, _now(), definitions, health, history, errors)


def render_markdown(report: ArsenalAuditReport) -> str:
    document = report.document()
    metrics = document["metrics"]
    lines = [
        "# Aegis arsenal audit", "",
        f"Generated: `{report.generated_at}`", "",
        "## Metrics", "",
    ]
    for key, value in metrics.items():
        lines.append(f"- `{key}`: `{value}`")
    health = {item.capability_id: item for item in report.health}
    latest = {item.capability_id: item for item in report.history}
    lines.extend([
        "", "## Capability matrix", "",
        "| Capability | Implemented | Current state | Backend healthy | Last verified | Evidence |",
        "|---|---:|---|---:|---|---|",
    ])
    for definition in report.definitions:
        current = health[definition.capability_id]
        prior = latest.get(definition.capability_id)
        lines.append(
            f"| `{definition.capability_id}` | yes | {current.current_state.value} | "
            f"{'yes' if current.backend_healthy else 'no'} | "
            f"{prior.state.value if prior else 'never'} | "
            f"`{prior.evidence_digest if prior else ''}` |"
        )
    return "\n".join(lines) + "\n"


def write_audit(
    report: ArsenalAuditReport, *, json_path: str | Path | None,
    markdown_path: str | Path | None,
) -> None:
    if json_path:
        path = Path(json_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report.document(), indent=2, sort_keys=True) + "\n",
                        encoding="utf-8")
    if markdown_path:
        path = Path(markdown_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(render_markdown(report), encoding="utf-8")


__all__ = ["build_audit", "render_markdown", "write_audit"]
