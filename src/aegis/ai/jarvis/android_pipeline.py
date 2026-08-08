"""Static-only Android research pipeline for authorized APK artifacts.

Stages:
1. optional loopback MobSF static scan,
2. networkless JADX/apktool derived trees with APK-digest-bound tickets,
3. manifest/WebView/TLS hypothesis generation over each tree,
4. cross-engine candidate deduplication and workspace cleanup.

No store acquisition, emulator/device runtime, Frida/Objection, or target network traffic occurs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from ..mobsf_adapter import MobSFConfig
from ..tool_runtime import ToolPin, ToolRuntimeManager
from .android_static import (
    ANDROID_STATIC_METHODS,
    AndroidDerivedTree,
    DeepScannerMethod,
    cleanup_android_static,
    execute_android_static,
    issue_android_static_ticket,
)
from .android_surface import AndroidSurfaceError, analyze_android_derived_tree
from .asset_capabilities import MOBSF, AssetKind
from .asset_execution import execute_authorized_offline_method
from .asset_execution_ticket import CapabilityAvailability, issue_offline_execution_ticket


@dataclass(frozen=True)
class AndroidStageResult:
    stage: str
    status: str
    detail: str = ""


@dataclass
class AndroidPipelineReport:
    apk_path: str
    scope_digest: str
    stages: list[AndroidStageResult] = field(default_factory=list)
    candidates: list[dict] = field(default_factory=list)
    observations: list[dict] = field(default_factory=list)
    engine_errors: dict[str, str] = field(default_factory=dict)
    retained_trees: list[AndroidDerivedTree] = field(default_factory=list)


def _dedupe(rows: Iterable[dict]) -> list[dict]:
    output: list[dict] = []
    seen: set[tuple[str, str, int, str]] = set()
    for row in rows:
        answer = row.get("json_answer") or {}
        key = (
            str(answer.get("vulnerability_type") or ""),
            str(answer.get("file_path") or ""),
            int(answer.get("line") or 0),
            str(answer.get("summary") or ""),
        )
        if key in seen:
            continue
        seen.add(key)
        output.append(row)
    return output


def run_android_static_pipeline(
    apk_path: str | Path,
    *,
    scope_digest: str,
    decompilers: Iterable[DeepScannerMethod] = ANDROID_STATIC_METHODS,
    mobsf_config: MobSFConfig | None = None,
    mobsf_client=None,
    workspace_root: str | Path | None = None,
    retain_derived_trees: bool = False,
    runtime_manager: ToolRuntimeManager | None = None,
    pins: dict[str, ToolPin] | None = None,
    process_runner=None,
) -> AndroidPipelineReport:
    """Run all configured static Android engines independently and preserve partial results."""
    apk = Path(apk_path).expanduser().resolve()
    report = AndroidPipelineReport(str(apk), str(scope_digest))
    candidates: list[dict] = []

    if mobsf_config is not None:
        try:
            ticket = issue_offline_execution_ticket(
                asset_kind=AssetKind.ANDROID_APK,
                method=MOBSF,
                scope_digest=scope_digest,
                availability=CapabilityAvailability(artifact_available=True),
            )
            outcome = execute_authorized_offline_method(
                MOBSF,
                ticket=ticket,
                scope_digest=scope_digest,
                artifact_path=apk,
                mobsf_config=mobsf_config,
                mobsf_client=mobsf_client,
            )
            candidates.extend(outcome.candidates)
            report.observations.extend(
                {
                    "kind": observation.kind,
                    "tool": observation.tool,
                    "method": observation.method,
                    "data": observation.data,
                }
                for observation in outcome.observations
            )
            report.stages.append(AndroidStageResult("mobsf", "complete"))
        except Exception as exc:
            report.engine_errors["MobSF"] = f"{type(exc).__name__}: {exc}"[:240]
            report.stages.append(AndroidStageResult("mobsf", "failed", report.engine_errors["MobSF"]))
    else:
        report.stages.append(AndroidStageResult("mobsf", "skipped", "MobSF not configured"))

    for method in tuple(decompilers):
        identity = f"{method.tool}/{method.method}"
        tree: AndroidDerivedTree | None = None
        try:
            ticket = issue_android_static_ticket(apk, method, scope_digest=scope_digest)
            static = execute_android_static(
                apk,
                method,
                ticket=ticket,
                scope_digest=scope_digest,
                workspace_root=workspace_root,
                runtime_manager=runtime_manager,
                pins=pins,
                process_runner=process_runner,
            )
            tree = static.derived_tree
            report.observations.append(static.observation)
            analysis = analyze_android_derived_tree(tree)
            candidates.extend(analysis.candidates)
            report.observations.append(analysis.observation)
            report.stages.append(AndroidStageResult(identity, "complete"))
            if retain_derived_trees:
                report.retained_trees.append(tree)
                tree = None
        except AndroidSurfaceError as exc:
            report.engine_errors[identity] = f"surface: {exc}"[:240]
            report.stages.append(AndroidStageResult(identity, "partial", report.engine_errors[identity]))
        except Exception as exc:
            report.engine_errors[identity] = f"{type(exc).__name__}: {exc}"[:240]
            report.stages.append(AndroidStageResult(identity, "failed", report.engine_errors[identity]))
        finally:
            if tree is not None:
                cleanup_android_static(tree)

    report.candidates = _dedupe(candidates)
    return report


def cleanup_android_pipeline(report: AndroidPipelineReport) -> None:
    for tree in list(report.retained_trees):
        cleanup_android_static(tree)
    report.retained_trees.clear()
