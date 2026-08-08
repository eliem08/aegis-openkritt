"""Unified safe-offline dispatcher for heterogeneous asset research.

This is an execution façade over the concrete pipelines already implemented; it is not another
agent framework. It never falls back from an unsupported/dynamic asset to live testing. Supported
local lanes are Android APK, iOS IPA, native PE/ELF executable, firmware image/archive, AI model
artifact, and a single Solidity source file.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, is_dataclass
from pathlib import Path
from typing import Any

from ..mobsf_adapter import MobSFConfig
from ..tool_runtime import ToolPin, ToolRuntimeManager
from .ai_model_pipeline import run_ai_model_pipeline
from .android_pipeline import run_android_static_pipeline
from .asset_capabilities import AssetKind
from .binary_pipeline import run_binary_offline_pipeline
from .contract_static_pipeline import run_contract_static_pipeline
from .firmware_pipeline import run_firmware_offline_pipeline
from .ios_pipeline import run_ios_static_pipeline


class OfflineAssetResearchError(RuntimeError):
    pass


@dataclass(frozen=True)
class OfflineStage:
    stage: str
    status: str
    detail: str = ""


@dataclass
class OfflineAssetResearchReport:
    asset_kind: str
    artifact_path: str
    scope_digest: str
    candidates: list[dict] = field(default_factory=list)
    observations: list[dict] = field(default_factory=list)
    stages: list[OfflineStage] = field(default_factory=list)
    engine_errors: dict[str, str] = field(default_factory=dict)
    details: dict[str, Any] = field(default_factory=dict)


_SUPPORTED = {
    AssetKind.ANDROID_APK,
    AssetKind.IOS_IPA,
    AssetKind.EXECUTABLE,
    AssetKind.HARDWARE,
    AssetKind.AI_MODEL,
    AssetKind.SMART_CONTRACT,
}


def _kind(value: AssetKind | str) -> AssetKind:
    if isinstance(value, AssetKind):
        return value
    try:
        return AssetKind(str(value))
    except ValueError as exc:
        raise OfflineAssetResearchError(f"unsupported asset kind: {value}") from exc


def _observation(value: Any) -> dict:
    if isinstance(value, dict):
        return dict(value)
    if is_dataclass(value):
        return asdict(value)
    return {"kind": "opaque_observation", "value_type": type(value).__name__}


def _stages(values) -> list[OfflineStage]:
    output: list[OfflineStage] = []
    for item in values:
        output.append(
            OfflineStage(
                stage=str(getattr(item, "stage", "unknown")),
                status=str(getattr(item, "status", "unknown")),
                detail=str(getattr(item, "detail", ""))[:500],
            )
        )
    return output


def run_offline_asset_research(
    asset_kind: AssetKind | str,
    artifact_path: str | Path,
    *,
    scope_digest: str,
    workspace_root: str | Path | None = None,
    runtime_manager: ToolRuntimeManager | None = None,
    pins: dict[str, ToolPin] | None = None,
    process_runner=None,
    ghidra_runner=None,
    mobsf_config: MobSFConfig | None = None,
    mobsf_client=None,
    include_ghidra: bool = False,
    sandbox_available: bool = False,
    run_modelscan: bool = True,
) -> OfflineAssetResearchReport:
    """Dispatch one local artifact to its concrete safe pipeline; never widen to live testing."""
    kind = _kind(asset_kind)
    if kind not in _SUPPORTED:
        raise OfflineAssetResearchError(
            f"{kind.value} has no unified safe-offline pipeline; use its policy-controlled lane"
        )
    path = Path(artifact_path).expanduser().resolve()
    if not path.is_file():
        raise OfflineAssetResearchError("offline research requires an existing local artifact")
    scope = str(scope_digest or "").strip()
    if not scope:
        raise OfflineAssetResearchError("scope_digest is required")

    common = {
        "workspace_root": workspace_root,
    }
    if kind is AssetKind.ANDROID_APK:
        result = run_android_static_pipeline(
            path,
            scope_digest=scope,
            mobsf_config=mobsf_config,
            mobsf_client=mobsf_client,
            runtime_manager=runtime_manager,
            pins=pins,
            process_runner=process_runner,
            **common,
        )
        details = {"pipeline": "android_static", "dynamic_runtime_used": False}
    elif kind is AssetKind.IOS_IPA:
        result = run_ios_static_pipeline(
            path,
            scope_digest=scope,
            mobsf_config=mobsf_config,
            mobsf_client=mobsf_client,
            **common,
        )
        details = {"pipeline": "ios_static", "dynamic_runtime_used": False}
    elif kind is AssetKind.EXECUTABLE:
        result = run_binary_offline_pipeline(
            path,
            scope_digest=scope,
            include_ghidra=include_ghidra,
            sandbox_available=sandbox_available,
            runtime_manager=runtime_manager,
            pins=pins,
            process_runner=process_runner,
            ghidra_runner=ghidra_runner,
            **common,
        )
        details = {
            "pipeline": "native_binary",
            "target_binary_executed": False,
            "ghidra_requested": include_ghidra,
        }
    elif kind is AssetKind.HARDWARE:
        result = run_firmware_offline_pipeline(
            path,
            scope_digest=scope,
            runtime_manager=runtime_manager,
            pins=pins,
            process_runner=process_runner,
            **common,
        )
        details = {
            "pipeline": "firmware_offline",
            "emulation_used": False,
            "needs_isolated_filesystem_backend": result.needs_isolated_filesystem_backend,
        }
    elif kind is AssetKind.AI_MODEL:
        result = run_ai_model_pipeline(
            path,
            scope_digest=scope,
            run_modelscan=run_modelscan,
            runtime_manager=runtime_manager,
            pins=pins,
            process_runner=process_runner,
            **common,
        )
        details = {
            "pipeline": "ai_model",
            "deserialized": False,
            "detected_format": result.provenance.format if result.provenance else "unknown",
        }
    else:  # SMART_CONTRACT
        result = run_contract_static_pipeline(
            path,
            scope_digest=scope,
            runtime_manager=runtime_manager,
            pins=pins,
            process_runner=process_runner,
            **common,
        )
        details = {
            "pipeline": "solidity_static",
            "rpc_used": False,
            "foundry_echidna_dynamic_used": False,
        }

    return OfflineAssetResearchReport(
        asset_kind=kind.value,
        artifact_path=str(path),
        scope_digest=scope,
        candidates=list(getattr(result, "candidates", ()) or ()),
        observations=[_observation(item) for item in (getattr(result, "observations", ()) or ())],
        stages=_stages(getattr(result, "stages", ()) or ()),
        engine_errors=dict(getattr(result, "engine_errors", {}) or {}),
        details=details,
    )
