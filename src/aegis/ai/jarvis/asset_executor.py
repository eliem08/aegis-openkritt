"""Fail-closed execution seam for concrete Aegis-owned asset adapters.

Planning and authorization happen elsewhere. This module only dispatches an already-selected
internal method to a concrete implementation and returns normalized candidate observations.
Unknown methods never fall through to shell execution.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..mobsf_adapter import MobSFConfig, MobSFStaticAdapter
from .asset_deep_capabilities import PlannedMethod


class InternalAssetExecutorError(RuntimeError):
    pass


@dataclass(frozen=True)
class InternalAssetExecution:
    tool: str
    method: str
    candidates: tuple[dict, ...]
    provenance: dict[str, Any]


def execute_internal_asset_method(
    method: PlannedMethod,
    *,
    artifact_path: str | Path | None = None,
    mobsf_config: MobSFConfig | None = None,
    mobsf_client=None,
) -> InternalAssetExecution:
    """Execute one explicitly supported internal method.

    The function does not acquire artifacts or credentials. For MobSF, the caller must provide
    a pre-existing authorized artifact; MobSF configuration itself enforces a loopback service.
    """
    tool = str(method.tool)
    method_name = str(method.method)
    if (tool, method_name) == ("MobSF", "rest-static-analysis"):
        if artifact_path is None:
            raise InternalAssetExecutorError("MobSF execution requires an authorized artifact")
        config = mobsf_config or MobSFConfig.from_env()
        adapter = MobSFStaticAdapter(config, client=mobsf_client)
        try:
            result = adapter.scan(artifact_path)
        finally:
            # Injected clients are not owned by the adapter; close() is safe/no-op for them.
            adapter.close()
        return InternalAssetExecution(
            tool=tool,
            method=method_name,
            candidates=result.findings,
            provenance={
                "adapter": "aegis.ai.mobsf_adapter.MobSFStaticAdapter",
                "artifact_sha256": result.artifact_sha256,
                "mobsf_hash": result.mobsf_hash,
                "report_digest": result.report_digest,
                "scan_type": result.scan_type,
                "file_name": result.file_name,
                "report_metadata": result.report_metadata,
                "cleanup_deleted": result.cleanup_deleted,
                "cleanup_error": result.cleanup_error,
                "verification_state": "candidate",
            },
        )

    raise InternalAssetExecutorError(
        f"unsupported internal asset method: {tool}/{method_name}"
    )
