"""Durable scan scheduling — the coordinator that governs adapter execution.

Distinct from ``aegis.orchestrator`` (the in-process detector loop): this package
drives the persisted scan model (scans/stages/tasks/leases/artifacts) through
reservation, leasing, the process runner, event normalization, and recovery.
"""

from .coordinator import (
    ScanConfig,
    ScanCoordinator,
    StageSpec,
    StepResult,
    TaskSpec,
)

__all__ = [
    "ScanConfig",
    "ScanCoordinator",
    "StageSpec",
    "StepResult",
    "TaskSpec",
]
