"""Canonical registration and honest coverage for production hunter executors."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from .hunter_techniques import TECHNIQUES


class ExecutorProvider(Protocol):
    def runtime_executors(self) -> Mapping[str, Any]: ...


@dataclass(frozen=True, slots=True)
class ExecutorCoverage:
    capability: str
    status: str
    reason: str


def compose_production_executors(
    providers: Iterable[ExecutorProvider],
    *,
    existing: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Merge exact capability providers; ambiguous duplicate authority fails closed."""
    executors = dict(existing or {})
    for provider in providers:
        for capability, executor in provider.runtime_executors().items():
            if not capability.startswith(("dynamic:", "jarvis:")) or "*" in capability:
                raise ValueError(f"executor capability must be exact: {capability}")
            if capability in executors and executors[capability] is not executor:
                raise ValueError(f"multiple production executors claim {capability}")
            executors[capability] = executor
    return executors


def production_execution_coverage(executors: Mapping[str, Any]) -> tuple[ExecutorCoverage, ...]:
    capabilities = sorted({definition.worker_capability for definition in TECHNIQUES.values()})
    return tuple(ExecutorCoverage(
        capability,
        "REAL" if capability in executors else "UNAVAILABLE",
        "exact production executor registered" if capability in executors
        else "no production executor registered; execution must fail closed",
    ) for capability in capabilities)


__all__ = [
    "ExecutorCoverage", "ExecutorProvider", "compose_production_executors",
    "production_execution_coverage",
]
