"""Typed fail-closed outcomes shared by canonical mission executors."""

from __future__ import annotations


class MissionExecutionError(RuntimeError):
    """Base class for an executor that could not produce a completed observation."""


class MissionPrerequisiteError(MissionExecutionError):
    """Required operator-supplied fixtures, credentials, or artifacts are absent."""


class MissionBackendUnavailableError(MissionExecutionError):
    """A configured execution backend is absent or cannot be reached."""


class MissionObservationPending(MissionExecutionError):
    """Execution happened, but an asynchronous observation window is still open."""


__all__ = [
    "MissionBackendUnavailableError",
    "MissionExecutionError",
    "MissionObservationPending",
    "MissionPrerequisiteError",
]
