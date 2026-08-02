"""Ephemeral distributed coordination (Phase 5).

Redis-shaped rate buckets, semaphores, cancellation, and dedup that fail closed
when the backend is lost. PostgreSQL stays the source of truth for terminal state.
"""

from .coordinator import (
    PASSIVE_TIERS,
    Admission,
    Coordinator,
    CoordUnavailable,
    InMemoryBackend,
)
from .identity import (
    QUEUE_CAPABILITIES,
    InvalidWorkerIdentity,
    WorkerAuthority,
    WorkerAuthError,
    WorkerIdentity,
    WorkerIdentityExpired,
    WorkerIdentityIssuer,
    worker_proof,
)

__all__ = [
    "Coordinator",
    "InMemoryBackend",
    "Admission",
    "CoordUnavailable",
    "PASSIVE_TIERS",
    "WorkerIdentity",
    "WorkerIdentityIssuer",
    "WorkerAuthority",
    "WorkerAuthError",
    "InvalidWorkerIdentity",
    "WorkerIdentityExpired",
    "worker_proof",
    "QUEUE_CAPABILITIES",
]
