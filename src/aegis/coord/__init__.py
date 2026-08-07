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
    WorkerAuthError,
    WorkerAuthority,
    WorkerIdentity,
    WorkerIdentityExpired,
    WorkerIdentityIssuer,
    worker_proof,
)

__all__ = [
    "PASSIVE_TIERS",
    "QUEUE_CAPABILITIES",
    "Admission",
    "CoordUnavailable",
    "Coordinator",
    "InMemoryBackend",
    "InvalidWorkerIdentity",
    "WorkerAuthError",
    "WorkerAuthority",
    "WorkerIdentity",
    "WorkerIdentityExpired",
    "WorkerIdentityIssuer",
    "worker_proof",
]
