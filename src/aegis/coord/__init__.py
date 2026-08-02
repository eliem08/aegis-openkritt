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

__all__ = [
    "Coordinator",
    "InMemoryBackend",
    "Admission",
    "CoordUnavailable",
    "PASSIVE_TIERS",
]
