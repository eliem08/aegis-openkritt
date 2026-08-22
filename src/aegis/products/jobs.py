"""In-process async job store for product runs.

Product runs (a hunt, a reproduction) can take minutes, so the hosted API submits them as jobs
and lets the caller poll. This is a deliberately small, dependency-free executor suitable for a
single control-plane process; a multi-node deployment would swap it for a durable queue behind the
same :class:`ProductJobStore` interface.
"""

from __future__ import annotations

import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Callable


@dataclass
class ProductJob:
    id: str
    product: str
    status: str = "queued"          # queued | running | completed | failed
    result: dict | None = None
    error: str | None = None
    tenant: str = ""
    created_ts: float = 0.0
    finished_ts: float | None = None
    meta: dict = field(default_factory=dict)

    def public(self) -> dict:
        return {
            "job_id": self.id,
            "product": self.product,
            "status": self.status,
            "result": self.result,
            "error": self.error,
            "created_ts": self.created_ts,
            "finished_ts": self.finished_ts,
        }


class ProductJobStore:
    """Thread-pool-backed job store. Thread-safe; results kept in memory."""

    def __init__(self, max_workers: int = 4) -> None:
        self._ex = ThreadPoolExecutor(max_workers=max_workers,
                                      thread_name_prefix="aegis-product")
        self._jobs: dict[str, ProductJob] = {}
        self._lock = threading.Lock()

    def submit(self, product: str, fn: Callable[[], dict], *, tenant: str = "") -> ProductJob:
        job = ProductJob(id=uuid.uuid4().hex[:16], product=product, tenant=tenant,
                         created_ts=time.time())
        with self._lock:
            self._jobs[job.id] = job

        def _run() -> None:
            job.status = "running"
            try:
                job.result = fn()
                job.status = "completed"
            except Exception as exc:  # noqa: BLE001 - surface any engine error to the caller
                job.error = f"{type(exc).__name__}: {exc}"[:500]
                job.status = "failed"
            finally:
                job.finished_ts = time.time()

        self._ex.submit(_run)
        return job

    def get(self, job_id: str) -> ProductJob | None:
        with self._lock:
            return self._jobs.get(job_id)

    def list(self, *, tenant: str | None = None) -> list[ProductJob]:
        with self._lock:
            jobs = list(self._jobs.values())
        if tenant is not None:
            jobs = [j for j in jobs if j.tenant == tenant]
        return sorted(jobs, key=lambda j: j.created_ts, reverse=True)
