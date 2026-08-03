"""Live open·kritt connector — HTTP against its backend API, arm's-length.

Talks to a *running* open·kritt backend over the endpoints it actually exposes
(``/api/scans``, ``/api/scans/{id}/vulnerabilities``, ``/api/vulnerabilities/{id}``)
and funnels the result through :func:`ingest_openkritt_findings`, so a live
open·kritt scan produces Aegis candidates in the shared pipeline. No open·kritt
source is used — only its HTTP contract (see ``docs/OPENKRITT_INTEGRATION.md``).

The ``httpx.Client`` is injectable so tests drive it with a mock transport; the
network boundary is never crossed in the suite.
"""

from __future__ import annotations

import httpx

from .openkritt import ingest_openkritt_findings


class OpenKrittClient:
    def __init__(self, base_url: str, *, api_key: str | None = None,
                 client: httpx.Client | None = None, timeout: float = 30.0,
                 headers: dict | None = None):
        self._base = base_url.rstrip("/")
        merged = dict(headers or {})
        if api_key:
            merged.setdefault("Authorization", f"Bearer {api_key}")
        self._owns_client = client is None
        self._client = client or httpx.Client(timeout=timeout)
        self._headers = merged

    # --- read: pull findings ------------------------------------------------

    def list_scans(self) -> list[dict]:
        return self._get("/api/scans") or []

    def scan_vulnerabilities(self, scan_id, *, include_duplicates: bool = False) -> list[dict]:
        """Raw serialized vulnerabilities for a scan (canonical-only by default)."""
        params = {"includeDuplicates": "1"} if include_duplicates else None
        return self._get(f"/api/scans/{scan_id}/vulnerabilities", params=params) or []

    def import_candidates(self, scan_id, *, include_duplicates: bool = False, **ingest_kwargs):
        """Fetch a scan's findings and map them to unverified Aegis candidates."""
        rows = self.scan_vulnerabilities(scan_id, include_duplicates=include_duplicates)
        # The API already applied open·kritt's dedup; keep duplicates only if the
        # caller explicitly asked to include them.
        ingest_kwargs.setdefault("only_canonical", not include_duplicates)
        return ingest_openkritt_findings(rows, **ingest_kwargs)

    # --- write: drive a scan (operator action) ------------------------------

    def create_scan(self, payload: dict) -> dict:
        """POST /api/scans — queue an open·kritt research run. Operator-initiated."""
        return self._post("/api/scans", payload)

    # --- plumbing -----------------------------------------------------------

    def _get(self, path: str, *, params=None):
        resp = self._client.get(self._base + path, params=params, headers=self._headers)
        resp.raise_for_status()
        return resp.json()

    def _post(self, path: str, json_body):
        resp = self._client.post(self._base + path, json=json_body, headers=self._headers)
        resp.raise_for_status()
        return resp.json()

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
