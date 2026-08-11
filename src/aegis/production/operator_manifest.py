"""Immutable, hash-chained operator run manifests and event persistence."""

from __future__ import annotations

import json
import os
import secrets
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
from enum import Enum
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping


class OperatorRunError(RuntimeError):
    pass


class RunMode(str, Enum):
    DRY_RUN = "dry_run"
    LIVE_CANARY = "live_canary"


class RunStatus(str, Enum):
    CREATED = "created"
    SCOPE_REFRESHED = "scope_refreshed"
    AUTHORIZED = "authorized"
    PLANNED = "planned"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    REVOKED = "revoked"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canonical(document: Mapping[str, Any]) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def document_digest(document: Mapping[str, Any]) -> str:
    return sha256(_canonical(document)).hexdigest()


@dataclass(frozen=True, slots=True)
class RunBudgets:
    max_requests: int
    requests_per_second: float
    max_cost_usd: float
    max_concurrent_sessions: int = 1

    def __post_init__(self) -> None:
        if (
            self.max_requests <= 0
            or self.requests_per_second <= 0
            or self.max_cost_usd < 0
            or self.max_concurrent_sessions <= 0
        ):
            raise ValueError("operator budgets must be positive and cost cannot be negative")


@dataclass(frozen=True, slots=True)
class OperatorRunManifest:
    schema_version: int
    run_id: str
    mode: RunMode
    created_at: str
    operator_id: str
    program_handle: str
    program_source: str
    selected_assets: tuple[str, ...]
    canary_asset: str | None
    controlled_identity_refs: tuple[str, ...]
    policy_snapshot: Mapping[str, Any]
    policy_digest: str
    scope_snapshot: Mapping[str, Any]
    scope_digest: str
    operator_selections: Mapping[str, Any]
    budgets: RunBudgets
    authorization: Mapping[str, Any]
    execution_grants: tuple[Mapping[str, Any], ...] = ()
    mission_ids: tuple[str, ...] = ()
    evidence_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.schema_version != 1 or not all((self.run_id, self.operator_id, self.program_handle)):
            raise ValueError("manifest identity is incomplete")
        if not self.selected_assets:
            raise ValueError("operator must explicitly select at least one asset")
        if self.mode is RunMode.LIVE_CANARY:
            if len(self.selected_assets) != 1 or self.canary_asset != self.selected_assets[0]:
                raise ValueError("live canary requires exactly one explicitly selected canary asset")
        if self.policy_digest != document_digest(self.policy_snapshot):
            raise ValueError("policy snapshot digest mismatch")
        if self.scope_digest != document_digest(self.scope_snapshot):
            raise ValueError("scope snapshot digest mismatch")

    def document(self) -> dict[str, Any]:
        value = asdict(self)
        value["mode"] = self.mode.value
        return value


@dataclass(frozen=True, slots=True)
class RunEvent:
    sequence: int
    observed_at: str
    event_type: str
    status: RunStatus
    detail: Mapping[str, Any] = field(default_factory=dict)
    previous_digest: str = ""
    digest: str = ""

    def unsigned_document(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "observed_at": self.observed_at,
            "event_type": self.event_type,
            "status": self.status.value,
            "detail": dict(self.detail),
            "previous_digest": self.previous_digest,
        }

    def document(self) -> dict[str, Any]:
        return self.unsigned_document() | {"digest": self.digest}


class ImmutableRunStore:
    """Create-only files with a verified event hash chain; no in-place run mutation."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)

    def create(self, manifest: OperatorRunManifest) -> str:
        run_dir = self.root / manifest.run_id
        try:
            run_dir.mkdir(parents=True, exist_ok=False)
        except FileExistsError as exc:
            raise OperatorRunError(f"run {manifest.run_id} already exists") from exc
        (run_dir / "events").mkdir()
        document = manifest.document()
        digest = document_digest(document)
        self._exclusive_json(run_dir / "manifest.json", document | {"manifest_digest": digest})
        self.append_event(
            manifest.run_id, "run_created", RunStatus.CREATED,
            {"manifest_digest": digest, "mode": manifest.mode.value},
        )
        return digest

    def append_event(
        self,
        run_id: str,
        event_type: str,
        status: RunStatus,
        detail: Mapping[str, Any] | None = None,
    ) -> RunEvent:
        events = self.events(run_id)
        sequence = len(events) + 1
        previous = events[-1].digest if events else ""
        draft = RunEvent(sequence, _now(), event_type, status, dict(detail or {}), previous)
        event = replace(draft, digest=document_digest(draft.unsigned_document()))
        path = self.root / run_id / "events" / f"{sequence:08d}-{event.digest}.json"
        self._exclusive_json(path, event.document())
        return event

    def events(self, run_id: str) -> tuple[RunEvent, ...]:
        directory = self.root / run_id / "events"
        if not directory.is_dir():
            if (self.root / run_id).exists():
                raise OperatorRunError("run event directory is missing")
            return ()
        output: list[RunEvent] = []
        previous = ""
        for path in sorted(directory.glob("*.json")):
            value = json.loads(path.read_text(encoding="utf-8"))
            digest = str(value.pop("digest", ""))
            if digest != document_digest(value) or value.get("previous_digest", "") != previous:
                raise OperatorRunError(f"event chain verification failed at {path.name}")
            event = RunEvent(
                sequence=int(value["sequence"]), observed_at=str(value["observed_at"]),
                event_type=str(value["event_type"]), status=RunStatus(value["status"]),
                detail=dict(value.get("detail") or {}),
                previous_digest=str(value.get("previous_digest") or ""), digest=digest,
            )
            if event.sequence != len(output) + 1:
                raise OperatorRunError("event sequence is not contiguous")
            output.append(event)
            previous = digest
        return tuple(output)

    def verify(self, run_id: str) -> dict[str, Any]:
        path = self.root / run_id / "manifest.json"
        document = json.loads(path.read_text(encoding="utf-8"))
        digest = str(document.pop("manifest_digest", ""))
        if digest != document_digest(document):
            raise OperatorRunError("manifest digest verification failed")
        events = self.events(run_id)
        return {
            "run_id": run_id,
            "manifest_digest": digest,
            "events": len(events),
            "last_status": events[-1].status.value if events else RunStatus.CREATED.value,
            "last_event_digest": events[-1].digest if events else "",
        }

    def persist_evidence(self, run_id: str, document: Mapping[str, Any]) -> tuple[str, str]:
        """Persist one immutable evidence document and return its path and digest."""
        self.verify(run_id)
        digest = document_digest(document)
        relative = f"evidence/{digest}.json"
        self._exclusive_json(self.root / run_id / relative, document | {"evidence_digest": digest})
        return relative, digest

    def load_manifest(self, run_id: str) -> OperatorRunManifest:
        """Verify and rehydrate the immutable manifest for restart-safe continuation."""
        self.verify(run_id)
        value = json.loads((self.root / run_id / "manifest.json").read_text(encoding="utf-8"))
        value.pop("manifest_digest", None)
        value["mode"] = RunMode(value["mode"])
        value["selected_assets"] = tuple(value.get("selected_assets") or ())
        value["controlled_identity_refs"] = tuple(value.get("controlled_identity_refs") or ())
        value["execution_grants"] = tuple(value.get("execution_grants") or ())
        value["mission_ids"] = tuple(value.get("mission_ids") or ())
        value["evidence_refs"] = tuple(value.get("evidence_refs") or ())
        value["budgets"] = RunBudgets(**value["budgets"])
        return OperatorRunManifest(**value)

    @staticmethod
    def new_run_id() -> str:
        return f"run-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{secrets.token_hex(6)}"

    @staticmethod
    def _exclusive_json(path: Path, document: Mapping[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        descriptor = os.open(path, flags, 0o600)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                json.dump(document, stream, indent=2, sort_keys=True)
                stream.write("\n")
        except Exception:
            try:
                os.close(descriptor)
            except OSError:
                pass
            raise
