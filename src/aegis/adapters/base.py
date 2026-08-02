"""Shared plumbing for pinned third-party tool adapters (Phase 2).

Every discovery tool speaks JSON Lines, so the parse/terminal/diagnostic logic is
identical; only the command construction and the record→event mapping differ.
Subclasses implement :meth:`build_command` and :meth:`map_record`.

Three disciplines live here because getting them wrong in one adapter is as bad
as getting them wrong in all five:

* **Binaries are pinned and checksum-verified.** A declared digest that does not
  match the resolved binary is a hard failure — never a warning. A tool whose
  digest has not been pinned yet refuses to run unless explicitly permitted.
* **Output-schema mismatches block the adapter version.** A record the pinned
  schema does not describe becomes a *blocking* diagnostic, which quarantines the
  task's output rather than letting a half-understood record become an asset.
* **Errors carry distinct codes** so partial coverage is visible and never
  reported as complete (Phase 2 §Error handling).
"""

from __future__ import annotations

import json
import os
import shutil

from aegis.process import verify_binary

from .contract import (
    AdapterEvent,
    AdapterManifest,
    EventKind,
    ExecutionEnvelope,
    event_from,
    validate_against_manifest,
)

# Distinct error codes (Phase 2 §Error handling).
PROVIDER_ERROR = "provider_error"
TARGET_UNREACHABLE = "target_unreachable"
PARSER_INCOMPATIBLE = "parser_incompatible"
QUOTA_EXHAUSTED = "quota_exhausted"
GATEWAY_BLOCKED = "gateway_blocked"


class ToolUnavailable(RuntimeError):
    """The pinned binary is missing, unpinned, or fails checksum verification."""


class SchemaMismatch(ValueError):
    """A record does not match the adapter's pinned output schema."""


class JsonLinesAdapter:
    """Base for adapters over a pinned JSONL-emitting binary."""

    manifest: AdapterManifest
    tool_name: str = ""
    #: Set to allow running before a digest is pinned (tests/local dev only).
    allow_unpinned: bool = False

    def __init__(self, executable: str | None = None, *, allow_unpinned: bool | None = None) -> None:
        self._executable = executable
        if allow_unpinned is not None:
            self.allow_unpinned = allow_unpinned

    # -- contract ----------------------------------------------------------

    def validate_envelope(self, envelope: ExecutionEnvelope) -> None:
        validate_against_manifest(envelope, self.manifest)

    def parse_line(self, line: str, envelope: ExecutionEnvelope) -> AdapterEvent | None:
        line = line.strip()
        if not line:
            return None
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            return self._diagnostic(envelope, PARSER_INCOMPATIBLE, "unparseable output line",
                                    raw=line[:200], blocking=True)
        if not isinstance(record, dict):
            return self._diagnostic(envelope, PARSER_INCOMPATIBLE, "output line is not an object",
                                    raw=line[:200], blocking=True)
        try:
            mapped = self.map_record(record, envelope)
        except SchemaMismatch as exc:
            # Blocking: this adapter version's output is not understood, so the
            # task is quarantined instead of half-parsed into the asset graph.
            return self._diagnostic(envelope, PARSER_INCOMPATIBLE, str(exc),
                                    raw=line[:200], blocking=True)
        if mapped is None:
            return None
        kind, data, confidence = mapped
        return event_from(kind, envelope, data, source=self.manifest.name, confidence=confidence)

    def interpret_result(self, result, envelope: ExecutionEnvelope) -> AdapterEvent:
        status = "succeeded" if getattr(result, "ok", False) else getattr(result.outcome, "value", "failed")
        return event_from(
            EventKind.TERMINAL, envelope,
            {"status": status, "exit_code": result.exit_code, "truncated": result.truncated},
            source=self.manifest.name,
        )

    # -- subclass hooks ----------------------------------------------------

    def build_command(self, envelope: ExecutionEnvelope) -> list[str]:
        raise NotImplementedError

    def map_record(self, record: dict, envelope: ExecutionEnvelope):
        """Return ``(EventKind, data, confidence)``, or None to ignore the record.

        Raise :class:`SchemaMismatch` when the record cannot be trusted.
        """
        raise NotImplementedError

    # -- helpers -----------------------------------------------------------

    def resolve_executable(self) -> str:
        """Locate the pinned binary and verify its checksum (fail closed)."""
        path = self._executable or os.environ.get(self._env_var()) or shutil.which(self.tool_name)
        if not path:
            raise ToolUnavailable(f"{self.tool_name!r} not found; set {self._env_var()}")
        digest = self.manifest.executable_digest
        if not digest:
            if not self.allow_unpinned:
                raise ToolUnavailable(
                    f"{self.tool_name!r} has no pinned checksum; refusing to run "
                    "(pin the release digest before distribution)"
                )
            return path
        verify_binary(path, digest)  # raises BinaryVerificationError on mismatch
        return path

    def _env_var(self) -> str:
        return f"AEGIS_TOOL_{self.tool_name.upper().replace('-', '_')}"

    def _diagnostic(self, envelope, code: str, message: str, *, blocking: bool = False,
                    **extra) -> AdapterEvent:
        data = {"code": code, "message": message, "blocking": blocking}
        data.update(extra)
        return event_from(EventKind.DIAGNOSTIC, envelope, data,
                          source=self.manifest.name, confidence=0.0)


def in_parent_scope(host: str, parent: str) -> bool:
    """True when ``host`` is the parent domain or a subdomain of it.

    Subfinder-style enumeration must never return outside its immutable parent
    domain, so this is checked before an event is ever emitted.
    """
    host = (host or "").strip().lower().rstrip(".")
    parent = (parent or "").strip().lower().rstrip(".")
    if not host or not parent:
        return False
    return host == parent or host.endswith("." + parent)
