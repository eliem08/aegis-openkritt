"""A fake discovery adapter — exercises the contract end-to-end (Phase 1).

Translates an :class:`ExecutionEnvelope` into a command that runs the bundled
fake tool, parses its JSONL output into typed events (malformed lines become
diagnostics, never crashes), and interprets the terminal result. It receives no
repository objects and puts no secrets in argv.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys

from .contract import (
    AdapterEvent,
    AdapterManifest,
    CapabilityTier,
    EventKind,
    ExecutionEnvelope,
    event_from,
    validate_against_manifest,
)

_FAKETOOL = os.path.join(os.path.dirname(__file__), "_faketool.py")
# Digest of the fake tool source, so envelope/manifest checksum matching is real.
with open(_FAKETOOL, "rb") as _fh:
    _FAKETOOL_DIGEST = hashlib.sha256(_fh.read()).hexdigest()

FAKE_MANIFEST = AdapterManifest(
    name="fake-discovery",
    version="1.0.0",
    executable_digest=_FAKETOOL_DIGEST,
    license="MIT",
    capability_tier=CapabilityTier.PASSIVE_DISCOVERY.value,
    input_schema_version=1,
    output_schema_version=1,
    network_profile="passive-provider",
)


class FakeDiscoveryAdapter:
    manifest = FAKE_MANIFEST

    def validate_envelope(self, envelope: ExecutionEnvelope) -> None:
        validate_against_manifest(envelope, self.manifest)

    def build_command(self, envelope: ExecutionEnvelope) -> list[str]:
        # Target only; credentials stay as references (never argv), limits bound results.
        max_results = envelope.limits.max_events or 100
        return [sys.executable, _FAKETOOL, envelope.target, str(max_results)]

    def parse_line(self, line: str, envelope: ExecutionEnvelope) -> AdapterEvent | None:
        line = line.strip()
        if not line:
            return None
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            return event_from(
                EventKind.DIAGNOSTIC, envelope, {"message": "unparseable output line", "raw": line[:200]},
                source=self.manifest.name, confidence=0.0,
            )
        raw_kind = obj.pop("kind", "diagnostic")
        try:
            kind = EventKind(raw_kind)
        except ValueError:
            kind = EventKind.DIAGNOSTIC
            obj = {"message": f"unknown event kind {raw_kind!r}", "data": obj}
        return event_from(kind, envelope, obj, source=self.manifest.name)

    def interpret_result(self, result, envelope: ExecutionEnvelope) -> AdapterEvent:
        status = "succeeded" if getattr(result, "ok", False) else getattr(result.outcome, "value", "failed")
        return event_from(
            EventKind.TERMINAL, envelope,
            {"status": status, "exit_code": result.exit_code, "truncated": result.truncated},
            source=self.manifest.name,
        )
