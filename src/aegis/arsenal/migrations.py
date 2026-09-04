"""Formal runtime migration and deduplication registry for Aegis Arsenal.

When an arsenal runtime is superseded, unified, or formally migrated to maintain
denominator honesty without silent deletion or duplicate counting.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True, slots=True)
class RuntimeMigration:
    old_runtime_id: str
    replacement_runtime_id: str
    old_semantics: str
    replacement_semantics: str
    reason: str
    source_registry_provenance: str
    capabilities_affected: tuple[str, ...]
    coverage_interpretation: str
    migration_date: str
    lifecycle_state: str = "MIGRATED"
    migration_target: str = ""
    migration_reason: str = ""
    migration_source: str = ""
    migration_timestamp: str = ""
    source_commit: str = ""

    def __post_init__(self) -> None:
        if not self.migration_target:
            object.__setattr__(self, "migration_target", self.replacement_runtime_id)
        if not self.migration_reason:
            object.__setattr__(self, "migration_reason", self.reason)
        if not self.migration_source:
            object.__setattr__(self, "migration_source", self.source_registry_provenance)
        if not self.migration_timestamp:
            object.__setattr__(self, "migration_timestamp", self.migration_date)
        if not self.source_commit:
            object.__setattr__(self, "source_commit", "2c93c3017a4ea0134812fbb1c7a8769c8e11aee6")

    def document(self) -> dict[str, Any]:
        return asdict(self)


RUNTIME_MIGRATIONS: tuple[RuntimeMigration, ...] = (
    RuntimeMigration(
        old_runtime_id="firmadyne/qemu-lab",
        replacement_runtime_id="firmae/qemu-lab",
        old_semantics="isolated firmware emulation fallback for supported Linux-based images",
        replacement_semantics=(
            "isolated IoT firmware emulation for dynamic analysis (FirmAE embeds and "
            "automates the Firmadyne extraction, QEMU kernel emulation, and network service inspection pipeline)"
        ),
        reason=(
            "FirmAE is the direct automated successor that wraps and integrates Firmadyne core "
            "emulation components. Registering both as distinct external runtimes was an accidental double-counting "
            "of the same underlying QEMU firmware emulation engine."
        ),
        source_registry_provenance="src/aegis/ai/jarvis/asset_deep_capabilities.py:FIRMADYNE",
        capabilities_affected=("asset:firmadyne/firmware-emulation-fallback",),
        coverage_interpretation="migrated into asset:firmae/firmware-emulation; verified through unified FirmAE runner",
        migration_date="2026-09-03",
    ),
    RuntimeMigration(
        old_runtime_id="class-dump/macos-cli",
        replacement_runtime_id="otool/macos-cli",
        old_semantics="Objective-C class interface recovery from Mach-O binaries",
        replacement_semantics=(
            "Objective-C class interface, protocol, and load command extraction via otool (-ov / -l) "
            "on modern macOS Darwin runtimes"
        ),
        reason=(
            "Original Steve Nygard class-dump v3.5 is 32/early-64-bit and obsolete on modern macOS "
            "Darwin arm64/x86_64 runtimes. Modern macOS Xcode otool natively provides complete Objective-C "
            "class, method, and protocol recovery through `otool -ov`."
        ),
        source_registry_provenance="src/aegis/ai/jarvis/asset_deep_capabilities.py:CLASS_DUMP",
        capabilities_affected=("asset:class-dump/objective-c-interface-recovery",),
        coverage_interpretation="migrated into asset:otool/ios-macos-load-command-analysis; verified through otool Darwin runner",
        migration_date="2026-09-03",
    ),
)


def write_runtime_migrations(path: str | Path) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps({
            "schema_version": 1,
            "migrations": [item.document() for item in RUNTIME_MIGRATIONS],
        }, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


__all__ = ["RUNTIME_MIGRATIONS", "RuntimeMigration", "write_runtime_migrations"]
