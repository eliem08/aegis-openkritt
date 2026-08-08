"""Additional safe firmware methods owned by the authoritative asset planner."""

from __future__ import annotations

from .asset_deep_capabilities import DeepScannerMethod
from .asset_capabilities import Requirement


SAFE_ROOTFS_EXTRACT = DeepScannerMethod(
    "aegis-safe-rootfs-extract",
    "bounded-archive-extraction",
    requirement=Requirement.FIRMWARE,
    local_only=True,
    output="directory",
    purpose=(
        "extract only bounded ZIP/TAR-family firmware containers without links, devices, "
        "path traversal, archive permissions, or code execution"
    ),
)
