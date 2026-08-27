"""Per-asset-type arsenal capability: routing, guardrails, and lane execution.

The arsenal historically executed one asset class well (source code). This package
adds first-class handling for the remaining bounty asset types the operator works —
network ranges and hosts, APIs, cloud accounts, executables, smart contracts, AI
models, and unstructured "Other" entries — behind a single guarded entry point,
``aegis.arsenal.assets.hunt.run_hunt``.

Mobile and hardware are deliberately out of charter and raise
``UnsupportedAssetType`` rather than degrading into a technique that pretends.
"""

from .context import Identity, LaneContext
from .hunt import HuntRefused, HuntReport, render_markdown, run_hunt, write_report
from .results import Observation, TechniqueResult
from .scope import (
    OutOfScopeError,
    ScopeAllowlist,
    ScopeFileError,
    build_allowlist,
    load_allowlist,
)
from .session import HuntSession, InteractionRequired, RateLimit, StateChangeRefused
from .tooling import ToolAvailability, ToolLocation, ToolResolver
from .types import (
    ArsenalAssetType,
    Technique,
    UnsupportedAssetType,
    classify_identifier,
    coverage_matrix,
    parse_asset_type,
    techniques_for,
)

__all__ = [
    "ArsenalAssetType",
    "HuntRefused",
    "HuntReport",
    "HuntSession",
    "Identity",
    "InteractionRequired",
    "LaneContext",
    "Observation",
    "OutOfScopeError",
    "RateLimit",
    "ScopeAllowlist",
    "ScopeFileError",
    "StateChangeRefused",
    "Technique",
    "TechniqueResult",
    "ToolAvailability",
    "ToolLocation",
    "ToolResolver",
    "UnsupportedAssetType",
    "build_allowlist",
    "classify_identifier",
    "coverage_matrix",
    "load_allowlist",
    "parse_asset_type",
    "render_markdown",
    "run_hunt",
    "techniques_for",
    "write_report",
]
