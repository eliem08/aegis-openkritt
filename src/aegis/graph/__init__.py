"""Asset/observation graph and normalization (Phase 2).

Observations are immutable and keep every source; assets are the deduplicated
view derived from them. Snapshots capture what a scan saw, and diffs never turn
a partial scan into a removal.
"""

from .model import (
    Asset,
    AssetKind,
    AssetSnapshot,
    DiffStatus,
    Observation,
    SnapshotDiff,
    canonical_url,
    confirmed_removals,
    diff_snapshots,
    domain_key,
    new_observation,
    new_snapshot,
    normalize_hostname,
    parameter_key,
    route_key,
    service_key,
    technology_key,
    url_key,
)
from .normalizer import (
    OUT_OF_SCOPE,
    SENSITIVE,
    UNPARSEABLE,
    UNSUPPORTED,
    WILDCARD,
    NormalizationResult,
    Normalizer,
    Rejection,
    merge_into,
)

__all__ = [
    "Asset",
    "AssetKind",
    "AssetSnapshot",
    "DiffStatus",
    "Observation",
    "SnapshotDiff",
    "canonical_url",
    "confirmed_removals",
    "diff_snapshots",
    "domain_key",
    "new_observation",
    "new_snapshot",
    "normalize_hostname",
    "parameter_key",
    "route_key",
    "service_key",
    "technology_key",
    "url_key",
    "NormalizationResult",
    "Normalizer",
    "Rejection",
    "merge_into",
    "OUT_OF_SCOPE",
    "WILDCARD",
    "UNPARSEABLE",
    "UNSUPPORTED",
    "SENSITIVE",
]
