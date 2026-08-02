"""Ingestion sources — turn real bug-bounty programs into scope + rules (§4).

Discovery here is passive and read-only. It yields a
:class:`~aegis.ingest.program.ProgramRules` (scope, out-of-scope, and parsed
automation/AI/rate constraints) and an *unsigned* authorization draft. Active
testing still requires the control plane to sign that authorization and a human
to confirm the program's rules.
"""

from .program import (
    AssetType,
    ProgramRules,
    ScopeAsset,
    classify_asset_type,
    identifier_to_host,
    parse_policy_constraints,
)

__all__ = [
    "AssetType",
    "ProgramRules",
    "ScopeAsset",
    "classify_asset_type",
    "identifier_to_host",
    "parse_policy_constraints",
]

# HackerOne connector needs httpx (api/dev extras). Keep core importable without it.
try:
    from .hackerone import (
        HackerOneAuthError,
        HackerOneClient,
        map_program,
    )

    __all__ += ["HackerOneAuthError", "HackerOneClient", "map_program"]
except ModuleNotFoundError:  # pragma: no cover - httpx not installed
    pass
