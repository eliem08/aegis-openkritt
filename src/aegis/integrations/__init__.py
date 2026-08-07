"""Arm's-length integrations with separate third-party services.

Integrations here talk to *other* programs over their public data contracts
(files, HTTP, finding exports) — they never vendor that program's source into
this tree. This keeps Aegis's own license clean even when the other side is
strongly copyleft: see :mod:`aegis.integrations.openkritt`.
"""

from .openkritt import (
    OPENKRITT_FINDING_KEYS,
    ingest_openkritt_findings,
    to_openkritt_output_format,
)
from .openkritt_client import OpenKrittClient
from .repo_pipeline import (
    DEEPSEEK_MODEL,
    PipelineError,
    PipelineResult,
    RepoTarget,
    ScanTemplate,
    console_for_scans,
    discover_scan_template,
    launch_repo_scans,
    repos_in_scope,
    run_repo_pipeline,
    with_deepseek_fallback,
)

__all__ = [
    "DEEPSEEK_MODEL",
    "OPENKRITT_FINDING_KEYS",
    "OpenKrittClient",
    "PipelineError",
    "PipelineResult",
    "RepoTarget",
    "ScanTemplate",
    "console_for_scans",
    "discover_scan_template",
    "ingest_openkritt_findings",
    "launch_repo_scans",
    "repos_in_scope",
    "run_repo_pipeline",
    "to_openkritt_output_format",
    "with_deepseek_fallback",
]
