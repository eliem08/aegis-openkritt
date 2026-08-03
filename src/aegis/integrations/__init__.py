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

__all__ = [
    "OPENKRITT_FINDING_KEYS",
    "ingest_openkritt_findings",
    "to_openkritt_output_format",
]
