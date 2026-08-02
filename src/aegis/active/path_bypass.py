"""Path-normalization allowlist-bypass detection (report-corpus driven).

A recurring gateway bug: the allowlist/auth check runs against the *raw* request
path, which is normalized only afterward — so an obfuscated path (``/./metrics``,
``/metrics/``, ``/metrics%2f``, ``/api/./admin``) slips past the check and then
resolves to the protected route. This probes a *gated* route (401/403) with benign
normalization variants and flags any that reach the application.

Transport-agnostic and safe: it issues only benign GETs of path variants (send
them with path-as-is), never a payload; ``probe(path)`` returns the status code.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

GATED_STATUSES = frozenset({401, 403})
_ABSENT = frozenset({404, 410})


@dataclass(frozen=True)
class PathBypassFinding:
    path: str
    variant: str
    baseline_status: int
    variant_status: int
    confidence: float
    verified: bool = False


def normalization_variants(path: str) -> list[str]:
    base = "/" + (path or "").strip().lstrip("/")
    base = base.rstrip("/") or "/"
    segs = base.split("/")
    last = segs[-1]
    parent = "/".join(segs[:-1])
    variants = {
        base + "/",                          # trailing slash
        base + "/.",                         # trailing /.
        "/." + base,                         # leading /./
        f"{parent}/./{last}" if last else base,   # /a/./b
        base.replace("/", "//", 1),          # double slash near the root
        base + "%2f",                        # encoded trailing slash
        base + "..;/",                       # matrix-parameter trick
        base + ";",                          # matrix parameter
    }
    if base.lower() != base.upper():
        variants.add(base.upper())           # case variation
    variants.discard(base)
    return sorted(v for v in variants if v and v != base)


def analyze_path_normalization(probe: Callable[[str], int], path: str) -> list[PathBypassFinding]:
    baseline = probe(path)
    if baseline not in GATED_STATUSES:
        return []                            # no gate here — nothing to bypass
    findings: list[PathBypassFinding] = []
    for variant in normalization_variants(path):
        status = probe(variant)
        if status in _ABSENT or status == baseline:
            continue                         # route absent, or the gate held identically
        if 200 <= status < 300:
            confidence = 0.9                 # full bypass — reached the resource
        elif status in (400, 422, 500, 502, 503) or (baseline == 403 and status == 401):
            confidence = 0.65                # reached the app / a deeper auth layer
        else:
            continue                         # a different but not-less-restrictive gate
        findings.append(PathBypassFinding(path, variant, baseline, status, confidence))
    return findings
