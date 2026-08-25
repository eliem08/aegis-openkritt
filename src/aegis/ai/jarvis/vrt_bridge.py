"""Bridge the Bugcrowd VRT taxonomy to concrete hunt methods.

`aegis.policy.vrt_coverage` says *which lane* a VRT class belongs to; this bridge
says *how to hunt it* by mapping each VRT category (and cross-cutting specific
names) to the `UNIVERSAL_FAMILIES` weakness catalog — each family carries the CWEs,
attack surfaces, and validation method. Together they let Jarvis take ANY VRT row
and produce a hunt plan: the lane (source-web / crypto / live / off) plus the
weakness family(ies) whose method it should run.

Layering: this lives in the jarvis layer because it joins a policy module
(vrt_coverage) with a jarvis module (weakness_catalog) — the allowed direction.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from aegis.policy.vrt_coverage import HuntLane, classify

from .weakness_catalog import UNIVERSAL_FAMILIES, WeaknessFamily

__all__ = ["VrtHuntPlan", "hunt_plan_for_vrt", "families_for_vrt"]

_BY_ID = {f.family_id: f for f in UNIVERSAL_FAMILIES}


# VRT top-level category (lowercased) -> weakness family ids that hunt it.
_CATEGORY_FAMILIES: dict[str, tuple[str, ...]] = {
    "ai application security": ("injection", "authz", "privacy", "client", "resource"),
    "broken access control (bac)": ("authz", "binding", "workflow"),
    "broken authentication and session management": ("authn", "oauth"),
    "server-side injection": ("injection", "file", "xml"),
    "cross-site scripting (xss)": ("client",),
    "cross-site request forgery (csrf)": ("csrf_cors",),
    "sensitive data exposure": ("privacy", "debug", "crypto"),
    "server security misconfiguration": ("misconfig", "ssrf", "proxy", "redirect", "headers", "api", "file"),
    "cryptographic weakness": ("crypto",),
    "unvalidated redirects and forwards": ("redirect",),
    "client-side injection": ("client",),
    "using components with known vulnerabilities": ("supply",),
    "cloud security": ("cloud", "misconfig"),
    "insecure os/firmware": ("injection", "crypto", "privacy"),
    # crypto lanes: no web-family method — handled by the Solidity static pipeline
    "smart contract misconfiguration": (),
    "decentralized application misconfiguration": (),
    "blockchain infrastructure misconfiguration": (),
    "zero knowledge security misconfiguration": (),
    "protocol specific misconfiguration": (),
}

# Cross-cutting specific-name -> family id (checked before the category default).
_SPECIFIC_FAMILY: tuple[tuple[str, str], ...] = (
    ("command injection", "injection"),
    ("sql injection", "injection"),
    ("server-side template injection", "injection"),
    ("xml external entity", "xml"),
    ("file inclusion", "file"),
    ("path traversal", "file"),
    ("unsafe file upload", "file"),
    ("server-side request forgery", "ssrf"),
    ("http request smuggling", "proxy"),
    ("cache poisoning", "proxy"),
    ("cache deception", "proxy"),
    ("deserialization", "deserialize"),
    ("insecure direct object references", "authz"),
    ("privilege escalation", "authz"),
    ("mass assignment", "binding"),
    ("prototype pollution", "prototype"),
    ("race condition", "race"),
    ("open redirect", "redirect"),
    ("oauth misconfiguration", "oauth"),
    ("software package takeover", "supply"),
    ("outdated software version", "supply"),
    ("webhook", "webhook"),
)


@dataclass(frozen=True)
class VrtHuntPlan:
    category: str
    specific: str | None
    lane: HuntLane
    pursuable: bool
    families: tuple[WeaknessFamily, ...] = field(default_factory=tuple)
    note: str = ""

    @property
    def family_ids(self) -> tuple[str, ...]:
        return tuple(f.family_id for f in self.families)

    def __str__(self) -> str:  # pragma: no cover
        fam = ",".join(self.family_ids) or "-"
        return f"[{self.lane.value}] {self.category} -> families({fam})"


def _norm(s: str | None) -> str:
    return (s or "").strip().lower()


def families_for_vrt(category: str, specific: str | None = None) -> tuple[WeaknessFamily, ...]:
    """Resolve the weakness families whose method hunts this VRT class."""
    spec = _norm(specific)
    cat = _norm(category)

    ids: list[str] = []
    for needle, fam_id in _SPECIFIC_FAMILY:
        if needle in spec or needle in cat:
            ids.append(fam_id)
    if not ids:
        ids = list(_CATEGORY_FAMILIES.get(cat, ()))

    # de-dup, preserve order, resolve to real family objects
    seen: dict[str, None] = {}
    out: list[WeaknessFamily] = []
    for fid in ids:
        if fid in seen:
            continue
        seen[fid] = None
        fam = _BY_ID.get(fid)
        if fam is not None:
            out.append(fam)
    return tuple(out)


def hunt_plan_for_vrt(category: str, specific: str | None = None) -> VrtHuntPlan:
    """Full plan for a VRT class: lane (pursue/gate) + weakness families (method)."""
    cov = classify(category, specific)
    families = families_for_vrt(category, specific) if cov.pursuable else ()

    note = cov.reason
    if cov.lane is HuntLane.SOURCE_CRYPTO and not families:
        note = "crypto lane — hunt via the Solidity static pipeline (contract_static_pipeline), not a web family"
    elif cov.pursuable and not families:
        note = f"{cov.reason}; no specific family mapped — route to a general source-review agent"

    return VrtHuntPlan(
        category=category, specific=specific, lane=cov.lane,
        pursuable=cov.pursuable, families=families, note=note,
    )
