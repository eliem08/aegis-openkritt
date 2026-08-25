"""Program-policy eligibility verification — the scope-lesson gate.

`ScopeGuard` (see :mod:`aegis.policy.scope`) answers a *network* question — "may a
packet reach this host?". This module answers the *economic / authorization*
question that must be settled BEFORE a hunt (source or live) spends any effort:

    "Is this target actually eligible on the program's CURRENT policy —
     in scope, not excluded, paying cash, and not suspended?"

It exists because three costly misses each came from trusting a stale asset list
instead of reading the whole policy:

  * **pipelinewise** — the repo was silently *moved to out-of-scope*; the stale
    snapshot still listed it. → we must consult the exclusion list, not just the
    in-scope list.
  * **Nextcloud** — the paid program was *suspended* ("no monetary rewards …
    regardless of severity"); the historical $ ranges were still shown. → we must
    detect suspension in the policy text, not infer "pays" from a reward ceiling.
  * **Netflix** — `Netflix/dispatch` appeared on the scope page, but inside the
    *"Out-of-Scope (Please Read)"* section; only Zuul/Atlas/Spectator were
    reward-eligible. → an asset appearing in the policy text is not the same as
    being *eligible*; exclusions win.

The gate is **fail-closed**: anything it cannot positively establish as eligible
is reported as ``NOT_ELIGIBLE`` / ``UNKNOWN`` rather than passed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum

from aegis.policy.scope import normalize_host

__all__ = [
    "Eligibility",
    "EligibilityResult",
    "verify_target",
    "canonical_repo",
]


class Eligibility(str, Enum):
    """Verdict for a (program, target) pair, most-eligible first."""

    SUBMITTABLE = "submittable"      # in scope, pays cash, not suspended, asset reward-eligible
    RECON_ONLY = "recon_only"        # in scope but recon-tagged / library bug not rewarded
    CREDIT_ONLY = "credit_only"      # valid + accepted, but VDP / suspended → recognition/CVE, no cash
    NOT_ELIGIBLE = "not_eligible"    # out of scope, excluded, or inactive
    UNKNOWN = "unknown"              # insufficient data — treat as not-eligible (fail closed)


# --- policy-text signals -----------------------------------------------------

# Paid program is currently suspended / recognition-only.
_SUSPENSION_MARKERS = (
    r"no monetary bounties",
    r"does not offer (?:monetary|financial|paid)",
    r"no financial rewards",
    r"suspended (?:our |the )?(?:paid |bounty )?(?:bounty )?program",
    r"temporarily suspended",
    r"recognition only",
    r"no (?:cash|bounty) (?:reward|payout)",
)

# GitHub scope that is recon-only (hunt for leaked secrets, not source vulns) or
# where third-party / library source bugs are explicitly not rewarded.
_RECON_MARKERS = (
    r"\brecon\b",
    r"third[- ]party (?:library|bugs?).{0,40}(?:not|won't|will not) be rewarded",
    r"library bugs.{0,40}not (?:rewarded|eligible)",
    r"leaked (?:secret|credential)",
)


def _text_blob(program: dict) -> str:
    parts = [
        program.get("scope_text") or "",
        program.get("rules") or "",
        program.get("notes") or "",
    ]
    return "\n".join(parts).lower()


def _matches_any(blob: str, patterns) -> str | None:
    for pat in patterns:
        if re.search(pat, blob, re.IGNORECASE):
            return pat
    return None


# --- target canonicalisation -------------------------------------------------

_GITHUB_RE = re.compile(r"github\.com[/:]+([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?/?$", re.IGNORECASE)
_OWNER_REPO_RE = re.compile(r"^([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)$")


def canonical_repo(value: str) -> str | None:
    """Return a lowercased ``owner/repo`` if *value* denotes a GitHub repo, else None.

    Accepts ``https://github.com/Owner/Repo``, ``github.com/Owner/Repo``,
    ``git@github.com:Owner/Repo.git``, or a bare ``Owner/Repo``.
    """
    if not value:
        return None
    v = value.strip().rstrip("/")
    m = _GITHUB_RE.search(v)
    if m:
        return m.group(1).lower().removesuffix(".git")
    # bare owner/repo (but not a path with more than one slash, and not a host)
    if "." not in v.split("/")[0] and _OWNER_REPO_RE.match(v):
        return v.lower()
    return None


def _target_matches_entry(target: str, entry: str) -> bool:
    """True if *entry* (a scope/exclusion line) refers to the same asset as *target*.

    Handles both GitHub repos (owner/repo, org wildcards like ``matomo-org/*`` or a
    bare org) and hostnames (exact + ``*.`` wildcards).
    """
    if not entry:
        return False
    entry = entry.strip()

    t_repo = canonical_repo(target)
    e_repo = canonical_repo(entry)
    if t_repo:
        if e_repo and e_repo == t_repo:
            return True
        # org-level entry: "owner/*", bare "owner", or a github.com/owner URL
        e_low = entry.lower().rstrip("/")
        owner = t_repo.split("/", 1)[0]
        for form in (f"{owner}/*", owner, f"github.com/{owner}", f"github.com/{owner}/*",
                     f"https://github.com/{owner}", f"https://github.com/{owner}/*"):
            if e_low == form:
                return True
        return False

    # hostname comparison
    try:
        t_host = normalize_host(target)
    except ValueError:
        return False
    e = entry.lower().rstrip("/")
    if e.startswith("*."):
        return t_host == e[2:] or t_host.endswith("." + e[2:])
    try:
        return normalize_host(e) == t_host
    except ValueError:
        return False


@dataclass(frozen=True)
class EligibilityResult:
    verdict: Eligibility
    target: str
    program: str
    pays_cash: bool
    reasons: tuple[str, ...] = field(default_factory=tuple)

    @property
    def submittable_for_cash(self) -> bool:
        return self.verdict is Eligibility.SUBMITTABLE and self.pays_cash

    def __str__(self) -> str:  # pragma: no cover - convenience
        return (f"[{self.verdict.value}] {self.target} @ {self.program} "
                f"pays_cash={self.pays_cash} :: {'; '.join(self.reasons)}")


def verify_target(program: dict, target: str) -> EligibilityResult:
    """Decide whether *target* is eligible under *program*'s current policy.

    *program* is a program record (as stored in ``reports/programs.json``):
    ``handle``, ``active``, ``reward_ceiling``, ``targets``,
    ``bounty_eligible_targets``, ``out_of_scope``, ``scope_text``, ``rules``,
    ``notes`` are consulted. Fail-closed: missing/ambiguous data yields
    ``NOT_ELIGIBLE`` or ``UNKNOWN``, never a silent pass.
    """
    handle = str(program.get("handle") or program.get("url") or "?")
    reasons: list[str] = []

    # 0. Inactive programs are never eligible.
    if program.get("active") is False:
        return EligibilityResult(Eligibility.NOT_ELIGIBLE, target, handle, False,
                                 ("program marked inactive",))

    blob = _text_blob(program)
    t_repo = canonical_repo(target)

    # 1. EXPLICIT out-of-scope list wins over everything (pipelinewise lesson).
    out_of_scope = program.get("out_of_scope") or []
    if isinstance(out_of_scope, str):
        out_of_scope = [out_of_scope]
    for entry in out_of_scope:
        if _target_matches_entry(target, str(entry)):
            return EligibilityResult(Eligibility.NOT_ELIGIBLE, target, handle, False,
                                     (f"target matches out-of-scope entry: {entry!r}",))

    # 2. Suspension / VDP → no cash (Nextcloud lesson).
    ceiling = program.get("reward_ceiling")
    suspended = _matches_any(blob, _SUSPENSION_MARKERS)
    pays_cash = bool(ceiling and float(ceiling) > 0) and suspended is None
    if suspended is not None:
        reasons.append(f"paid program suspended/recognition-only (matched {suspended!r})")

    # 3. IN-SCOPE membership from the STRUCTURED lists (authoritative — trusted over
    #    free-text). Prefer the reward-eligible list, then the targets list.
    eligible = program.get("bounty_eligible_targets") or []
    targets = program.get("targets") or []
    in_eligible = any(_target_matches_entry(target, str(e)) for e in eligible)
    in_targets = any(_target_matches_entry(target, str(e)) for e in targets)

    if not (in_eligible or in_targets):
        # Not in any structured list → fall back to policy TEXT, but exclusions win
        # (Netflix lesson: a repo can appear on the page inside the out-of-scope
        # section). Use a newline-spanning window so a section header on one line
        # still governs a repo listed a few lines below it.
        if t_repo and re.search(
            r"(?:out[- ]of[- ]scope|not in scope|excluded|not eligible)\b.{0,600}?"
            + re.escape(t_repo),
            blob, re.IGNORECASE | re.DOTALL,
        ):
            return EligibilityResult(Eligibility.NOT_ELIGIBLE, target, handle, False,
                                     tuple(reasons)
                                     + (f"repo {t_repo} appears in an out-of-scope/exclusion section",))
        if t_repo and re.search(
            r"(?:in scope|in-scope|primary target|secondary target|eligible)\b.{0,600}?"
            + re.escape(t_repo),
            blob, re.IGNORECASE | re.DOTALL,
        ):
            reasons.append("target in scope_text (in-scope line)")
        else:
            return EligibilityResult(Eligibility.UNKNOWN, target, handle, False,
                                     tuple(reasons) + ("target not found in any in-scope list; "
                                                       "fail closed — verify against the live policy",))
    else:
        reasons.append("target in "
                       + ("bounty_eligible_targets" if in_eligible else "targets"))

    # 4. Recon-only / library-bugs-not-rewarded → not a source-vuln cash target.
    recon = _matches_any(blob, _RECON_MARKERS)
    if recon is not None and not in_eligible:
        reasons.append(f"scope is recon-only / library bugs not rewarded (matched {recon!r})")
        return EligibilityResult(Eligibility.RECON_ONLY, target, handle, pays_cash, tuple(reasons))

    # 5. Combine.
    if not pays_cash:
        reasons.append("no cash (VDP/suspended/zero ceiling) → recognition/CVE only")
        return EligibilityResult(Eligibility.CREDIT_ONLY, target, handle, False, tuple(reasons))

    reasons.append(f"pays cash (ceiling={ceiling})")
    return EligibilityResult(Eligibility.SUBMITTABLE, target, handle, True, tuple(reasons))
