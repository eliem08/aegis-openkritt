"""Target-authorization ledger — the BLOCK-by-default gate for *what* Aegis may hunt.

Distinct from :mod:`aegis.policy.authorization` (which authorizes *actions* via signed tokens):
this module answers "is this repository authorized to be researched at all?" and refuses unless
authorization can be established from a verifiable source:

1. an ACTIVE program in the registry whose current scope explicitly lists the repository;
2. a repository the operator owns / has explicitly allowlisted;
3. an explicit authorization record supplied locally (a ``manual`` ledger entry).

If none apply -> **BLOCK**. A public repository is never treated as authorized. The gate also
detects scope drift: a program-sourced authorization is re-derived every check and, if the
program's scope hash changed (or the program is gone/inactive), the target is blocked pending
re-approval. Records are persisted so decisions and their evidence survive restarts and audit.

Nothing here submits, attacks, or acts on a live system — it only decides whether local
source research on a target is permitted, and records why.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_LEDGER = "reports/authorization_ledger.json"
DEFAULT_MAX_AGE_DAYS = 7

# statuses
AUTHORIZED = "authorized"
BLOCKED = "blocked"
STALE = "stale"
SCOPE_CHANGED = "scope_changed"

# sources that carry no upstream scope drift (operator-asserted), so they are trusted without
# re-deriving a program each time (still subject to staleness).
_EXPLICIT_SOURCES = {"owner", "manual"}


def _now() -> datetime:
    return datetime.now(tz=timezone.utc)


def _norm(repo: str) -> str:
    return str(repo or "").strip().strip("/").lower()


def scope_hash(text: str) -> str:
    """Stable short hash of a scope snapshot — changes iff the scope text changes."""
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()[:16]


@dataclass
class AuthorizationRecord:
    repository: str
    status: str = BLOCKED
    source_platform: str = ""            # hackerone|bugcrowd|intigriti|immunefi|owner|manual|...
    program_id: str = ""
    program_name: str = ""
    program_url: str = ""
    asset_type: str = "repo"
    bounty_eligible: bool = False
    allowed_methods: list[str] = field(default_factory=list)
    prohibited_methods: list[str] = field(default_factory=list)
    rate_limits: str = ""
    auth_requirements: str = ""
    excluded_paths: list[str] = field(default_factory=list)
    scope_text: str = ""
    scope_snapshot_hash: str = ""
    scope_retrieved_at: str = ""         # ISO 8601
    last_verified_at: str = ""           # ISO 8601
    expires_at: str = ""                 # ISO 8601 (optional hard expiry)
    authorization_reason: str = ""
    evidence: str = ""                   # exact scope evidence (where the repo appears)

    def is_stale(self, now: datetime | None = None, max_age_days: int = DEFAULT_MAX_AGE_DAYS) -> bool:
        now = now or _now()
        if self.expires_at:
            try:
                if now >= datetime.fromisoformat(self.expires_at):
                    return True
            except ValueError:
                pass
        if not self.last_verified_at:
            return True
        try:
            age = now - datetime.fromisoformat(self.last_verified_at)
        except ValueError:
            return True
        return age.days >= max_age_days


@dataclass
class AuthorizationDecision:
    repository: str
    allowed: bool
    status: str
    reason: str
    record: AuthorizationRecord | None = None

    def as_dict(self) -> dict:
        return {"repository": self.repository, "allowed": self.allowed, "status": self.status,
                "reason": self.reason,
                "record": asdict(self.record) if self.record else None}


class AuthorizationLedger:
    """File-backed store of :class:`AuthorizationRecord` keyed by normalized repository."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path or DEFAULT_LEDGER)

    def _load_raw(self) -> dict:
        if not self.path.is_file():
            return {}
        try:
            data = json.loads(self.path.read_text(encoding="utf-8") or "{}")
        except (json.JSONDecodeError, OSError):
            return {}
        return data if isinstance(data, dict) else {}

    def all(self) -> list[AuthorizationRecord]:
        fields = set(AuthorizationRecord.__dataclass_fields__)
        out = []
        for rec in self._load_raw().values():
            if isinstance(rec, dict) and rec.get("repository"):
                out.append(AuthorizationRecord(**{k: v for k, v in rec.items() if k in fields}))
        return out

    def get(self, repository: str) -> AuthorizationRecord | None:
        raw = self._load_raw().get(_norm(repository))
        if not isinstance(raw, dict):
            return None
        fields = set(AuthorizationRecord.__dataclass_fields__)
        return AuthorizationRecord(**{k: v for k, v in raw.items() if k in fields})

    def upsert(self, record: AuthorizationRecord) -> None:
        raw = self._load_raw()
        raw[_norm(record.repository)] = asdict(record)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(raw, indent=2, sort_keys=True), encoding="utf-8")


def _owned_from_env(extra: list[str] | None = None) -> set[str]:
    owned = set(extra or [])
    env = os.environ.get("AEGIS_OWNED_REPOS", "")
    owned |= {_norm(x) for x in env.replace(";", ",").split(",") if x.strip()}
    f = os.environ.get("AEGIS_OWNED_REPOS_FILE", "")
    if f and Path(f).is_file():
        owned |= {_norm(x) for x in Path(f).read_text(encoding="utf-8").splitlines() if x.strip()
                  and not x.strip().startswith("#")}
    return {x for x in owned if x}


def _program_covering(repo: str, registry_path: str | Path | None):
    """Return the ACTIVE program whose current scope explicitly lists ``repo`` (and does not
    exclude it), or None. A public repo not explicitly in an active program's scope is NOT
    covered."""
    from .registry import load_registry
    r = _norm(repo)
    for prog in load_registry(registry_path):
        if not prog.active:
            continue
        targets = {_norm(t) for t in (prog.targets or [])}
        excluded = {_norm(t) for t in (prog.out_of_scope or [])}
        if r in targets and r not in excluded:
            return prog
    return None


def _record_from_program(prog, repo: str, now: datetime) -> AuthorizationRecord:
    scope = prog.scope_bundle()
    iso = now.isoformat()
    return AuthorizationRecord(
        repository=repo, status=AUTHORIZED, source_platform=prog.platform or "program",
        program_id=prog.handle, program_name=prog.handle, program_url=prog.url,
        asset_type=prog.kind or "repo", bounty_eligible=(prog.reward_ceiling or 0) > 0,
        prohibited_methods=["live-exploitation", "dos", "credential-theft", "persistence",
                            "defense-evasion"],
        allowed_methods=["local-source-review", "local-static-analysis",
                         "local-reproduction"],
        excluded_paths=list(prog.out_of_scope or []),
        scope_text=scope, scope_snapshot_hash=scope_hash(scope),
        scope_retrieved_at=iso, last_verified_at=iso,
        authorization_reason=f"in active program '{prog.handle}' scope",
        evidence=f"repository '{repo}' listed in program '{prog.handle}' in-scope targets")


def _owner_record(repo: str, now: datetime) -> AuthorizationRecord:
    iso = now.isoformat()
    return AuthorizationRecord(
        repository=repo, status=AUTHORIZED, source_platform="owner", asset_type="repo",
        allowed_methods=["local-source-review", "local-static-analysis", "local-reproduction"],
        prohibited_methods=["live-exploitation", "dos", "credential-theft"],
        scope_retrieved_at=iso, last_verified_at=iso,
        authorization_reason="owner/allowlisted repository",
        evidence="operator owned/allowlist entry")


def authorize(repository: str, *, registry_path: str | Path | None = None,
              ledger_path: str | Path | None = None, owned: list[str] | None = None,
              max_age_days: int = DEFAULT_MAX_AGE_DAYS, now: datetime | None = None,
              persist: bool = True) -> AuthorizationDecision:
    """The BLOCK-by-default target-authorization gate. Re-derives program authorization every
    call (so scope drift is caught) and reconciles with any stored ledger record."""
    now = now or _now()
    repo = _norm(repository)
    if not repo:
        return AuthorizationDecision(repository, False, BLOCKED, "empty repository")
    ledger = AuthorizationLedger(ledger_path)
    rec = ledger.get(repo)

    # explicit operator block always wins
    if rec and rec.status == BLOCKED and rec.source_platform in _EXPLICIT_SOURCES:
        return AuthorizationDecision(repo, False, BLOCKED,
                                     rec.authorization_reason or "explicitly blocked", rec)

    prog = _program_covering(repo, registry_path)

    # scope-drift / revocation detection for a previously program-authorized target
    if rec and rec.status == AUTHORIZED and rec.source_platform not in _EXPLICIT_SOURCES:
        if prog is None:
            blocked = replace(rec, status=BLOCKED, last_verified_at=now.isoformat(),
                              authorization_reason="target no longer in any active program "
                                                   "scope — authorization revoked")
            if persist:
                ledger.upsert(blocked)
            return AuthorizationDecision(repo, False, BLOCKED, blocked.authorization_reason,
                                         blocked)
        fresh = _record_from_program(prog, repo, now)
        if fresh.scope_snapshot_hash != rec.scope_snapshot_hash:
            blocked = replace(fresh, status=SCOPE_CHANGED,
                              authorization_reason="program scope changed since last "
                                                   "verification — re-approval required")
            if persist:
                ledger.upsert(blocked)
            return AuthorizationDecision(repo, False, SCOPE_CHANGED,
                                         blocked.authorization_reason, blocked)
        if persist:
            ledger.upsert(fresh)
        return AuthorizationDecision(repo, True, AUTHORIZED, fresh.authorization_reason, fresh)

    # explicit (owner/manual) authorization already in the ledger: honor unless stale
    if rec and rec.status == AUTHORIZED and rec.source_platform in _EXPLICIT_SOURCES:
        if rec.is_stale(now, max_age_days):
            return AuthorizationDecision(repo, False, STALE,
                                         "authorization stale — re-verify", rec)
        return AuthorizationDecision(repo, True, AUTHORIZED,
                                     rec.authorization_reason or "explicit authorization", rec)

    # no usable record yet: derive fresh authorization
    owned_set = _owned_from_env(owned)
    if repo in owned_set:
        new = _owner_record(repo, now)
        if persist:
            ledger.upsert(new)
        return AuthorizationDecision(repo, True, AUTHORIZED, new.authorization_reason, new)
    if prog is not None:
        new = _record_from_program(prog, repo, now)
        if persist:
            ledger.upsert(new)
        return AuthorizationDecision(repo, True, AUTHORIZED, new.authorization_reason, new)

    return AuthorizationDecision(repo, False, BLOCKED,
                                 "no verifiable authorization from any configured source "
                                 "(active program scope / owner allowlist / manual record)")


def gate(repository: str, **kwargs) -> AuthorizationDecision:
    """:func:`authorize`, honoring the ``AEGIS_REQUIRE_AUTHORIZATION=0`` controlled-test bypass.
    This is the function the hunt flow calls before any clone/network work."""
    if os.environ.get("AEGIS_REQUIRE_AUTHORIZATION", "1").strip() == "0":
        return AuthorizationDecision(_norm(repository), True, "override",
                                     "AEGIS_REQUIRE_AUTHORIZATION=0 (authorization bypass)")
    return authorize(repository, **kwargs)


def list_authorized(registry_path: str | Path | None = None,
                    ledger_path: str | Path | None = None,
                    owned: list[str] | None = None) -> list[str]:
    """Every repository currently authorized to hunt — active program targets + owned + fresh
    manual ledger records. Used to build the hunt queue from verifiable authorization only."""
    from .registry import load_registry
    repos: set[str] = set(_owned_from_env(owned))
    for prog in load_registry(registry_path):
        if prog.active:
            for t in (prog.targets or []):
                if _norm(t) not in {_norm(x) for x in (prog.out_of_scope or [])}:
                    repos.add(_norm(t))
    for rec in AuthorizationLedger(ledger_path).all():
        if rec.status == AUTHORIZED and rec.source_platform == "manual" and not rec.is_stale():
            repos.add(_norm(rec.repository))
    # only return ones that actually pass the gate right now
    return sorted(r for r in repos
                  if authorize(r, registry_path=registry_path, ledger_path=ledger_path,
                               owned=owned, persist=False).allowed)


def main(argv=None) -> int:
    import sys
    argv = list(argv if argv is not None else sys.argv[1:])
    if not argv:
        print("usage: python -m aegis.ai.target_authorization <owner/repo> [more...]")
        print("\ncurrently authorized:")
        for r in list_authorized():
            print(f"  AUTHORIZED  {r}")
        return 0
    rc = 0
    for repo in argv:
        d = authorize(repo, persist=False)
        tag = "AUTHORIZED" if d.allowed else "BLOCK"
        print(f"  {tag:10} {d.repository}  [{d.status}] {d.reason}")
        if not d.allowed:
            rc = 1
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
