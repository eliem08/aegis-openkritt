"""Target-authorization ledger — the BLOCK-by-default gate for *what* Aegis may hunt.

A public repository is never authorization. Program-sourced authorization is valid only when
an ACTIVE current scope explicitly lists the repository *and* the upstream scope snapshot is
fresh. Owner/manual records remain explicit operator assertions and use their own expiry rules.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_LEDGER = "reports/authorization_ledger.json"
DEFAULT_MAX_AGE_DAYS = 7
DEFAULT_PROGRAM_SCOPE_MAX_AGE_HOURS = 24
_LEDGER_LOCK = threading.RLock()

AUTHORIZED = "authorized"
BLOCKED = "blocked"
STALE = "stale"
SCOPE_CHANGED = "scope_changed"

_EXPLICIT_SOURCES = {"owner", "manual"}


def _now() -> datetime:
    return datetime.now(tz=timezone.utc)


def _norm(repo: str) -> str:
    return str(repo or "").strip().strip("/").lower()


def _parse_iso(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value or ""))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def scope_hash(text: str) -> str:
    """Stable short hash of a scope snapshot — changes iff the scope text changes."""
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()[:16]


def _program_scope_max_age_hours() -> int:
    raw = os.environ.get("AEGIS_PROGRAM_SCOPE_MAX_AGE_HOURS", "").strip()
    if not raw:
        return DEFAULT_PROGRAM_SCOPE_MAX_AGE_HOURS
    try:
        return max(1, int(raw))
    except ValueError:
        return DEFAULT_PROGRAM_SCOPE_MAX_AGE_HOURS


def _program_scope_is_stale(prog, now: datetime) -> bool:
    """True when upstream scope freshness cannot be established within the configured TTL."""
    fetched = _parse_iso(getattr(prog, "scope_retrieved_at", "") or
                         getattr(prog, "source_retrieved_at", ""))
    if fetched is None:
        return True
    return (now - fetched).total_seconds() >= _program_scope_max_age_hours() * 3600


@dataclass
class AuthorizationRecord:
    repository: str
    status: str = BLOCKED
    source_platform: str = ""
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
    scope_retrieved_at: str = ""
    last_verified_at: str = ""
    expires_at: str = ""
    authorization_reason: str = ""
    evidence: str = ""

    def is_stale(self, now: datetime | None = None, max_age_days: int = DEFAULT_MAX_AGE_DAYS) -> bool:
        now = now or _now()
        if self.expires_at:
            expires = _parse_iso(self.expires_at)
            if expires is None or now >= expires:
                return True
        verified = _parse_iso(self.last_verified_at)
        if verified is None:
            return True
        return (now - verified).total_seconds() >= max_age_days * 86400


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
    """Atomic file-backed store keyed by normalized repository."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path or DEFAULT_LEDGER)

    def _load_raw(self) -> dict:
        if not self.path.is_file():
            return {}
        with _LEDGER_LOCK:
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
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with _LEDGER_LOCK:
            raw = self._load_raw()
            raw[_norm(record.repository)] = asdict(record)
            payload = json.dumps(raw, indent=2, sort_keys=True)
            tmp = self.path.with_name(f".{self.path.name}.{os.getpid()}.tmp")
            tmp.write_text(payload, encoding="utf-8")
            os.replace(tmp, self.path)


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
    """Return the active program whose structured scope explicitly covers ``repo``."""
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
    bounty_targets = {_norm(t) for t in (getattr(prog, "bounty_eligible_targets", []) or [])}
    bounty_known = bool(getattr(prog, "bounty_eligibility_known", False))
    bounty_eligible = (_norm(repo) in bounty_targets if bounty_known
                       else (prog.reward_ceiling or 0) > 0)
    source_scope_time = (getattr(prog, "scope_retrieved_at", "") or
                         getattr(prog, "source_retrieved_at", ""))
    return AuthorizationRecord(
        repository=repo, status=AUTHORIZED, source_platform=prog.platform or "program",
        program_id=prog.handle, program_name=prog.handle, program_url=prog.url,
        asset_type=prog.kind or "repo", bounty_eligible=bounty_eligible,
        prohibited_methods=["live-exploitation", "dos", "credential-theft", "persistence",
                            "defense-evasion"],
        allowed_methods=["local-source-review", "local-static-analysis", "local-reproduction"],
        excluded_paths=list(prog.out_of_scope or []),
        scope_text=scope, scope_snapshot_hash=scope_hash(scope),
        scope_retrieved_at=source_scope_time, last_verified_at=iso,
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
    """BLOCK-by-default target gate with upstream scope freshness enforcement."""
    now = now or _now()
    repo = _norm(repository)
    if not repo:
        return AuthorizationDecision(repository, False, BLOCKED, "empty repository")
    ledger = AuthorizationLedger(ledger_path)
    rec = ledger.get(repo)

    if rec and rec.status == BLOCKED and rec.source_platform in _EXPLICIT_SOURCES:
        return AuthorizationDecision(repo, False, BLOCKED,
                                     rec.authorization_reason or "explicitly blocked", rec)

    prog = _program_covering(repo, registry_path)

    if prog is not None and _program_scope_is_stale(prog, now):
        stale = _record_from_program(prog, repo, now)
        stale = replace(stale, status=STALE,
                        authorization_reason="upstream program scope snapshot is stale or missing; "
                                             "refresh program sources before hunting")
        if persist:
            ledger.upsert(stale)
        return AuthorizationDecision(repo, False, STALE, stale.authorization_reason, stale)

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

    if rec and rec.status == AUTHORIZED and rec.source_platform in _EXPLICIT_SOURCES:
        if rec.is_stale(now, max_age_days):
            return AuthorizationDecision(repo, False, STALE,
                                         "authorization stale — re-verify", rec)
        return AuthorizationDecision(repo, True, AUTHORIZED,
                                     rec.authorization_reason or "explicit authorization", rec)

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
                                 "(active fresh program scope / owner allowlist / manual record)")


def gate(repository: str, **kwargs) -> AuthorizationDecision:
    """Authorize a target, honoring the explicit controlled-test bypass only."""
    if os.environ.get("AEGIS_REQUIRE_AUTHORIZATION", "1").strip() == "0":
        return AuthorizationDecision(_norm(repository), True, "override",
                                     "AEGIS_REQUIRE_AUTHORIZATION=0 (authorization bypass)")
    return authorize(repository, **kwargs)


def list_authorized(registry_path: str | Path | None = None,
                    ledger_path: str | Path | None = None,
                    owned: list[str] | None = None) -> list[str]:
    """Every repository that passes the target gate right now."""
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
    return sorted(r for r in repos
                  if authorize(r, registry_path=registry_path, ledger_path=ledger_path,
                               owned=owned, persist=False).allowed)


def authorized_targets(registry_path: str | Path | None = None,
                       ledger_path: str | Path | None = None,
                       owned: list[str] | None = None) -> list:
    """EV-rankable targets restricted to the currently fresh authorization set."""
    from .registry import to_hunt_targets

    out = []
    for t in to_hunt_targets(path=registry_path):
        d = gate(t.repository, registry_path=registry_path, ledger_path=ledger_path,
                 owned=owned, persist=False)
        if d.allowed:
            out.append(t)
    return out


def main(argv=None) -> int:
    import sys

    from ..env import load_dotenv

    load_dotenv()
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
