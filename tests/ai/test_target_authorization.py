"""Target-authorization gate: BLOCK by default; authorize only from verifiable sources;
detect scope drift, revocation, and staleness; persist decisions. Safety-critical."""

from __future__ import annotations

from datetime import timedelta

from aegis.ai import target_authorization as ta
from aegis.ai.registry import Program, save_registry


def _reg(tmp_path, *programs):
    p = tmp_path / "programs.json"
    save_registry(list(programs), p)
    return p


def _led(tmp_path):
    return tmp_path / "ledger.json"


def test_unknown_repo_is_blocked_by_default(tmp_path):
    d = ta.authorize("some/public-repo", registry_path=_reg(tmp_path),
                     ledger_path=_led(tmp_path), owned=[])
    assert d.allowed is False
    assert d.status == ta.BLOCKED
    assert "no verifiable authorization" in d.reason


def test_public_repo_is_not_authorized_just_because_it_exists(tmp_path):
    # a program exists but does NOT list this repo -> still blocked
    reg = _reg(tmp_path, Program(handle="acme", platform="hackerone",
                                 targets=["acme/backend"], active=True))
    d = ta.authorize("torvalds/linux", registry_path=reg, ledger_path=_led(tmp_path), owned=[])
    assert d.allowed is False and d.status == ta.BLOCKED


def test_active_program_scope_authorizes_with_evidence(tmp_path):
    reg = _reg(tmp_path, Program(handle="acme", platform="hackerone", url="https://h1/acme",
                                 targets=["acme/backend"], reward_ceiling=5000,
                                 out_of_scope=["acme/docs"], scope_text="in scope: acme/backend",
                                 active=True))
    led = _led(tmp_path)
    d = ta.authorize("acme/backend", registry_path=reg, ledger_path=led, owned=[])
    assert d.allowed is True and d.status == ta.AUTHORIZED
    assert d.record.source_platform == "hackerone"
    assert d.record.bounty_eligible is True
    assert d.record.scope_snapshot_hash
    assert "acme/backend" in d.record.evidence
    assert "live-exploitation" in d.record.prohibited_methods
    # persisted
    assert ta.AuthorizationLedger(led).get("acme/backend") is not None


def test_inactive_program_is_blocked(tmp_path):
    reg = _reg(tmp_path, Program(handle="acme", targets=["acme/backend"], active=False))
    d = ta.authorize("acme/backend", registry_path=reg, ledger_path=_led(tmp_path), owned=[])
    assert d.allowed is False


def test_explicitly_excluded_repo_is_blocked(tmp_path):
    reg = _reg(tmp_path, Program(handle="acme", targets=["acme/backend"],
                                 out_of_scope=["acme/backend"], active=True))
    d = ta.authorize("acme/backend", registry_path=reg, ledger_path=_led(tmp_path), owned=[])
    assert d.allowed is False


def test_owned_allowlist_authorizes(tmp_path):
    d = ta.authorize("me/myrepo", registry_path=_reg(tmp_path), ledger_path=_led(tmp_path),
                     owned=["me/myrepo"])
    assert d.allowed is True and d.record.source_platform == "owner"


def test_scope_change_blocks_until_reapproval(tmp_path):
    led = _led(tmp_path)
    reg = _reg(tmp_path, Program(handle="acme", targets=["acme/backend"],
                                 scope_text="scope v1", active=True))
    first = ta.authorize("acme/backend", registry_path=reg, ledger_path=led, owned=[])
    assert first.allowed is True
    # scope text changes -> hash changes -> next check must block
    _reg(tmp_path, Program(handle="acme", targets=["acme/backend"],
                           scope_text="scope v2 CHANGED", active=True))
    second = ta.authorize("acme/backend", registry_path=reg, ledger_path=led, owned=[])
    assert second.allowed is False and second.status == ta.SCOPE_CHANGED


def test_revocation_when_program_removed(tmp_path):
    led = _led(tmp_path)
    reg = _reg(tmp_path, Program(handle="acme", targets=["acme/backend"], active=True))
    assert ta.authorize("acme/backend", registry_path=reg, ledger_path=led, owned=[]).allowed
    save_registry([], reg)     # program gone
    d = ta.authorize("acme/backend", registry_path=reg, ledger_path=led, owned=[])
    assert d.allowed is False and "no longer" in d.reason


def test_staleness_blocks_owner_record(tmp_path):
    led = _led(tmp_path)
    now = ta._now()
    # authorize as owner, then re-check far in the future -> stale
    ta.authorize("me/x", registry_path=_reg(tmp_path), ledger_path=led, owned=["me/x"], now=now)
    future = now + timedelta(days=ta.DEFAULT_MAX_AGE_DAYS + 1)
    d = ta.authorize("me/x", registry_path=_reg(tmp_path), ledger_path=led, owned=["me/x"],
                     now=future)
    assert d.allowed is False and d.status == ta.STALE


def test_explicit_manual_block_wins(tmp_path):
    led = _led(tmp_path)
    ledger = ta.AuthorizationLedger(led)
    ledger.upsert(ta.AuthorizationRecord(repository="me/x", status=ta.BLOCKED,
                                         source_platform="manual",
                                         authorization_reason="operator hold"))
    # even if owned, an explicit manual block wins
    d = ta.authorize("me/x", registry_path=_reg(tmp_path), ledger_path=led, owned=["me/x"])
    assert d.allowed is False and "operator hold" in d.reason


def test_gate_blocks_unauthorized_but_bypass_env_overrides(tmp_path, monkeypatch):
    monkeypatch.delenv("AEGIS_REQUIRE_AUTHORIZATION", raising=False)
    d = ta.gate("some/public-repo", registry_path=_reg(tmp_path), ledger_path=_led(tmp_path),
                owned=[])
    assert d.allowed is False and d.status == ta.BLOCKED
    # controlled test bypass
    monkeypatch.setenv("AEGIS_REQUIRE_AUTHORIZATION", "0")
    d2 = ta.gate("some/public-repo")
    assert d2.allowed is True and d2.status == "override"


def test_list_authorized_only_returns_verifiable(tmp_path):
    reg = _reg(tmp_path, Program(handle="acme", targets=["acme/backend", "acme/api"],
                                 out_of_scope=["acme/api"], active=True),
               Program(handle="dead", targets=["dead/repo"], active=False))
    got = ta.list_authorized(registry_path=reg, ledger_path=_led(tmp_path), owned=["me/mine"])
    assert "acme/backend" in got
    assert "me/mine" in got
    assert "acme/api" not in got      # excluded
    assert "dead/repo" not in got     # inactive


def test_authorized_targets_queue_only_contains_authorized(tmp_path):
    reg = _reg(tmp_path, Program(handle="acme", targets=["acme/backend"], reward_ceiling=5000,
                                 findability=0.6, active=True),
               Program(handle="dead", targets=["dead/repo"], reward_ceiling=9000, active=False))
    q = ta.authorized_targets(registry_path=reg, ledger_path=_led(tmp_path), owned=[])
    repos = {t.repository for t in q}
    assert "acme/backend" in repos
    assert "dead/repo" not in repos    # inactive program excluded despite higher ceiling
