"""Program registry, hostile-triager pass, and target-selection scoring."""

from __future__ import annotations

from pathlib import Path

from aegis.ai.registry import (
    Program,
    get_program,
    load_registry,
    scope_text_for,
    to_hunt_targets,
    upsert,
)
from aegis.ai.selection import maturity_discount, score_programs
from aegis.ai.triager import HostileTriager, triage_report


# --- registry ---------------------------------------------------------------

def test_upsert_and_get_roundtrip(tmp_path: Path):
    store = tmp_path / "programs.json"
    p = Program(handle="acme", platform="immunefi", targets=["acme/vault"], kind="contract",
                reward_ceiling=250000, out_of_scope=["dependencies", "test/**"],
                scope_text="In scope: the vault contracts.")
    upsert(p, store)
    got = get_program("acme", store)
    assert got and got.reward_ceiling == 250000 and got.kind == "contract"
    assert len(load_registry(store)) == 1


def test_upsert_replaces_by_handle(tmp_path: Path):
    store = tmp_path / "programs.json"
    upsert(Program(handle="acme", reward_ceiling=1000), store)
    upsert(Program(handle="acme", reward_ceiling=5000), store)
    progs = load_registry(store)
    assert len(progs) == 1 and progs[0].reward_ceiling == 5000


def test_scope_bundle_composes_lists():
    p = Program(handle="x", targets=["a/b"], out_of_scope=["deps"], rules="No DoS.",
                scope_text="Focus the vault.")
    b = p.scope_bundle()
    assert "Focus the vault" in b and "In scope: a/b" in b and "Out of scope: deps" in b \
        and "Rules: No DoS" in b


def test_scope_text_for_reads_store(tmp_path: Path):
    store = tmp_path / "programs.json"
    upsert(Program(handle="acme", targets=["acme/vault"]), store)
    assert "acme/vault" in scope_text_for("acme", store)


def test_to_hunt_targets_skips_inactive(tmp_path: Path):
    progs = [Program(handle="live", targets=["a/b"], active=True),
             Program(handle="dead", targets=["c/d"], active=False)]
    tgts = to_hunt_targets(progs)
    assert [t.repository for t in tgts] == ["a/b"]


def test_load_tolerates_unknown_keys(tmp_path: Path):
    store = tmp_path / "programs.json"
    store.write_text('[{"handle":"x","bogus_field":1,"reward_ceiling":9}]', encoding="utf-8")
    progs = load_registry(store)
    assert len(progs) == 1 and progs[0].reward_ceiling == 9


# --- selection scoring ------------------------------------------------------

def test_maturity_discount_penalises_audited_and_old():
    fresh = maturity_discount(audits=0, age_months=1, paid_reports=0)
    picked = maturity_discount(audits=4, age_months=30, paid_reports=80)
    assert fresh == 1.0
    assert picked < 0.2 and picked > 0.0


def test_score_ranks_fresh_above_overaudited():
    fresh = Program(handle="fresh", targets=["f/f"], kind="contract", reward_ceiling=100000,
                    findability=0.6, audits=0, age_months=1, paid_reports=0)
    ssv = Program(handle="ssv", targets=["s/s"], kind="contract", reward_ceiling=250000,
                  findability=0.6, audits=5, age_months=30, paid_reports=60)
    ranked = score_programs([fresh, ssv])
    assert ranked[0].program.handle == "fresh"     # despite ssv's higher ceiling
    assert ranked[0].discount > ranked[1].discount


# --- hostile triager --------------------------------------------------------

class _Client:
    def __init__(self, payload):
        self._p = payload

    def complete_json(self, messages, **kw):
        if isinstance(self._p, Exception):
            raise self._p
        return self._p


def _row(loc="package-lock.json:0", sev="high"):
    return {"validation": {"verdict": "confirmed"}, "severity": sev, "location": loc,
            "json_answer": {"summary": "x", "vulnerability_type": "rce"}}


def test_triager_reject_demotes_finding():
    c = _Client({"verdict": "reject", "scope_ok": False, "attacker_realistic": True,
                 "corrected_severity": "info", "reason": "dependency, out of scope"})
    rep = {"vulnerabilities": [_row()]}
    summ = triage_report(rep, c, scope_text="deps out of scope")
    assert summ["rejected"] == 1 and summ["passed"] == 0
    row = rep["vulnerabilities"][0]
    assert row["rejected_by_triager"] and row["validation"]["verdict"] == "rejected"


def test_triager_downgrade_rewrites_severity():
    c = _Client({"verdict": "downgrade", "corrected_severity": "low", "reason": "low impact"})
    rep = {"vulnerabilities": [_row(sev="critical")]}
    triage_report(rep, c)
    assert rep["vulnerabilities"][0]["severity"] == "low"


def test_triager_pass_keeps_finding():
    c = _Client({"verdict": "pass", "corrected_severity": "high", "reason": "solid"})
    rep = {"vulnerabilities": [_row()]}
    summ = triage_report(rep, c)
    assert summ["passed"] == 1 and rep["vulnerabilities"][0].get("rejected_by_triager") is None


def test_triager_error_degrades_not_drops():
    c = _Client(RuntimeError("boom"))
    rep = {"vulnerabilities": [_row()]}
    summ = triage_report(rep, c)
    assert summ["rejected"] == 0
    assert rep["vulnerabilities"][0]["triage"]["verdict"] == "unreviewed"


def test_triager_invalid_verdict_is_unreviewed():
    c = _Client({"verdict": "definitely-a-bug"})
    assert HostileTriager(c).triage(_row())["verdict"] == "unreviewed"
