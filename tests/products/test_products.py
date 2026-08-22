"""Hermetic tests for the product layer — fully offline via injected fake ports.

The engine (LLM, scanners, reproduction) is replaced by deterministic fakes so these tests assert
the *product* orchestration and the evidence-stage contract, never network or Docker.
"""

from __future__ import annotations

from aegis.products import (
    bounty_triage,
    pr_gatekeeper,
    proof_of_fix,
    proof_of_vuln,
    repo_autopilot,
    slop_filter,
    standing_redteam,
)
from aegis.products.models import (
    HONESTY,
    ProductFinding,
    ProductResult,
    evidence_from_row,
    to_report,
)
from aegis.products.ports import Ports

# --------------------------------------------------------------------------------------------
# Deterministic fakes
# --------------------------------------------------------------------------------------------

def _row(cwe, file="app/x.py", line=10, sev="high"):
    return {"json_answer": {"vulnerability_type": cwe, "file_path": file, "line": line,
                            "summary": f"{cwe} at {file}"}, "severity": sev, "source": "test"}


def _fake_validate(report, repo_dir):
    for r in report.get("vulnerabilities", []):
        cwe = (r.get("json_answer") or {}).get("vulnerability_type", "")
        if "REAL" in cwe:
            v, c = "confirmed", 0.9
        elif "FAKE" in cwe:
            v, c = "false_positive", 0.1
        else:
            v, c = "unresolved", 0.2
        r["validation"] = {"verdict": v, "reason": f"test:{v}", "confidence": c}
        r["validation_status"] = v
    return report


def _fake_reproduce(report, repo_dir, **kw):
    triggers = str(repo_dir).endswith("-triggers")
    n = 0
    for r in report.get("vulnerabilities", []):
        if (r.get("validation") or {}).get("verdict") == "confirmed":
            r["reproduction"] = {"verdict": "reproduced" if triggers else "refuted"}
            n += 1 if triggers else 0
    return {"attempted": True, "reproduced": n}


def _fake_hunt(repo, *, repo_dir=None, files=12, samples=2, subpath="", include_paths=None, **kw):
    rows = [_row("REAL-CWE-89"), _row("FAKE-CWE-79", file="app/y.py"),
            _row("UNSURE-CWE-1", file="app/z.py")]
    rep = {"scan": {"repository": repo, "selected_files": ["a", "b"]}, "vulnerabilities": rows}
    return _fake_validate(rep, repo_dir or "hunt")


def fake_ports():
    return Ports(hunt=_fake_hunt, validate_report=_fake_validate, reproduce_report=_fake_reproduce,
                 dedupe=lambda rows: rows, corroborate=lambda rows: rows)


# --------------------------------------------------------------------------------------------
# Contract
# --------------------------------------------------------------------------------------------

def test_evidence_precedence_reproduced_beats_confirmed():
    r = _row("REAL")
    r["validation"] = {"verdict": "confirmed"}
    r["reproduction"] = {"verdict": "reproduced"}
    assert evidence_from_row(r).verdict == "reproduced"
    del r["reproduction"]
    assert evidence_from_row(r).verdict == "confirmed"
    r["validation"] = {"verdict": "false_positive"}
    assert evidence_from_row(r).verdict == "refuted"


def test_result_ranks_and_counts_and_carries_honesty():
    findings = [
        ProductFinding.from_row({**_row("A"), "reproduction": {"verdict": "reproduced"}}),
        ProductFinding.from_row({**_row("B"), "validation": {"verdict": "confirmed"}}),
        ProductFinding.from_row({**_row("C"), "validation": {"verdict": "false_positive"}}),
    ]
    res = ProductResult(product="t", target="x", findings=findings)
    assert res.ranked()[0].evidence.verdict == "reproduced"
    d = res.to_dict()
    assert d["stats"]["reproduced"] == 1 and d["stats"]["confirmed"] == 1
    assert d["honesty"] == HONESTY


# --------------------------------------------------------------------------------------------
# B — proof / validation
# --------------------------------------------------------------------------------------------

def test_proof_of_vuln_reproduces_real_on_live_instance():
    res = proof_of_vuln.run(_row("REAL-CWE-89"), "app-triggers", ports=fake_ports(), reproduce=True)
    assert res.findings[0].evidence.verdict == "reproduced"


def test_proof_of_vuln_confirmed_when_no_repro_and_refutes_fake():
    real = proof_of_vuln.run(_row("REAL-CWE-89"), "app-clean", ports=fake_ports(), reproduce=True)
    assert real.findings[0].evidence.verdict == "confirmed"      # validated but not triggered
    fake = proof_of_vuln.run(_row("FAKE-CWE-79"), "app-clean", ports=fake_ports(), reproduce=False)
    assert fake.findings[0].evidence.verdict == "refuted"


def test_proof_of_fix_verdicts():
    p = fake_ports()
    confirmed = proof_of_fix.run(_row("REAL-CWE-89"), "vuln-triggers", "fixed-clean", ports=p)
    assert confirmed.stats["fix_verdict"]["fix_confirmed"] == 1
    assert confirmed.findings[0].evidence.verdict == "fix_confirmed"

    still = proof_of_fix.run(_row("REAL-CWE-89"), "vuln-triggers", "fixed-triggers", ports=p)
    assert still.stats["fix_verdict"]["still_vulnerable"] == 1

    unproven = proof_of_fix.run(_row("REAL-CWE-89"), "vuln-clean", "fixed-clean", ports=p)
    assert unproven.stats["fix_verdict"]["fix_unproven"] == 1


def test_slop_filter_keeps_real_kills_the_rest():
    findings = [_row("REAL-CWE-89"), _row("FAKE-CWE-79", file="app/y.py"),
                _row("UNSURE-CWE-1", file="app/z.py")]
    res = slop_filter.run(findings, "app", ports=fake_ports())
    assert res.stats["input"] == 3
    assert res.stats["kept"] == 1
    assert res.stats["killed"] == 2
    assert res.stats["kill_rate"] == round(2 / 3, 3)


def test_bounty_triage_dedupes_and_validates():
    reports = [_row("REAL-CWE-89"), _row("REAL-CWE-89"),  # duplicate submission
               _row("FAKE-CWE-79", file="app/y.py")]
    res = bounty_triage.run(reports, repo_dir="app", ports=fake_ports())
    assert res.stats["received"] == 3
    assert res.stats["unique"] == 2
    assert res.stats["duplicates"] == 1
    real = [f for f in res.findings if "REAL" in f.cwe][0]
    assert real.meta.get("duplicate_reports") == 2
    assert real.evidence.verdict == "confirmed"


# --------------------------------------------------------------------------------------------
# A — finders
# --------------------------------------------------------------------------------------------

def test_repo_autopilot_ships_only_conclusions():
    res = repo_autopilot.run("owner/repo", repo_dir="checkout-triggers", ports=fake_ports())
    verdicts = {f.evidence.verdict for f in res.findings}
    assert verdicts <= {"confirmed", "reproduced"}          # no raw/refuted/unresolved noise
    assert any(f.evidence.verdict == "reproduced" for f in res.findings)
    assert all("FAKE" not in f.cwe for f in res.findings)


def test_repo_autopilot_reproduced_only_mode():
    res = repo_autopilot.run("owner/repo", repo_dir="checkout-triggers", ports=fake_ports(),
                             reproduced_only=True)
    assert res.findings and all(f.evidence.verdict == "reproduced" for f in res.findings)
    empty = repo_autopilot.run("owner/repo", repo_dir="checkout-clean", ports=fake_ports(),
                               reproduced_only=True)
    assert empty.findings == []                             # nothing reproduced on a clean instance


def test_pr_gatekeeper_gates_on_changed_file_and_emits_sarif():
    p = fake_ports()
    blocked = pr_gatekeeper.run("owner/repo", ["app/x.py"], repo_dir="d", ports=p)
    assert pr_gatekeeper.gate_failed(blocked) is True
    assert blocked.stats["gate"]["blocking"]
    assert all(f.file == "app/x.py" for f in blocked.findings)   # scoped to the diff
    sarif = pr_gatekeeper.to_sarif(blocked)
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"][0]["ruleId"] == "REAL-CWE-89"

    clean = pr_gatekeeper.run("owner/repo", ["app/unrelated.py"], repo_dir="d", ports=p)
    assert pr_gatekeeper.gate_failed(clean) is False


def test_standing_redteam_flags_only_new():
    p = fake_ports()
    first = standing_redteam.run("owner/repo", repo_dir="checkout-triggers", ports=p)
    assert first.stats["new"] == len(first.findings) and first.stats["known"] == 0
    ids = first.stats["current_ids"]
    second = standing_redteam.run("owner/repo", repo_dir="checkout-triggers", ports=p,
                                  previous_ids=ids)
    assert second.stats["new"] == 0 and second.stats["known"] == len(second.findings)


def test_to_report_roundtrips():
    rep = to_report([_row("X")], repository="o/r")
    assert rep["vulnerabilities"][0]["json_answer"]["vulnerability_type"] == "X"
    assert rep["scan"]["repository"] == "o/r"


def test_cli_triage_no_validate_is_hermetic(tmp_path):
    """The `aegis products triage --no-validate` path needs no engine — a full CLI smoke test."""
    import json

    from aegis.cli import main

    reports = tmp_path / "reports.json"
    reports.write_text(json.dumps([
        _row("CWE-89"), _row("CWE-89", line=11),        # duplicate locus
        _row("CWE-79", file="app/y.py"),
    ]), encoding="utf-8")
    out = tmp_path / "out.json"
    rc = main(["products", "triage", "--reports", str(reports), "--no-validate",
               "--json", str(out)])
    assert rc == 0
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["product"] == "bounty-triage"
    assert doc["stats"]["received"] == 3 and doc["stats"]["unique"] == 2
    assert doc["stats"]["duplicates"] == 1
    assert "honesty" in doc
