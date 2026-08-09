"""Real-CVE ground-truth harness: pickaxe derivation on a real local git repo (no network) and
the metric math. Proves the self-verifying (vulnerable, fixed) derivation works."""

from __future__ import annotations

import subprocess

import pytest

from aegis.bench.real_cve import (
    RealBenchResult,
    RealCase,
    RealCaseResult,
    ScanObservation,
    derive_pair,
)


def _git(args, cwd):
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True)


def _has_git() -> bool:
    try:
        subprocess.run(["git", "--version"], capture_output=True, check=True)
        return True
    except Exception:
        return False


@pytest.mark.skipif(not _has_git(), reason="git not available")
def test_derive_pair_finds_the_fix_commit_and_its_vulnerable_parent(tmp_path):
    repo = tmp_path / "proj"
    repo.mkdir()
    _git(["init", "-q"], repo)
    _git(["config", "user.email", "t@t"], repo)
    _git(["config", "user.name", "t"], repo)
    src = repo / "app.py"
    # commit 1: unrelated; commit 2: introduces the vuln; commit 3: the FIX removes the pattern
    src.write_text("x = 1\n", encoding="utf-8")
    _git(["add", "-A"], repo); _git(["commit", "-qm", "init"], repo)
    src.write_text("import jwt\nd = jwt.decode(token, verify=False)\n", encoding="utf-8")
    _git(["add", "-A"], repo); _git(["commit", "-qm", "add auth"], repo)
    src.write_text("import jwt\nd = jwt.decode(token, key, algorithms=['RS256'])\n", encoding="utf-8")
    _git(["add", "-A"], repo); _git(["commit", "-qm", "fix: verify jwt"], repo)

    pair = derive_pair(str(repo), "verify=False")
    assert pair is not None
    vuln_ref, fix_ref = pair
    # the vulnerable revision contains the pattern; the fixed one does not
    vuln_src = subprocess.run(["git", "-C", str(repo), "show", f"{vuln_ref}:app.py"],
                              capture_output=True, text=True).stdout
    fix_src = subprocess.run(["git", "-C", str(repo), "show", f"{fix_ref}:app.py"],
                             capture_output=True, text=True).stdout
    assert "verify=False" in vuln_src
    assert "verify=False" not in fix_src


@pytest.mark.skipif(not _has_git(), reason="git not available")
def test_derive_pair_returns_none_when_pattern_never_removed(tmp_path):
    repo = tmp_path / "clean"
    repo.mkdir()
    _git(["init", "-q"], repo)
    _git(["config", "user.email", "t@t"], repo)
    _git(["config", "user.name", "t"], repo)
    (repo / "a.py").write_text("print('ok')\n", encoding="utf-8")
    _git(["add", "-A"], repo); _git(["commit", "-qm", "init"], repo)
    assert derive_pair(str(repo), "verify=False") is None


@pytest.mark.skipif(not _has_git(), reason="git not available")
def test_derive_pair_uses_pinned_fix_when_pattern_was_removed_again_later(tmp_path):
    repo = tmp_path / "history"
    repo.mkdir()
    _git(["init", "-q"], repo)
    _git(["config", "user.email", "t@t"], repo)
    _git(["config", "user.name", "t"], repo)
    src = repo / "app.py"
    src.write_text("dangerous(x)\n", encoding="utf-8")
    _git(["add", "-A"], repo); _git(["commit", "-qm", "vulnerable"], repo)
    src.write_text("safe(x)\n", encoding="utf-8")
    _git(["add", "-A"], repo); _git(["commit", "-qm", "advisory fix"], repo)
    pinned = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                            capture_output=True, text=True, check=True).stdout.strip()
    src.write_text("dangerous(x)\n", encoding="utf-8")
    _git(["add", "-A"], repo); _git(["commit", "-qm", "regression"], repo)
    src.write_text("safe(x)\n", encoding="utf-8")
    _git(["add", "-A"], repo); _git(["commit", "-qm", "later fix"], repo)

    latest_pair = derive_pair(str(repo), "dangerous(x)")
    pinned_pair = derive_pair(str(repo), "dangerous(x)", expected_fix_commit=pinned)
    assert latest_pair is not None and latest_pair[1] != pinned
    assert pinned_pair is not None and pinned_pair[1] == pinned


def test_metric_math_only_counts_scored_cases():
    res = RealBenchResult(cases=[
        RealCaseResult("a", "detected"), RealCaseResult("b", "detected"),
        RealCaseResult("c", "missed"), RealCaseResult("d", "regressed"),
        RealCaseResult("e", "skipped", "clone failed"),
        RealCaseResult("f", "unavailable", "no scanner"),
        RealCaseResult("g", "invalid", "provenance mismatch"),
    ])
    assert res.summary()["scored"] == 4          # detected+detected+missed+regressed
    assert res.recall == round(2 / 4, 4)
    assert res.regressions == 1
    assert res.summary()["by_status"]["skipped"] == 1
    assert res.unavailable == 1 and res.invalid == 1 and res.measured


def test_all_unavailable_is_not_measured_recall():
    res = RealBenchResult(cases=[RealCaseResult("a", "unavailable", "semgrep broken")])
    assert res.scored == []
    assert res.recall == 0.0
    assert res.measured is False


def test_required_detector_must_run_even_if_an_unrelated_tool_ran():
    observation = ScanObservation(attempted=["bandit"], unavailable={"semgrep": "broken"})
    assert observation.any_ran
    assert not observation.can_score(("semgrep",))
    assert observation.can_score(("bandit",))


def test_case_expected_defaults_to_cwe():
    assert RealCase("x", "o/r", "pat", "CWE-347").expected() == "cwe-347"
    assert RealCase("x", "o/r", "pat", "CWE-347", match="alg").expected() == "alg"


def test_load_cases_from_manifest_ignores_bad_rows(tmp_path):
    import json

    from aegis.bench.real_cve import load_cases
    manifest = tmp_path / "cases.json"
    manifest.write_text(json.dumps([
        {"id": "c1", "repo": "o/r", "pattern": "verify=False", "cwe": "CWE-347"},
        {"id": "", "repo": "o/r", "pattern": "x", "cwe": "y"},        # no id -> skipped
        {"repo": "o/r", "pattern": "x"},                              # no id -> skipped
        {"id": "c2", "repo": "o/r2", "pattern": "unserialize($_", "cwe": "CWE-502",
         "path_hint": "src/", "match": "cwe-502"},
    ]), encoding="utf-8")
    cases = load_cases(manifest)
    assert [c.id for c in cases] == ["c1", "c2"]
    assert cases[1].path_hint == "src/" and cases[1].expected() == "cwe-502"


def test_load_cases_rejects_bad_provenance_and_duplicates(tmp_path):
    import json

    from aegis.bench.real_cve import load_cases
    manifest = tmp_path / "bad.json"
    manifest.write_text(json.dumps([{
        "id": "c1", "repo": "o/r", "pattern": "x", "cwe": "CWE-1",
        "expected_fix_commit": "short",
    }]), encoding="utf-8")
    with pytest.raises(ValueError, match="full 40-character SHA"):
        load_cases(manifest)

    row = {"id": "c1", "repo": "o/r", "pattern": "x", "cwe": "CWE-1"}
    manifest.write_text(json.dumps([row, row]), encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate"):
        load_cases(manifest)


@pytest.mark.skipif(not _has_git(), reason="git not available")
def test_unavailable_scanner_is_not_counted_as_detector_miss(tmp_path):
    from aegis.bench.real_cve import run_real_case

    repo = tmp_path / "source"
    repo.mkdir()
    _git(["init", "-q"], repo)
    _git(["config", "user.email", "t@t"], repo)
    _git(["config", "user.name", "t"], repo)
    src = repo / "app.py"
    src.write_text("dangerous(x)\n", encoding="utf-8")
    _git(["add", "-A"], repo); _git(["commit", "-qm", "vulnerable"], repo)
    src.write_text("safe(x)\n", encoding="utf-8")
    _git(["add", "-A"], repo); _git(["commit", "-qm", "fix"], repo)
    fix = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                         capture_output=True, text=True, check=True).stdout.strip()

    def no_scanner(_root, _case):
        return ScanObservation(unavailable={"semgrep": "runtime unavailable"})

    case = RealCase("real", repo.as_uri(), "dangerous(x)", "CWE-1",
                    expected_fix_commit=fix)
    result = run_real_case(case, workdir=str(tmp_path / "run"), scanner=no_scanner)
    assert result.status == "unavailable"
    assert "semgrep" in result.reason


@pytest.mark.skipif(not _has_git(), reason="git not available")
def test_pinned_fix_mismatch_invalidates_case_before_scoring(tmp_path):
    from aegis.bench.real_cve import run_real_case

    repo = tmp_path / "source"
    repo.mkdir()
    _git(["init", "-q"], repo)
    _git(["config", "user.email", "t@t"], repo)
    _git(["config", "user.name", "t"], repo)
    src = repo / "app.py"
    src.write_text("dangerous(x)\n", encoding="utf-8")
    _git(["add", "-A"], repo); _git(["commit", "-qm", "vulnerable"], repo)
    src.write_text("safe(x)\n", encoding="utf-8")
    _git(["add", "-A"], repo); _git(["commit", "-qm", "fix"], repo)

    result = run_real_case(
        RealCase("real", repo.as_uri(), "dangerous(x)", "CWE-1",
                 expected_fix_commit="0" * 40),
        workdir=str(tmp_path / "run"),
        scanner=lambda *_: pytest.fail("scanner must not run for invalid provenance"),
    )
    assert result.status == "invalid"
    assert "pinned fix commit" in result.reason
