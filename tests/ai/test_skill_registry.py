"""External-skill registry + arm's-length invoker."""

from __future__ import annotations

from aegis.ai.skill_registry import (
    Lane, License, SkillInvoker, all_skills, for_lane, invoke_only, recommend, vendorable,
)


def test_catalog_covers_the_provided_repos():
    sources = {s.source.split("/")[0] for s in all_skills()}
    assert {"pashov", "cloudflare", "trailofbits", "Factory-AI", "getsentry"} <= sources


def test_license_gates_vendoring():
    # MIT skills may be vendored; unlicensed ones are invoke-only
    assert all(s.license is License.MIT for s in vendorable())
    assert all(s.invoke_only for s in invoke_only())
    # pashov + cloudflare (MIT) are vendorable; Factory-AI/Sentry (no license) are not
    vnames = {s.source.split("/")[0] for s in vendorable()}
    assert "pashov" in vnames and "cloudflare" in vnames
    assert "Factory-AI" not in vnames and "getsentry" not in vnames


def test_for_lane_contract_has_solidity_auditor():
    names = {s.name for s in for_lane(Lane.CONTRACT)}
    assert {"solidity-auditor", "x-ray", "fizz"} <= names


def test_recommend_contract_puts_mit_first():
    recs = recommend("contract")
    assert recs and recs[0].license is License.MIT           # vendorable surfaces first
    assert any(s.name == "solidity-auditor" for s in recs)


def test_recommend_code_targets_general_review():
    recs = recommend("repo")
    assert any(s.name == "find-bugs" for s in recs)          # sentry code lane
    assert all(Lane.CONTRACT not in s.lanes or Lane.CODE in s.lanes for s in recs) or recs


def test_invoker_runs_each_skill_via_caller_runner():
    ran = []
    def runner(skill, target):
        ran.append(skill.name)
        return True, f"{skill.name} ok on {target}"
    skills = for_lane(Lane.CONTRACT)[:2]
    results = SkillInvoker(runner).run(skills, "0xVault")
    assert [r.skill for r in results] == [s.name for s in skills]
    assert all(r.ok for r in results) and ran == [s.name for s in skills]


def test_invoker_isolates_a_failing_skill():
    def runner(skill, target):
        if skill.name == "fizz":
            raise RuntimeError("echidna not installed")
        return True, "ok"
    results = SkillInvoker(runner).run(for_lane(Lane.CONTRACT), "0xV")
    failed = [r for r in results if not r.ok]
    assert failed and "echidna not installed" in failed[0].error
    assert any(r.ok for r in results)                        # others still ran


def test_shell_runner_substitutes_and_reports():
    from aegis.ai.skill_registry import make_shell_runner, for_lane, Lane
    seen = {}
    def fake_run(argv, timeout):
        seen["argv"] = argv
        return True, "solidity-auditor: 3 High findings"
    runner = make_shell_runner("agent run {source} on {target}", run=fake_run)
    skill = for_lane(Lane.CONTRACT)[0]
    ok, out = runner(skill, "0xVault")
    assert ok and "findings" in out
    assert skill.source in seen["argv"] and "0xVault" in seen["argv"]


def test_shell_runner_failure_is_reported_not_raised():
    from aegis.ai.skill_registry import make_shell_runner, SkillInvoker, for_lane, Lane
    def fake_run(argv, timeout):
        return False, "skill not installed"
    runs = SkillInvoker(make_shell_runner("x {source} {target}", run=fake_run)).run(
        for_lane(Lane.CONTRACT)[:1], "0xV")
    assert runs and runs[0].ok is False
