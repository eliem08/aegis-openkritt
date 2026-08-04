"""Arm's-length skill bridge — invoke installed skills, ingest their output."""

from __future__ import annotations

from aegis.ai.skill_bridge import SkillBridge, _try_json_findings


def test_disabled_without_command(monkeypatch):
    monkeypatch.delenv("AEGIS_SKILL_CMD", raising=False)
    b = SkillBridge()
    assert b.enabled is False and b.run("owner/repo") == []


def test_runs_recommended_skills_via_injected_runner():
    calls = []
    def runner(skill, target):
        calls.append((skill.name, target))
        return True, ""
    b = SkillBridge(runner=runner)
    assert b.enabled
    runs = b.run("owner/repo", target_kind="repo")
    assert runs and all(r.ok for r in runs)
    assert calls and calls[0][1] == "owner/repo"


def test_ingest_json_findings():
    findings = _try_json_findings('noise before [{"title":"IDOR","file":"a.js","line":"7",'
                                  '"severity":"high","description":"no owner check"}] trailing')
    assert findings and findings[0]["title"] == "IDOR"


def test_ingest_findings_key_object():
    findings = _try_json_findings('{"findings":[{"type":"SSRF"},{"type":"XSS"}]}')
    assert [f["type"] for f in findings] == ["SSRF", "XSS"]


def test_to_findings_maps_json_and_raw():
    from aegis.ai.skill_registry import SkillRun
    b = SkillBridge(runner=lambda s, t: (True, ""))
    runs = [
        SkillRun(skill="solidity-auditor", ok=True,
                 output='[{"title":"Reentrancy","file":"V.sol","line":"42","severity":"critical"}]'),
        SkillRun(skill="x-ray", ok=True, output="human-readable threat model, no json"),
        SkillRun(skill="fizz", ok=False, error="not installed"),   # dropped
    ]
    rows = b.to_findings(runs, repository="acme/contracts")
    assert len(rows) == 2                                          # failed run dropped
    structured = next(r for r in rows if r["source"] == "aegis:skill:solidity-auditor")
    assert structured["json_answer"]["vulnerability_type"] == "Reentrancy"
    assert structured["severity"] == "critical"
    assert structured["validation_status"] == "unverified"        # never auto-confirmed
    raw = next(r for r in rows if r["source"] == "aegis:skill:x-ray")
    assert "review manually" in raw["json_answer"]["summary"]


def test_skill_candidates_are_never_pre_confirmed():
    from aegis.ai.skill_registry import SkillRun
    rows = SkillBridge(runner=lambda s, t: (True, "")).to_findings(
        [SkillRun(skill="s", ok=True, output='[{"title":"x","severity":"high"}]')])
    assert all(r["validation_status"] == "unverified" and r["confidence"] == 0.0 for r in rows)
