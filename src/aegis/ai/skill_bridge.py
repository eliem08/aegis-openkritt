"""Arm's-length bridge to external security skills — the open·kritt pattern for skills.

Like ``OpenKrittClient`` talks to a running open·kritt over its API and folds the result
into Aegis's pipeline, this drives the operator's INSTALLED skills over a command they
configure and folds their output back in as Aegis candidates. No skill source is
embedded — Aegis calls the skill where the operator installed it, exactly the boundary
we hold for open·kritt.

Enabled by setting ``AEGIS_SKILL_CMD`` to the operator's command with ``{source}`` and
``{target}`` placeholders (e.g. their agent CLI wired to run an installed skill). Unset
=> disabled, no-op.
"""

from __future__ import annotations

import json
import os

from .skill_registry import Skill, SkillInvoker, SkillRun, make_shell_runner, recommend


class SkillBridge:
    """Run the recommended installed skills for a target and ingest their findings."""

    def __init__(self, runner=None, *, cmd: str | None = None) -> None:
        cmd = cmd if cmd is not None else os.environ.get("AEGIS_SKILL_CMD")
        self._runner = runner or (make_shell_runner(cmd) if cmd else None)

    @property
    def enabled(self) -> bool:
        return self._runner is not None

    def skills_for(self, target_kind: str) -> list[Skill]:
        return recommend(target_kind)

    def run(self, target: str, *, target_kind: str = "repo") -> list[SkillRun]:
        if not self.enabled:
            return []
        return SkillInvoker(self._runner).run(self.skills_for(target_kind), target)

    def to_findings(self, runs: list[SkillRun], *, repository: str = "") -> list[dict]:
        """Fold each successful skill run into Aegis candidate rows. If a skill emitted
        JSON findings, ingest them; otherwise keep its raw output as one skill-sourced
        candidate for human review. All marked unverified — Aegis's own validator and a
        human still gate them."""
        rows: list[dict] = []
        for run in runs:
            if not run.ok or not run.output:
                continue
            parsed = _try_json_findings(run.output)
            if parsed:
                for item in parsed:
                    rows.append(_skill_row(run.skill, item, repository))
            else:
                rows.append({
                    "json_answer": {
                        "vulnerability_type": f"skill:{run.skill}",
                        "file_path": "", "line": 0,
                        "summary": f"{run.skill} output (review manually)",
                        "explanation": run.output[:4000],
                    },
                    "severity": "medium",
                    "source": f"aegis:skill:{run.skill}",
                    "validation_status": "unverified",
                    "confidence": 0.0,
                })
        return rows


def _try_json_findings(output: str) -> list[dict]:
    """Best-effort: pull a JSON array/object of findings from a skill's stdout."""
    text = output.strip()
    start = text.find("[")
    obj = text.find("{")
    idx = min(x for x in (start, obj) if x >= 0) if (start >= 0 or obj >= 0) else -1
    if idx < 0:
        return []
    try:
        data, _ = json.JSONDecoder().raw_decode(text[idx:])   # ignore trailing noise
    except json.JSONDecodeError:
        return []
    if isinstance(data, list):
        return [d for d in data if isinstance(d, dict)]
    if isinstance(data, dict):
        for key in ("findings", "vulnerabilities", "results", "issues"):
            if isinstance(data.get(key), list):
                return [d for d in data[key] if isinstance(d, dict)]
        return [data]
    return []


def _skill_row(skill: str, item: dict, repository: str) -> dict:
    sev = str(item.get("severity") or item.get("impact") or "medium").lower()
    if sev not in ("critical", "high", "medium", "low"):
        sev = "medium"
    return {
        "json_answer": {
            "vulnerability_type": str(item.get("title") or item.get("type")
                                      or item.get("vulnerability") or f"skill:{skill}")[:200],
            "file_path": str(item.get("file") or item.get("path") or item.get("file_path") or ""),
            "line": int(item.get("line") or 0) if str(item.get("line") or "").isdigit() else 0,
            "summary": str(item.get("summary") or item.get("description")
                           or item.get("title") or "")[:300],
            "explanation": str(item.get("description") or item.get("detail")
                               or item.get("explanation") or "")[:4000],
        },
        "severity": sev,
        "source": f"aegis:skill:{skill}",
        "validation_status": "unverified",
        "confidence": float(item.get("confidence", 0.0) or 0.0),
        "target": f"{repository}:skill:{skill}",
    }
