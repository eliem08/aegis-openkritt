"""Guarded localhost-only reproduction of Jarvis-escalated findings.

A disposable compose instance is a real local state change.  It remains explicit opt-in via
``AEGIS_ALLOW_REPRO=1`` and now also consumes Jarvis's canonical Reproduction policy decision.
Successful deterministic reproduction advances the canonical evidence lifecycle through
runtime-observed -> oracle-passed -> locally-reproduced; a string label alone cannot do so.
"""

from __future__ import annotations

import os


def repro_enabled() -> bool:
    return os.environ.get("AEGIS_ALLOW_REPRO", "").strip() == "1"


_UPLOAD_SIGNS = (
    "upload",
    "cwe-434",
    "file upload",
    "webshell",
    "arbitrary file",
    "unrestricted file",
)
_BENIGN_UPLOAD_NOTE = (
    "\n\nREPRODUCTION SAFETY (mandatory): this is a file-upload finding. On the local "
    "instance, upload ONLY a benign marker payload whose entire body is a single echo of a "
    "unique nonce. Prove execution by confirming the nonce appears in the response when the "
    "file is fetched. NEVER upload a functional webshell, reverse shell, command runner, or "
    "any destructive/persistent payload, even to prove impact."
)


def _jarvis_reproduction_allowed(row: dict) -> bool:
    """Compatibility-safe Reproduction decision lookup.

    Old reports without a Jarvis annotation keep the existing opt-in behavior. New Jarvis rows
    require both economic escalation and the second quality proposal (Reproduction) to be
    explicitly approved.
    """
    jarvis = row.get("jarvis")
    if not isinstance(jarvis, dict):
        return True
    if not jarvis.get("should_escalate", False):
        return False
    quality = jarvis.get("quality_policy") or []
    if len(quality) < 2:
        return False
    return bool(quality[1].get("approved", False))


def _hypothesis_from_row(row: dict):
    from .agents.contracts import Hypothesis, VerificationProposal

    answer = row.get("json_answer") or {}
    blob = (
        str(answer.get("vulnerability_type") or "")
        + " "
        + str(answer.get("summary") or "")
        + " "
        + str(row.get("vuln_type") or "")
    ).lower()
    rationale = str(
        answer.get("explanation") or answer.get("summary") or "confirmed finding"
    )[:4000]
    if any(sign in blob for sign in _UPLOAD_SIGNS):
        rationale = (rationale + _BENIGN_UPLOAD_NOTE)[:4300]
    return Hypothesis(
        weakness=str(answer.get("vulnerability_type") or "finding")[:200],
        title=str(answer.get("summary") or answer.get("vulnerability_type") or "finding")[:300],
        file_path=str(answer.get("file_path") or "unknown")[:500],
        line=int(answer.get("line") or 1) or 1,
        rationale=rationale,
        confidence=0.9,
        verification=VerificationProposal(
            method="http",
            expected_observation="impact visible in the response",
        ),
        entry_point=str(answer.get("file_path") or "")[:600],
        attacker="an unauthenticated or low-privilege remote user",
        impact=str(answer.get("summary") or "")[:600],
        severity=(
            str(row.get("severity") or "medium")
            if str(row.get("severity")) in ("critical", "high", "medium", "low")
            else "medium"
        ),
    )


def maybe_reproduce(
    pin_dir,
    validated: dict,
    client,
    *,
    max_attempts: int = 4,
    ready_path: str = "/",
    ready_timeout: float = 120.0,
) -> dict:
    """Reproduce Jarvis-approved confirmed rows on an explicit disposable local instance."""
    if not repro_enabled():
        return {"attempted": False, "reason": "AEGIS_ALLOW_REPRO != 1 (opt-in)"}

    from .local_instance import LocalInstanceError, has_compose, start_local_instance

    if not has_compose(pin_dir):
        return {"attempted": False, "reason": "no docker-compose in the checkout"}
    all_confirmed = [
        row
        for row in (validated.get("vulnerabilities") or [])
        if (row.get("validation") or {}).get("verdict") == "confirmed"
    ]
    confirmed = [row for row in all_confirmed if _jarvis_reproduction_allowed(row)]
    if not confirmed:
        return {
            "attempted": False,
            "reason": "no confirmed findings cleared the Jarvis reproduction gate",
            "jarvis_deferred": len(all_confirmed),
        }

    from .repro_agent import HttpExecutor, ReproductionAgent, ReproTarget

    reproduced = 0
    repository = str((validated.get("scan") or {}).get("repository") or "")
    report_root = os.environ.get("AEGIS_REPORT_DIR", "reports")
    try:
        with start_local_instance(
            pin_dir,
            allow_compose_up=True,
            ready_path=ready_path,
            ready_timeout=ready_timeout,
        ) as instance:
            agent = ReproductionAgent(client, HttpExecutor(), max_attempts=max_attempts)
            target = ReproTarget(base_url=instance.base_url)
            for row in confirmed:
                try:
                    result = agent.reproduce(_hypothesis_from_row(row), target)
                    row["reproduction"] = {
                        "verdict": result.verdict,
                        "summary": result.summary,
                        "attempts": len(result.attempts),
                        "instance": instance.base_url,
                    }
                    if result.triggered:
                        reproduced += 1
                        try:
                            from .jarvis_bridge import advance_reproduction

                            advance_reproduction(
                                row,
                                repository,
                                report_root=report_root,
                            )
                        except Exception:
                            # Keep the raw reproduction evidence even if lifecycle persistence
                            # fails; never fabricate a later stage.
                            pass
                except Exception as exc:
                    row["reproduction"] = {
                        "verdict": "error",
                        "summary": f"{type(exc).__name__}: {exc}"[:200],
                    }
        return {
            "attempted": True,
            "confirmed": len(confirmed),
            "reproduced": reproduced,
            "jarvis_deferred": len(all_confirmed) - len(confirmed),
            "instance_url": "http://127.0.0.1 (disposable, torn down)",
        }
    except LocalInstanceError as exc:
        return {"attempted": False, "reason": f"instance: {exc}"[:200]}
    except Exception as exc:
        return {"attempted": False, "reason": f"{type(exc).__name__}: {exc}"[:200]}
