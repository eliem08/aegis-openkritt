"""Guarded, localhost-only reproduction of confirmed findings on the repo's own instance.

Bridges the hunt's confirmed candidates to the reproduction agent: when a repo ships a
docker-compose, bring up a disposable LOCAL instance, let the agent craft->send->observe
->refine an HTTP request against it, and mark each confirmed finding
reproduced / not_reproduced by a DETERMINISTIC oracle on the response. Turns "candidate"
into "proven exploitable" — safely, on localhost, never a third party.

Boundaries (all must hold, else it no-ops):
* opt-in: AEGIS_ALLOW_REPRO=1 (running a repo's compose executes third-party service
  definitions, so it is never implicit);
* localhost-only: the agent + executor refuse any non-loopback target;
* needs a docker-compose in the checkout and a working docker.

Default OFF. Any failure degrades to "not attempted" — it never blocks the hunt.
"""

from __future__ import annotations

import os


def repro_enabled() -> bool:
    return os.environ.get("AEGIS_ALLOW_REPRO", "").strip() == "1"


# Safety primer for file-upload (CWE-434) reproduction: prove code execution on the LOCAL
# instance with a HARMLESS marker that only echoes a nonce — never a functional webshell,
# reverse shell, or destructive payload. The oracle is "did the marker echo back", which is
# sufficient proof of arbitrary-code execution without shipping a weapon.
_UPLOAD_SIGNS = ("upload", "cwe-434", "file upload", "webshell", "arbitrary file",
                 "unrestricted file")
_BENIGN_UPLOAD_NOTE = (
    "\n\nREPRODUCTION SAFETY (mandatory): this is a file-upload finding. On the local "
    "instance, upload ONLY a benign marker payload whose entire body is a single echo of a "
    "unique nonce (e.g. `<?php echo \"AEGIS-REPRO-\".\"<nonce>\"; ?>`). Prove execution by "
    "confirming the nonce appears in the response when the file is fetched. NEVER upload a "
    "functional webshell, reverse shell, command runner, or any destructive/persistent "
    "payload, even to prove impact.")


def _hypothesis_from_row(row: dict):
    from .agents.contracts import Hypothesis, VerificationProposal
    a = row.get("json_answer") or {}
    _blob = (str(a.get("vulnerability_type") or "") + " " + str(a.get("summary") or "") + " "
             + str(row.get("vuln_type") or "")).lower()
    _rationale = str(a.get("explanation") or a.get("summary") or "confirmed finding")[:4000]
    if any(s in _blob for s in _UPLOAD_SIGNS):
        _rationale = (_rationale + _BENIGN_UPLOAD_NOTE)[:4300]
    return Hypothesis(
        weakness=str(a.get("vulnerability_type") or "finding")[:200],
        title=str(a.get("summary") or a.get("vulnerability_type") or "finding")[:300],
        file_path=str(a.get("file_path") or "unknown")[:500],
        line=int(a.get("line") or 1) or 1,
        rationale=_rationale,
        confidence=0.9,
        verification=VerificationProposal(method="http",
                                          expected_observation="impact visible in the response"),
        entry_point=str(a.get("file_path") or "")[:600],
        attacker="an unauthenticated or low-privilege remote user",
        impact=str(a.get("summary") or "")[:600],
        severity=str(row.get("severity") or "medium") if str(row.get("severity")) in
        ("critical", "high", "medium", "low") else "medium",
    )


def maybe_reproduce(pin_dir, validated: dict, client, *, max_attempts: int = 4,
                    ready_path: str = "/", ready_timeout: float = 120.0) -> dict:
    """Reproduce confirmed rows in ``validated`` on a local instance. Annotates each
    confirmed row in place with a ``reproduction`` dict and returns a summary."""
    if not repro_enabled():
        return {"attempted": False, "reason": "AEGIS_ALLOW_REPRO != 1 (opt-in)"}
    from .local_instance import LocalInstanceError, has_compose, start_local_instance
    if not has_compose(pin_dir):
        return {"attempted": False, "reason": "no docker-compose in the checkout"}
    confirmed = [r for r in (validated.get("vulnerabilities") or [])
                 if (r.get("validation") or {}).get("verdict") == "confirmed"]
    if not confirmed:
        return {"attempted": False, "reason": "no confirmed findings to reproduce"}

    from .repro_agent import HttpExecutor, ReproductionAgent, ReproTarget
    reproduced = 0
    try:
        with start_local_instance(pin_dir, allow_compose_up=True, ready_path=ready_path,
                                  ready_timeout=ready_timeout) as inst:
            agent = ReproductionAgent(client, HttpExecutor(), max_attempts=max_attempts)
            target = ReproTarget(base_url=inst.base_url)     # localhost; agent re-checks
            for row in confirmed:
                try:
                    res = agent.reproduce(_hypothesis_from_row(row), target)
                    row["reproduction"] = {"verdict": res.verdict, "summary": res.summary,
                                           "attempts": len(res.attempts),
                                           "instance": inst.base_url}
                    if res.triggered:
                        reproduced += 1
                except Exception as exc:
                    row["reproduction"] = {"verdict": "error",
                                           "summary": f"{type(exc).__name__}: {exc}"[:200]}
        return {"attempted": True, "confirmed": len(confirmed), "reproduced": reproduced,
                "instance_url": "http://127.0.0.1 (disposable, torn down)"}
    except LocalInstanceError as exc:
        return {"attempted": False, "reason": f"instance: {exc}"[:200]}
    except Exception as exc:
        return {"attempted": False, "reason": f"{type(exc).__name__}: {exc}"[:200]}
