"""Hostile-triager pass — the adversarial gate that tries to REJECT a finding.

The triager consumes the canonical Jarvis seam before spending another model call.
Each still-confirmed row is normalized into ``agentic_os`` lifecycle/economics, gets a
persistent mission when positive-EV, and is triaged only when Jarvis authorizes the
Skeptic quality step. Low/negative-EV rows are deferred, never mislabeled false positives.
"""

from __future__ import annotations

import json
import os

_VERDICTS = ("pass", "downgrade", "needs_evidence", "reject")

_SYSTEM = (
    "You are a HOSTILE bug-bounty triager reviewing a finding you do NOT believe. Your job "
    "is to find the reason it should be rejected, not to help it. Assume the reporter is "
    "over-claiming until the supplied code proves otherwise.\n\n"
    "Re-derive the claim from scratch against the code and answer, strictly:\n"
    "1. SCOPE: is the vulnerable asset inside the program scope provided? If it is a "
    "dependency, test/dev file, or an asset the scope excludes, REJECT.\n"
    "2. ATTACKER POSITION: is the stated attacker realistic (unauth or low-priv remote)? If "
    "the bug only works with admin/root/local/physical access or tooling the attacker would "
    "not have, REJECT or DOWNGRADE.\n"
    "3. PREREQUISITES: list every precondition. If any is not attacker-satisfiable, say so.\n"
    "4. REAL ISSUE: is this a security defect, or the product working as intended / a "
    "self-inflicted config? If intended behavior, REJECT.\n"
    "5. SEVERITY: give the severity the impact actually justifies (may be lower than claimed).\n\n"
    "You may NOT invent a new attack angle to save the report — judge only the claim as "
    "stated. Choose exactly one verdict: 'pass' (defensible as-is), 'downgrade' (real but "
    "lower severity), 'needs_evidence' (plausible but unproven from this code), 'reject' "
    "(out of scope / not a bug / unrealistic attacker).\n"
    'Return ONLY JSON: {"verdict":"pass|downgrade|needs_evidence|reject",'
    '"scope_ok":true|false,"attacker_realistic":true|false,'
    '"corrected_severity":"critical|high|medium|low|info","reason":"<=2 sentences",'
    '"prerequisites":["..."]}'
)


def _finding_brief(row: dict) -> dict:
    answer = row.get("json_answer") or {}
    return {
        "vulnerability_type": (
            answer.get("vulnerability_type") or row.get("vuln_type") or "finding"
        ),
        "summary": answer.get("summary") or row.get("summary") or "",
        "location": row.get("location") or answer.get("file_path") or "",
        "line": answer.get("line"),
        "claimed_severity": row.get("severity") or "medium",
        "explanation": (answer.get("explanation") or answer.get("summary") or "")[:2500],
        "attacker": row.get("attacker") or answer.get("attacker") or "",
    }


class HostileTriager:
    """One adversarial review per finding. ``client.complete_json`` does the model call."""

    def __init__(self, client) -> None:
        self._client = client

    def triage(self, row: dict, *, scope_text: str = "", source: str = "") -> dict:
        payload = {
            "program_scope": (
                scope_text
                or "(no scope supplied — judge on general in-scope reasoning; still reject "
                "dependency/test/dev assets)"
            )[:6000],
            "finding": _finding_brief(row),
            "source_excerpt": (source or "")[:8000],
        }
        try:
            raw = self._client.complete_json(
                [
                    {"role": "system", "content": _SYSTEM},
                    {
                        "role": "user",
                        "content": "Triage this finding. Reject unless it defends itself:\n"
                        + json.dumps(payload),
                    },
                ]
            )
        except Exception as exc:
            return {
                "verdict": "unreviewed",
                "reason": f"triager error: {type(exc).__name__}: {str(exc)[:160]}",
            }
        verdict = str(raw.get("verdict", "")).strip().lower()
        if verdict not in _VERDICTS:
            return {"verdict": "unreviewed", "reason": "triager returned an invalid verdict"}
        severity = str(raw.get("corrected_severity", "")).strip().lower()
        return {
            "verdict": verdict,
            "scope_ok": bool(raw.get("scope_ok", True)),
            "attacker_realistic": bool(raw.get("attacker_realistic", True)),
            "corrected_severity": (
                severity
                if severity in ("critical", "high", "medium", "low", "info")
                else str(row.get("severity") or "medium")
            ),
            "reason": str(raw.get("reason", ""))[:400],
            "prerequisites": [str(item)[:160] for item in (raw.get("prerequisites") or [])][:8],
        }


def _confirmed(row: dict) -> bool:
    return (
        (row.get("validation") or {}).get("verdict") == "confirmed"
        or row.get("status") == "confirmed"
        or bool(row.get("confirmed"))
    )


def _runtime_target(report: dict):
    """Rebuild the live HuntTarget from the canonical registry without inventing scope."""
    from .auto_hunt import HuntTarget
    from .registry import load_registry

    repository = str((report.get("scan") or {}).get("repository") or "").strip()
    fallback = HuntTarget(repository=repository)
    if not repository:
        return fallback
    normalized = repository.strip("/").lower()
    for program in load_registry():
        in_scope = {str(item).strip("/").lower() for item in (program.targets or [])}
        if normalized not in in_scope:
            continue
        return HuntTarget(
            repository=repository,
            handle=program.handle,
            reward_ceiling=float(program.reward_ceiling or 0.0),
            findability=float(program.findability or 0.5),
            subpath=program.subpath,
            kind=program.kind,
            saturation=float(program.saturation or 0.0),
        )
    return fallback


def _jarvis_quality_gate(report: dict, row: dict):
    """Return the canonical Jarvis finding decision, or ``None`` on compatibility failure."""
    if os.environ.get("AEGIS_JARVIS_LIVE", "1").strip() == "0":
        return None
    try:
        from .jarvis_bridge import evaluate_finding
        from .target_authorization import gate

        target = _runtime_target(report)
        if not target.repository:
            return None
        authorization = gate(target.repository, persist=False)
        return evaluate_finding(
            row,
            target,
            authorization,
            report_root=os.environ.get("AEGIS_REPORT_DIR", "reports"),
            model_egress_allowed=True,
            local_lab_available=os.environ.get("AEGIS_ALLOW_REPRO", "").strip() == "1",
        )
    except Exception:
        # A bridge compatibility failure cannot silently classify a finding as false. The
        # existing hostile triager remains the fallback until the integration is repaired.
        return None


def _skeptic_decision(row: dict) -> dict | None:
    """The canonical quality sequence is Skeptic -> Reproduction -> Evidence."""
    quality = (row.get("jarvis") or {}).get("quality_policy") or []
    return quality[0] if quality else None


def triage_report(
    report: dict,
    client,
    *,
    scope_text: str = "",
    source_for=None,
    on_event=None,
) -> dict:
    """Adversarially review economically worthwhile, policy-approved confirmed rows."""
    emit = on_event or (lambda *_: None)
    rows = [row for row in (report.get("vulnerabilities") or []) if _confirmed(row)]
    triager = HostileTriager(client)
    passed = rejected = downgraded = flagged = deferred = 0
    for row in rows:
        jarvis = _jarvis_quality_gate(report, row)
        if jarvis is not None:
            skeptic = _skeptic_decision(row)
            if not jarvis.should_escalate or (skeptic and not skeptic.get("approved", False)):
                reason = (
                    "Jarvis deferred further model spend: non-positive/low expected net value"
                    if not jarvis.should_escalate
                    else str(skeptic.get("reason") or "skeptic proposal vetoed")
                )
                row["jarvis_deferred"] = True
                row["triage"] = {"verdict": "deferred", "reason": reason[:400]}
                deferred += 1
                emit(
                    "triage",
                    {
                        "location": row.get("location", ""),
                        "verdict": "deferred",
                        "reason": reason[:160],
                    },
                )
                continue

        source = ""
        if source_for is not None:
            try:
                source = source_for(row) or ""
            except Exception:
                source = ""
        result = triager.triage(row, scope_text=scope_text, source=source)
        row["triage"] = result
        verdict = result.get("verdict")
        if verdict == "reject":
            row["rejected_by_triager"] = True
            row.setdefault("validation", {})["verdict"] = "rejected"
            row["status"] = "rejected"
            rejected += 1
        elif verdict == "downgrade":
            row["severity"] = result.get("corrected_severity", row.get("severity"))
            downgraded += 1
        elif verdict == "needs_evidence":
            flagged += 1
        elif verdict == "pass":
            passed += 1
        emit(
            "triage",
            {
                "location": result.get("location") or row.get("location", ""),
                "verdict": verdict,
                "reason": result.get("reason", "")[:160],
            },
        )
    summary = {
        "reviewed": len(rows) - deferred,
        "passed": passed,
        "rejected": rejected,
        "downgraded": downgraded,
        "needs_evidence": flagged,
        "jarvis_deferred": deferred,
    }
    report.setdefault("triage_summary", {}).update(summary)
    return summary
