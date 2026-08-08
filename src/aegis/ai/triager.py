"""Hostile-triager pass — the adversarial Skeptic gate for Jarvis.

The citation validator establishes source support. This module is the independent Skeptic:
it tries to reject every economically-promoted claim without inventing a new attack angle.
Before any LLM call, the canonical Jarvis economics gate chooses a bounded positive-net-value
portfolio. Deferred findings remain auditable source-supported candidates but do not consume
expensive council/reproduction budget in this run.
"""

from __future__ import annotations

import json

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
    a = row.get("json_answer") or {}
    return {
        "vulnerability_type": a.get("vulnerability_type") or row.get("vuln_type") or "finding",
        "summary": a.get("summary") or row.get("summary") or "",
        "location": row.get("location") or a.get("file_path") or "",
        "line": a.get("line"),
        "claimed_severity": row.get("severity") or "medium",
        "explanation": (a.get("explanation") or a.get("summary") or "")[:2500],
        "attacker": row.get("attacker") or a.get("attacker") or "",
    }


class HostileTriager:
    """One adversarial review per finding. ``client.complete_json(messages)`` does the call."""

    def __init__(self, client) -> None:
        self._client = client

    def triage(self, row: dict, *, scope_text: str = "", source: str = "") -> dict:
        payload = {
            "program_scope": (scope_text or "(no scope supplied — judge on general in-scope "
                              "reasoning; still reject dependency/test/dev assets)")[:6000],
            "finding": _finding_brief(row),
            "source_excerpt": (source or "")[:8000],
        }
        try:
            raw = self._client.complete_json([
                {"role": "system", "content": _SYSTEM},
                {"role": "user", "content": "Triage this finding. Reject unless it defends "
                                            "itself:\n" + json.dumps(payload)},
            ])
        except Exception as exc:
            return {"verdict": "unreviewed", "reason": f"triager error: "
                    f"{type(exc).__name__}: {str(exc)[:160]}"}
        verdict = str(raw.get("verdict", "")).strip().lower()
        if verdict not in _VERDICTS:
            return {"verdict": "unreviewed", "reason": "triager returned an invalid verdict"}
        sev = str(raw.get("corrected_severity", "")).strip().lower()
        return {
            "verdict": verdict,
            "scope_ok": bool(raw.get("scope_ok", True)),
            "attacker_realistic": bool(raw.get("attacker_realistic", True)),
            "corrected_severity": sev if sev in ("critical", "high", "medium", "low", "info")
            else str(row.get("severity") or "medium"),
            "reason": str(raw.get("reason", ""))[:400],
            "prerequisites": [str(x)[:160] for x in (raw.get("prerequisites") or [])][:8],
        }


def _confirmed(row: dict) -> bool:
    return (row.get("validation") or {}).get("verdict") == "confirmed" or \
        row.get("status") == "confirmed" or bool(row.get("confirmed"))


def _defer_economically(row: dict) -> None:
    econ = (row.get("jarvis") or {}).get("economics") or {}
    priority = str(econ.get("priority") or "retain_cheap")
    row["triage"] = {
        "verdict": "deferred_economics",
        "reason": f"Jarvis economics gate: {priority}; preserved as source-supported candidate",
    }
    row["economic_deferred"] = True
    row.setdefault("validation", {})["verdict"] = "unresolved"
    row["validation"]["reason"] = (
        str(row["validation"].get("reason") or "")
        + f" [Jarvis: {priority}; expensive council deferred]"
    ).strip()
    row["status"] = "unresolved"


def triage_report(report: dict, client, *, scope_text: str = "",
                  source_for=None, on_event=None) -> dict:
    """Run the economically-scheduled hostile council over confirmed source findings."""
    emit = on_event or (lambda *_: None)
    rows = [r for r in (report.get("vulnerabilities") or []) if _confirmed(r)]

    try:
        from .jarvis_runtime import prioritize_council
        selected, deferred = prioritize_council(rows)
    except Exception:
        selected, deferred = rows, []

    for row in deferred:
        _defer_economically(row)
        emit("triage", {"location": row.get("location", ""),
                        "verdict": "deferred_economics",
                        "reason": "below current Jarvis council allocation threshold"})

    triager = HostileTriager(client)
    passed = rejected = downgraded = flagged = 0
    for row in selected:
        src = ""
        if source_for is not None:
            try:
                src = source_for(row) or ""
            except Exception:
                src = ""
        t = triager.triage(row, scope_text=scope_text, source=src)
        row["triage"] = t
        v = t.get("verdict")
        if v == "reject":
            row["rejected_by_triager"] = True
            row.setdefault("validation", {})["verdict"] = "rejected"
            row["status"] = "rejected"
            rejected += 1
        elif v == "downgrade":
            row["severity"] = t.get("corrected_severity", row.get("severity"))
            downgraded += 1
        elif v == "needs_evidence":
            flagged += 1
        elif v == "pass":
            passed += 1
        try:
            from .jarvis_runtime import annotate_skeptic
            annotate_skeptic(row)
        except Exception:
            pass
        emit("triage", {"location": t.get("location") or row.get("location", ""),
                        "verdict": v, "reason": t.get("reason", "")[:160]})
    summary = {"reviewed": len(selected), "deferred_economics": len(deferred),
               "passed": passed, "rejected": rejected,
               "downgraded": downgraded, "needs_evidence": flagged}
    report.setdefault("triage_summary", {}).update(summary)
    return summary
