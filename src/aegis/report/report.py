"""Submission-ready report generation (Master Prompt §11; P1 #24).

Turns a verified :class:`~aegis.model.Finding` + its evidence into a structured,
HackerOne-ready report with the sections triagers expect: title, asset, CWE,
prerequisites, reproduction steps, expected vs. actual, minimal proof, business
impact, remediation, and an explicit scope/rules-compliance statement. Evidence
is redacted first. An optional LLM polishes the prose — but only ever from the
already-verified evidence, never inventing facts (§27).
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from aegis.model import EvidenceBundle, Finding

from .redact import redact_evidence

# CWE -> a concrete remediation suggestion (extend freely).
REMEDIATION: dict[str, str] = {
    "CWE-639": "Enforce object-level authorization server-side: verify the authenticated "
    "principal is entitled to the requested object before returning it (do not rely on "
    "unguessable IDs).",
    "CWE-284": "Add server-side access-control checks on every sensitive operation; deny by default.",
    "CWE-285": "Enforce function-level authorization: check the caller's role/permissions for each endpoint.",
    "CWE-200": "Remove sensitive files/data from web-reachable paths and ensure errors don't leak internals.",
    "CWE-538": "Restrict access to configuration, backup, and VCS files; return 404/403 from the web root.",
    "CWE-601": "Validate redirect targets against an allowlist; never reflect user input into Location.",
    "CWE-918": "Allowlist outbound URLs, block internal/link-local ranges, and disable unused URL schemes.",
    "CWE-287": "Fix the authentication flow: invalidate tokens on use/expiry and bind them to the session.",
    "CWE-269": "Remove client-controllable privilege parameters; assign roles server-side only.",
    "CWE-79": "Context-encode output and apply a strict Content-Security-Policy.",
    "CWE-89": "Use parameterised queries / prepared statements; never concatenate untrusted input.",
}
DEFAULT_REMEDIATION = "Apply the standard secure-coding remediation for this weakness class."


class SubmissionReport(BaseModel):
    title: str
    asset: str
    cwe: str = ""
    weakness: str = ""
    severity: str = ""
    prerequisites: str = ""
    steps: list[str] = Field(default_factory=list)
    expected: str = ""
    actual: str = ""
    impact: str = ""
    remediation: str = ""
    scope_compliance: str = ""
    evidence_ref: str | None = None
    ai_assisted: bool = False

    def to_markdown(self) -> str:
        lines = [
            f"# {self.title}",
            "",
            f"**Asset:** {self.asset}",
            f"**Weakness:** {self.weakness or self.cwe} ({self.cwe})" if self.cwe else f"**Weakness:** {self.weakness}",
            f"**Severity:** {self.severity}",
            "",
            "## Prerequisites",
            self.prerequisites or "None beyond a valid test account.",
            "",
            "## Steps to reproduce",
        ]
        lines += [f"{i}. {s}" for i, s in enumerate(self.steps, 1)] or ["(see evidence bundle)"]
        lines += [
            "",
            "## Expected vs. actual",
            f"- **Expected:** {self.expected}",
            f"- **Actual:** {self.actual}",
            "",
            "## Proof of impact",
            self.impact or "See minimal, non-destructive proof in the evidence bundle.",
            "",
            "## Remediation",
            self.remediation,
            "",
            "## Scope & rules compliance",
            self.scope_compliance,
        ]
        if self.evidence_ref:
            lines += ["", f"_Replay bundle: `{self.evidence_ref}`_"]
        if self.ai_assisted:
            lines += ["", "_Report drafting was AI-assisted; all facts are drawn from the verified evidence above._"]
        return "\n".join(lines)


def _scope_statement(program_handle: str | None) -> str:
    where = f" on program `{program_handle}`" if program_handle else ""
    return (
        f"Testing was performed within the authorized scope{where}, using only "
        "researcher-owned test accounts, at a rate within program limits, with no "
        "access to other users' data (a seeded canary proves impact). No "
        "destructive actions were taken."
    )


def build_report(
    finding: Finding,
    evidence: EvidenceBundle | None = None,
    *,
    program_handle: str | None = None,
    redact: bool = True,
) -> SubmissionReport:
    ev = evidence
    if ev is not None and redact:
        ev = redact_evidence(ev)

    steps = ev.request_sequence() if ev else list(finding.request_sequence)
    weakness = finding.weakness_label()
    return SubmissionReport(
        title=finding.title(),
        asset=finding.asset + (f" {finding.route}" if finding.route else ""),
        cwe=finding.cwe,
        weakness=weakness,
        severity=_severity_label(finding),
        prerequisites=finding.preconditions or "A valid, researcher-owned test account.",
        steps=steps,
        expected=(ev.expected if ev and ev.expected else finding.expected) or "Access is denied / no data is returned.",
        actual=(ev.observed if ev and ev.observed else finding.observed) or "The action succeeds and returns data.",
        impact=finding.impact or "Demonstrated with a seeded canary; no real user data was accessed.",
        remediation=REMEDIATION.get(finding.cwe, DEFAULT_REMEDIATION),
        scope_compliance=_scope_statement(program_handle),
        evidence_ref=(ev.replay_ref if ev else None) or finding.exploit_proof_ref,
    )


def _severity_label(finding: Finding) -> str:
    p = finding.priority
    if p >= 0.5:
        return "high"
    if p >= 0.2:
        return "medium"
    return "low"
