"""Aegis-native per-finding triage enrichment.

After validation confirms a finding, submission-quality triage still needs trust-model,
severity, exploitability, duplicate, payout and remediation context.  Jarvis now decides
which findings deserve this additional model spend: when a canonical ``jarvis`` annotation
exists and ``should_escalate`` is false, enrichment is skipped rather than paid for.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class FindingEnrichment(BaseModel):
    model_config = ConfigDict(extra="ignore")
    trust_model_holds: bool = True
    trust_model: str = Field(default="", max_length=1200)
    cvss_score: float = Field(default=0.0, ge=0, le=10)
    cvss_vector: str = Field(default="", max_length=120)
    severity_band: str = Field(default="medium", max_length=12)
    chain_required: bool = False
    preconditions: str = Field(default="", max_length=800)
    exploit_practicality: str = Field(default="", max_length=40)
    likely_duplicate: bool = False
    prior_art: str = Field(default="", max_length=400)
    bounty_min: float = Field(default=0.0, ge=0)
    bounty_likely: float = Field(default=0.0, ge=0)
    bounty_reasoning: str = Field(default="", max_length=600)
    remediation: str = Field(default="", max_length=1500)


_SYSTEM = (
    "You are a senior bug-bounty triage engineer. Given ONE validated finding, produce a "
    "professional triage record. Be adversarial and honest — do not inflate.\n"
    "1. TRUST MODEL: state what the attacker must already possess and what authenticates "
    "the entry point. If it needs a secret/role they cannot obtain, or a by-design-trusted "
    "role, set trust_model_holds=false — UNLESS the flaw bypasses a FURTHER control that "
    "should still apply on top of a held capability (a password, ownership, second "
    "factor), which IS real.\n"
    "2. CVSS 4.0 base: give a vector and a numeric base score (0-10) and band, from what "
    "the finding actually supports.\n"
    "3. EXPLOITABILITY: standalone vs chain, the preconditions, and a practicality rating "
    "(trivial/moderate/hard/theoretical).\n"
    "4. PRIOR ART: is it likely a known CVE/advisory or an already-patched pattern "
    "(duplicate)? Name any match.\n"
    "5. BOUNTY: using the program at {{program_url}}, estimate a conservative floor and a "
    "likely payout (USD) anchored to its reward tiers for the matching severity.\n"
    "6. REMEDIATION: the minimal correct fix — name the missing guard and where it goes.\n\n"
    "Return strict json with exactly these fields: trust_model_holds (bool), trust_model, "
    "cvss_score (number), cvss_vector, severity_band, chain_required (bool), preconditions, "
    "exploit_practicality, likely_duplicate (bool), prior_art, bounty_min (number), "
    "bounty_likely (number), bounty_reasoning, remediation."
)


def _jarvis_wants_more_work(row: dict) -> bool:
    """Compatibility-safe economic gate: old rows without Jarvis remain eligible."""
    jarvis = row.get("jarvis")
    if not isinstance(jarvis, dict):
        return True
    return bool(jarvis.get("should_escalate", False))


def enrich_finding(client, row: dict, *, program_url: str = "") -> dict:
    """Attach a triage ``enrichment`` block to one finding row (in place). Best-effort."""
    if not _jarvis_wants_more_work(row):
        row["enrichment_skipped"] = "jarvis_deferred"
        return row
    answer = row.get("json_answer") or {}
    finding = {
        "vulnerability_type": answer.get("vulnerability_type", ""),
        "severity": answer.get("severity") or row.get("severity", ""),
        "summary": answer.get("summary", ""),
        "explanation": answer.get("explanation", ""),
        "location": f"{answer.get('file_path','')}:{answer.get('line','')}",
        "trigger_flow": answer.get("trigger_flow", ""),
        "malicious_actor": answer.get("malicious_actor", ""),
        "agreement": f"{row.get('agreement', 1)}/{row.get('samples', 1)} agents",
        "program_url": program_url,
    }
    system = _SYSTEM.replace("{{program_url}}", program_url or "the configured program")
    try:
        import json

        data = client.complete_json(
            [
                {"role": "system", "content": system},
                {"role": "user", "content": "Triage this finding:\n" + json.dumps(finding)},
            ]
        )
        enrichment = FindingEnrichment.model_validate(data)
    except Exception:
        return row
    row["enrichment"] = enrichment.model_dump(mode="json")
    return row


def enrich_report(
    report_path,
    client,
    *,
    program_url: str = "",
    only_confirmed: bool = True,
    progress=None,
) -> dict:
    """Enrich confirmed, Jarvis-escalated findings and rewrite the report."""
    import json
    from pathlib import Path

    path = Path(report_path)
    data = json.loads(path.read_text(encoding="utf-8"))
    candidates = [
        row
        for row in (data.get("vulnerabilities") or [])
        if not only_confirmed or (row.get("validation") or {}).get("verdict") == "confirmed"
    ]
    rows = [row for row in candidates if _jarvis_wants_more_work(row)]
    for index, row in enumerate(rows, start=1):
        if progress:
            progress(index, len(rows))
        enrich_finding(client, row, program_url=program_url)
    skipped = len(candidates) - len(rows)
    data.setdefault("scan", {}).setdefault("jarvis", {})["enrichment_deferred"] = skipped
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return {"enriched": len(rows), "jarvis_deferred": skipped}
