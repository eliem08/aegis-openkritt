"""Aegis-native per-finding triage enrichment (runs in Aegis's own DeepSeek pipeline).

After validation confirms a finding, a professional submission still needs triage: an
adversarial trust-model check, a defensible CVSS score, whether it's standalone or a
chain, whether it's likely a known/duplicate, a program-aware bounty estimate, and a
remediation sketch (a suggested fix earns a bonus on many programs). This module does
all of that in ONE DeepSeek call per finding and attaches the result to the report row
under ``enrichment`` — no open-kritt, no extra services.

All prompt content is original. The call is strict-JSON and validated; a failure leaves
the finding un-enriched rather than sinking the pipeline.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class FindingEnrichment(BaseModel):
    model_config = ConfigDict(extra="ignore")
    # adversarial trust-model gate — does it survive "what must the attacker hold?"
    trust_model_holds: bool = True
    trust_model: str = Field(default="", max_length=1200)
    # defensible severity
    cvss_score: float = Field(default=0.0, ge=0, le=10)
    cvss_vector: str = Field(default="", max_length=120)
    severity_band: str = Field(default="medium", max_length=12)
    # exploitability
    chain_required: bool = False
    preconditions: str = Field(default="", max_length=800)
    exploit_practicality: str = Field(default="", max_length=40)   # trivial/moderate/hard/theoretical
    # prior art
    likely_duplicate: bool = False
    prior_art: str = Field(default="", max_length=400)
    # money
    bounty_min: float = Field(default=0.0, ge=0)
    bounty_likely: float = Field(default=0.0, ge=0)
    bounty_reasoning: str = Field(default="", max_length=600)
    # the fix
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


def enrich_finding(client, row: dict, *, program_url: str = "") -> dict:
    """Attach a triage ``enrichment`` block to one finding row (in place). Best-effort."""
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
        data = client.complete_json([
            {"role": "system", "content": system},
            {"role": "user", "content": "Triage this finding:\n" + json.dumps(finding)},
        ])
        enrichment = FindingEnrichment.model_validate(data)
    except Exception:                                # bad json / validation / network
        return row
    row["enrichment"] = enrichment.model_dump(mode="json")
    return row


def enrich_report(report_path, client, *, program_url: str = "",
                  only_confirmed: bool = True, progress=None) -> dict:
    """Enrich each (confirmed) finding in a persisted report and rewrite it."""
    import json
    from pathlib import Path

    path = Path(report_path)
    data = json.loads(path.read_text(encoding="utf-8"))
    rows = [r for r in (data.get("vulnerabilities") or [])
            if not only_confirmed or (r.get("validation") or {}).get("verdict") == "confirmed"]
    for index, row in enumerate(rows, start=1):
        if progress:
            progress(index, len(rows))
        enrich_finding(client, row, program_url=program_url)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return {"enriched": len(rows)}
