"""open·kritt interop: ingest its finding export into Aegis candidates.

The adapter is arm's-length — it maps open·kritt's public finding contract (the
``json_answer`` eight-key rows plus dedupe/rank wrapper) into unverified Aegis
candidates. No open·kritt source is vendored; every import stays a hypothesis.
"""

from __future__ import annotations

import json

from aegis.active import surface_candidates
from aegis.integrations import (
    OPENKRITT_FINDING_KEYS,
    ingest_openkritt_findings,
    to_openkritt_output_format,
)
from aegis.model import Candidate

# A representative open·kritt export (two clustered rows + a canonical high-sev).
EXPORT = {
    "vulnerabilities": [
        {
            "id": 1,
            "dedupe_is_canonical": True,
            "bounty_rank_impact_level": "critical",
            "json_answer": {
                "vulnerability_type": "Reentrancy",
                "file_path": "contracts/Vault.sol",
                "line": 42,
                "summary": "withdraw() calls out before settling balances",
                "explanation": "The external call precedes the balance write, enabling a re-entrant drain.",
                "trigger_flow": "deposit -> withdraw -> fallback re-enters withdraw",
                "malicious_input_example": "PAYLOAD_REENTER_SENTINEL",
                "malicious_actor": "any external caller",
                "exploitable": True,
            },
        },
        {
            "id": 2,
            "dedupe_is_canonical": False,               # a duplicate open·kritt already clustered
            "bounty_rank_impact_level": "critical",
            "json_answer": {"vulnerability_type": "Reentrancy", "file_path": "contracts/Vault.sol",
                            "line": 42, "summary": "dup", "explanation": "", "trigger_flow": "",
                            "malicious_input_example": "", "malicious_actor": ""},
        },
        {
            "id": 3,
            "dedupe_is_canonical": True,
            "bounty_rank_impact_level": "high",
            "json_answer": {
                "vulnerability_type": "Missing access control on privileged function",
                "file_path": "contracts/Vault.sol", "line": 55,
                "summary": "emergencyDrain has no owner check",
                "explanation": "Anyone can call emergencyDrain and transfer the balance.",
                "trigger_flow": "call emergencyDrain to move the balance",
                "malicious_input_example": "PAYLOAD_DRAIN_SENTINEL",
                "malicious_actor": "unauthenticated user",
            },
        },
    ]
}


def test_ingests_canonical_rows_and_maps_types_to_cwe():
    candidates = ingest_openkritt_findings(EXPORT)
    assert len(candidates) == 2                          # the non-canonical dup is dropped
    cwes = {c.cwe for c in candidates}
    assert cwes == {"CWE-841", "CWE-284"}                # reentrancy + access control
    reent = next(c for c in candidates if c.cwe == "CWE-841")
    assert reent.code_location == "contracts/Vault.sol:42"
    assert reent.worker == "integration:openkritt"
    assert reent.business_impact == 0.95 and reent.impact == "critical"


def test_imported_findings_are_unverified_candidates():
    candidates = ingest_openkritt_findings(EXPORT)
    # Candidate != verdict: open·kritt's exploitable/rank is a hint, not proof.
    assert all(isinstance(c, Candidate) and c.evidence_id is None for c in candidates)


def test_exploit_payload_is_never_surfaced():
    candidates = ingest_openkritt_findings(EXPORT)
    blob = " ".join(
        f"{c.observed} {c.expected} {c.preconditions} {c.identity_context} {c.impact}"
        for c in candidates)
    assert "PAYLOAD_REENTER_SENTINEL" not in blob       # malicious_input_example withheld
    assert "PAYLOAD_DRAIN_SENTINEL" not in blob


def test_min_impact_filters_below_the_floor():
    only_critical = ingest_openkritt_findings(EXPORT, min_impact="critical")
    assert {c.cwe for c in only_critical} == {"CWE-841"}


def test_accepts_a_json_string_and_a_bare_list():
    from_str = ingest_openkritt_findings(json.dumps(EXPORT))
    from_list = ingest_openkritt_findings(EXPORT["vulnerabilities"])
    assert len(from_str) == 2 and len(from_list) == 2


def test_output_format_matches_the_finding_contract():
    fmt = to_openkritt_output_format()
    assert [f["key"] for f in fmt] == list(OPENKRITT_FINDING_KEYS)
    assert next(f for f in fmt if f["key"] == "line")["type"] == "number"


def test_wired_into_surface_reporting():
    candidates = surface_candidates(openkritt_findings=EXPORT)
    assert candidates and all(c.worker == "integration:openkritt" for c in candidates)


def test_ingests_the_serialized_api_shape():
    # GET /api/scans/{id}/vulnerabilities flattens the keys and nests dedupe/impact
    serialized = [{
        "id": "1", "vulnerability_type": "Reentrancy", "file_path": "contracts/Vault.sol",
        "line": 42, "summary": "reentrant withdraw", "explanation": "call before write",
        "jsonAnswer": {"vulnerability_type": "Reentrancy"},
        "dedupe": {"isCanonical": True}, "bountyRank": {"impactLevel": "critical"},
    }]
    candidates = ingest_openkritt_findings(serialized)
    assert len(candidates) == 1
    assert candidates[0].cwe == "CWE-841" and candidates[0].impact == "critical"


def test_empty_export_is_safe():
    assert ingest_openkritt_findings(None) == []
    assert ingest_openkritt_findings([]) == []
    assert ingest_openkritt_findings({"vulnerabilities": []}) == []
