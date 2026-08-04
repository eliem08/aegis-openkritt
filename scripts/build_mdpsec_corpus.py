"""Build a DisclosedReport corpus (jsonl) from the surveyed mdpsec taxonomy.

These entries are faithful to the *classes* of real disclosed bug-bounty reports
surveyed at mdpsec.com/reports (~129 reports; see the mdpsec-report-corpus memory).
Specific program names and bounty amounts are deliberately left generic/blank rather
than fabricated — the real signal retrieval needs is the weakness class, the pattern
in the title, the severity tier, and the source-code asset type.
"""

from __future__ import annotations

import json
from pathlib import Path

# (cwe, title/pattern, severity, tags)
ENTRIES = [
    # broken access control — the dominant class
    ("CWE-639", "IDOR: sequential object id lets a user read another user's record", "high",
     ["idor", "access-control", "sequential-id"]),
    ("CWE-863", "One sibling route left unauthenticated while its twins enforce auth", "high",
     ["differential-auth", "access-control", "missing-gate"]),
    ("CWE-306", "Missing authentication check on a state-changing endpoint", "critical",
     ["missing-auth", "access-control"]),
    ("CWE-862", "Missing authorization: ownership never validated on the resource lookup", "high",
     ["bola", "access-control", "ownership"]),
    ("CWE-639", "BOLA: object-level authorization skipped for one object type", "high",
     ["bola", "access-control"]),
    ("CWE-287", "Authentication bypass: password check skipped for one resource type", "high",
     ["auth-bypass", "differential-auth"]),
    ("CWE-863", "Cross-tenant access: tenant id from the request is trusted, not the session", "critical",
     ["cross-tenant", "isolation", "access-control"]),
    ("CWE-863", "Per-resolver authorization gap in a GraphQL schema", "high",
     ["graphql", "access-control", "differential-auth"]),
    ("CWE-639", "Iterable identifier links to another account's credential", "high",
     ["idor", "enumeration", "access-control"]),
    ("CWE-285", "Writable tenant attribute enables privilege escalation across tenants", "critical",
     ["cross-tenant", "privilege-escalation"]),
    # injection
    ("CWE-89", "Unauthenticated SQL injection via a search parameter", "critical",
     ["sqli", "injection", "unauth"]),
    ("CWE-79", "Stored XSS via SVG upload rendered inline", "high", ["xss", "svg", "upload"]),
    ("CWE-79", "Reflected XSS via unanchored host allowlist in a redirect", "medium",
     ["xss", "redirect", "allowlist-bypass"]),
    ("CWE-94", "Server-side template injection reaching code execution", "critical",
     ["ssti", "injection", "rce"]),
    ("CWE-78", "OS command injection in a file-processing pipeline", "critical",
     ["command-injection", "rce"]),
    # ssrf / parsers / traversal
    ("CWE-918", "SSRF to cloud metadata via a data-provider URL", "high",
     ["ssrf", "metadata", "cloud"]),
    ("CWE-918", "Blind SSRF via a webhook target with DNS rebinding", "high",
     ["ssrf", "dns-rebind", "webhook"]),
    ("CWE-22", "Path traversal via normalization bypass in a static handler", "high",
     ["path-traversal", "normalization"]),
    ("CWE-98", "Local file inclusion via ImageMagick SVG processing", "high",
     ["lfi", "imagemagick", "parser"]),
    # secrets / crypto
    ("CWE-798", "Hardcoded API/RPC key in a public JS bundle", "high",
     ["secrets", "hardcoded", "js-bundle"]),
    ("CWE-522", "JWT/API key recoverable from a mobile binary", "high",
     ["secrets", "mobile", "jwt"]),
    ("CWE-347", "Signature verification skipped on one message type", "high",
     ["signature", "crypto", "differential-auth"]),
    ("CWE-330", "Predictable token from insufficient randomness", "medium",
     ["weak-random", "token", "crypto"]),
    # oauth / identity
    ("CWE-601", "OAuth open redirect via unvalidated redirect_uri", "medium",
     ["oauth", "open-redirect"]),
    ("CWE-346", "OAuth postMessage wildcard origin leaks the token", "high",
     ["oauth", "postmessage", "client-side"]),
    ("CWE-287", "Audience confusion accepts a token minted for another client", "high",
     ["oauth", "audience-confusion", "auth-bypass"]),
    # business logic (candidate-gen only; state-changing held behind human approval)
    ("CWE-840", "Price/amount tampering in a checkout flow", "high",
     ["business-logic", "price-tampering"]),
    ("CWE-841", "Entitlement/perk minting via a repeatable request", "high",
     ["business-logic", "entitlement"]),
    ("CWE-362", "Gift-card redemption race condition", "medium",
     ["race", "business-logic"]),
    # privilege escalation
    ("CWE-269", "Self-approval lets a user grant themselves elevated privileges", "high",
     ["privilege-escalation", "self-approval"]),
    ("CWE-269", "Group-membership injection escalates access", "high",
     ["privilege-escalation", "group-injection"]),
    # enumeration oracles
    ("CWE-203", "Subscriber-status enumeration oracle via response differential", "low",
     ["enumeration", "oracle"]),
    # supply chain
    ("CWE-1104", "npm dependency confusion in a published package", "high",
     ["supply-chain", "dependency-confusion"]),
    ("CWE-829", "CI curl-pipe-bash executes an attacker-controlled script", "high",
     ["supply-chain", "ci"]),
    # web3
    ("CWE-190", "Bridge integer overflow enables value drain", "critical",
     ["web3", "overflow", "bridge"]),
    ("CWE-367", "Magic-link TOCTOU drains funds", "high", ["web3", "toctou"]),
]


def build(out_path: str) -> int:
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as fh:
        for index, (cwe, title, severity, tags) in enumerate(ENTRIES, start=1):
            report = {
                "report_id": f"mdpsec-{index:03d}",
                "source": "mdpsec",
                "program": "",
                "title": title,
                "weakness": cwe,
                "cwe": cwe,
                "severity": severity,
                "asset_type": "source_code",
                "asset_identifier": "",
                "summary": title,
                "url": "https://mdpsec.com/reports/",
                "tags": tags,
            }
            fh.write(json.dumps(report) + "\n")
    return len(ENTRIES)


if __name__ == "__main__":
    import sys
    dest = sys.argv[1] if len(sys.argv) > 1 else "reports/mdpsec_corpus.jsonl"
    n = build(dest)
    print(f"wrote {n} disclosed-report classes -> {dest}")
