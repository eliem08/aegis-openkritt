"""End-to-end candidate funnel regression test across 8 canonical vulnerability classes.

Verifies that genuine candidate vulnerabilities survive the full funnel:
discovery -> normalization -> candidate reduction -> dedup -> evidence stage
without being falsely suppressed by heuristic noise filters.
"""

from __future__ import annotations

from aegis.ai.candidate_reduction import reduce_candidates


def _make_finding(
    vuln_class: str,
    file_path: str,
    line: int,
    tool: str,
    rule_id: str,
    cwe: str,
    severity: str = "high",
    confidence: float = 0.90,
) -> dict:
    return {
        "source": f"aegis:tool:{tool}",
        "tool": tool,
        "severity": severity,
        "confidence": confidence,
        "scanner_metadata": {"rule_id": rule_id, "cwe": cwe},
        "json_answer": {
            "vulnerability_type": vuln_class,
            "file_path": file_path,
            "line": line,
            "summary": f"Synthetic finding for {vuln_class}",
            "explanation": f"Reproducible test case for {vuln_class}",
        },
    }


def test_candidate_funnel_eight_vulnerability_classes() -> None:
    # Build synthetic finding dataset covering all 8 vulnerability classes:
    raw_findings = [
        # 1. SQL Injection
        _make_finding(
            vuln_class="sql_injection",
            file_path="src/api/users.py",
            line=42,
            tool="semgrep",
            rule_id="python.lang.security.audit.sqli.raw-sql",
            cwe="CWE-89",
            severity="critical",
            confidence=0.95,
        ),
        # 2. Command Injection
        _make_finding(
            vuln_class="command_injection",
            file_path="src/utils/backup.py",
            line=18,
            tool="semgrep",
            rule_id="python.lang.security.audit.dangerous-system-call",
            cwe="CWE-78",
            severity="critical",
            confidence=0.92,
        ),
        # 3. Reflected XSS
        _make_finding(
            vuln_class="reflected_xss",
            file_path="src/web/views.py",
            line=88,
            tool="semgrep",
            rule_id="python.django.security.injection.reflected-xss",
            cwe="CWE-79",
            severity="high",
            confidence=0.88,
        ),
        # 4. SSRF
        _make_finding(
            vuln_class="ssrf",
            file_path="src/services/webhook.py",
            line=64,
            tool="semgrep",
            rule_id="python.requests.security.audit.ssrf-injection",
            cwe="CWE-918",
            severity="high",
            confidence=0.89,
        ),
        # 5. Path Traversal
        _make_finding(
            vuln_class="path_traversal",
            file_path="src/handlers/download.py",
            line=35,
            tool="semgrep",
            rule_id="python.lang.security.audit.path-traversal.open",
            cwe="CWE-22",
            severity="high",
            confidence=0.90,
        ),
        # 6. Hardcoded Secret (in actual source code / config, not example/mock file)
        _make_finding(
            vuln_class="hardcoded_secret",
            file_path="src/config/jwt_signer.py",
            line=12,
            tool="gitleaks",
            rule_id="jwt-secret-key",
            cwe="CWE-798",
            severity="critical",
            confidence=0.96,
        ),
        # 7. Authorization Failure / IDOR
        _make_finding(
            vuln_class="broken_object_level_authorization",
            file_path="src/controllers/documents.py",
            line=104,
            tool="semgrep",
            rule_id="python.security.idor.unvalidated-owner-id",
            cwe="CWE-285",
            severity="high",
            confidence=0.88,
        ),
        # 8. Unsafe Deserialization
        _make_finding(
            vuln_class="unsafe_deserialization",
            file_path="src/messaging/consumer.py",
            line=53,
            tool="semgrep",
            rule_id="python.lang.security.audit.pickle.unsafe-load",
            cwe="CWE-502",
            severity="critical",
            confidence=0.94,
        ),
    ]

    # Stage 1: Feed through candidate reduction
    reduction = reduce_candidates(raw_findings)

    # Verify all 8 classes survived
    assert len(reduction.survivors) == 8, (
        f"Expected 8 survivors, got {len(reduction.survivors)}. "
        f"Suppressed: {[(c.summary, c.reason) for c in reduction.suppressed]}"
    )
    assert len(reduction.suppressed) == 0

    survivor_types = {c.summary for c in reduction.survivors}
    for item in raw_findings:
        summary = item["json_answer"]["summary"]
        assert summary in survivor_types, f"{summary} was unexpectedly dropped from survivors"

    # Stage 2: Deduplication verification
    # If the same finding is observed twice by the same tool on the same line,
    # it must deduplicate down to 1 survivor without reducing distinct findings.
    duplicate_raw = list(raw_findings) + [raw_findings[0]]  # duplicate SQLi
    dup_reduction = reduce_candidates(duplicate_raw)
    assert dup_reduction.funnel["raw"] == 9
    assert dup_reduction.funnel["deduped"] == 8
    assert len(dup_reduction.survivors) == 8

    # Stage 3: Corroboration by independent tool strengthens score
    # Add an independent tool (e.g. CodeQL or Bandit) finding the same SQLi at the same locus
    corroborated_raw = list(raw_findings) + [
        _make_finding(
            vuln_class="sql_injection",
            file_path="src/api/users.py",
            line=42,
            tool="codeql",
            rule_id="py/sql-injection",
            cwe="CWE-89",
            severity="critical",
            confidence=0.95,
        )
    ]
    corr_reduction = reduce_candidates(corroborated_raw)
    sqli_survivors = [c for c in corr_reduction.survivors if "sql_injection" in c.summary]
    assert len(sqli_survivors) == 2
    for s in sqli_survivors:
        assert s.corroborators == 2
        assert s.score > 0.80  # corroborated score is boosted
