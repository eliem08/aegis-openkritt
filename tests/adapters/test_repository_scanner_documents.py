"""Sanitized golden contracts for repository scanner JSON documents."""

from __future__ import annotations

import json

import pytest

from aegis.adapters import EventKind, ExecutionEnvelope
from aegis.process import ProcessOutcome, ProcessResult
from aegis.adapters.repository_scanners import (
    GitleaksDocumentAdapter,
    OsvScannerDocumentAdapter,
    SemgrepDocumentAdapter,
)


def _envelope(adapter):
    return ExecutionEnvelope.for_manifest(
        adapter.manifest,
        tenant_id="tenant", engagement_id="eng", scan_id="scan", stage_id="stage",
        task_id="task", target="repo", scope_digest="scope", idempotency_key="idem",
    )


def test_semgrep_document_preserves_triage_fields_without_claiming_verification():
    adapter = SemgrepDocumentAdapter()
    document = json.dumps({
        "results": [{
            "check_id": "python.security.injection",
            "path": "/src/app/api.py",
            "start": {"line": 12, "col": 3},
            "end": {"line": 12, "col": 18},
            "extra": {
                "message": "Potential injection reaches a dangerous sink",
                "severity": "ERROR",
                "metadata": {"category": "security", "confidence": "HIGH"},
            },
        }],
        "errors": [],
    })

    events = adapter.parse_document(document, _envelope(adapter))

    assert len(events) == 1 and events[0].kind == EventKind.FINDING
    assert events[0].data["path"] == "app/api.py"
    assert events[0].data["verified"] is False


def test_semgrep_errors_are_blocking_incomplete_coverage():
    adapter = SemgrepDocumentAdapter()
    events = adapter.parse_document(
        json.dumps({"results": [], "errors": [{"message": "parse failed"}]}),
        _envelope(adapter),
    )
    assert events[0].kind == EventKind.DIAGNOSTIC
    assert events[0].data["blocking"] is True


def test_gitleaks_never_emits_secret_match_line_or_author_identity():
    adapter = GitleaksDocumentAdapter()
    document = json.dumps([{
        "RuleID": "example-token",
        "File": "/src/config/settings.py",
        "StartLine": 9,
        "Fingerprint": "abc:config/settings.py:example-token:9",
        "Commit": "a" * 40,
        "Secret": "do-not-persist",
        "Match": "TOKEN=do-not-persist",
        "Line": "TOKEN=do-not-persist",
        "Author": "Private Person",
        "Email": "private@example.test",
    }])

    event = adapter.parse_document(document, _envelope(adapter))[0]

    assert event.kind == EventKind.SECRET_CANDIDATE
    serialized = json.dumps(event.data)
    assert event.data["redacted"] is True
    assert "do-not-persist" not in serialized
    assert "Private Person" not in serialized
    assert "private@example.test" not in serialized


def test_osv_document_expands_vulnerabilities_into_dependency_candidates():
    adapter = OsvScannerDocumentAdapter()
    document = json.dumps({"results": [{
        "source": {"path": "/src/package-lock.json", "type": "lockfile"},
        "packages": [{
            "package": {"name": "demo", "version": "1.0.0", "ecosystem": "npm"},
            "vulnerabilities": [{
                "id": "GHSA-demo",
                "aliases": ["CVE-2099-0001"],
                "severity": [{"type": "CVSS_V3", "score": "9.8"}],
            }],
        }],
    }]})

    event = adapter.parse_document(document, _envelope(adapter))[0]

    assert event.kind == EventKind.FINDING
    assert event.data["vulnerability_id"] == "GHSA-demo"
    assert event.data["source_path"] == "package-lock.json"
    assert event.data["verified"] is False


@pytest.mark.parametrize("adapter", [
    SemgrepDocumentAdapter(), GitleaksDocumentAdapter(), OsvScannerDocumentAdapter(),
])
def test_repository_scanners_refuse_host_execution_until_container_gate(adapter):
    with pytest.raises(Exception, match="hardened.*container executor"):
        adapter.build_command(_envelope(adapter))

def test_osv_exit_one_is_findings_success_but_other_failures_are_not():
    adapter = OsvScannerDocumentAdapter()
    found = ProcessResult(ProcessOutcome.FAILED, exit_code=1)
    broken = ProcessResult(ProcessOutcome.FAILED, exit_code=127)
    timed_out = ProcessResult(ProcessOutcome.TIMED_OUT, exit_code=None)
    assert adapter.result_succeeded(found) is True
    assert adapter.result_succeeded(broken) is False
    assert adapter.result_succeeded(timed_out) is False
