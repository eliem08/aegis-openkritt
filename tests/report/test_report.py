import pytest

from aegis.model import (
    Canary,
    CanaryKind,
    EvidenceBundle,
    Finding,
    FindingStatus,
    InteractionStep,
)
from aegis.report import (
    build_report,
    evaluate_quality,
    is_duplicate,
    is_submittable,
    prepare_submission,
    redact,
)
from aegis.knowledge import DisclosedReport


def _evidence(reproducible=True):
    return EvidenceBundle(
        steps=[InteractionStep(summary="GET /users/1001 as user_b",
                               request="Authorization: Bearer eyJa.b.c\nCookie: s=secret",
                               response='{"email":"v@corp.com","canary":"CANARY-1"}')] if reproducible else [],
        canary=Canary(kind=CanaryKind.SEEDED_RECORD, value="CANARY-1") if reproducible else None,
        observed="cross-user read", expected="403", confidence=0.85, replay_ref="replay://1",
    )


def _finding(**kw):
    base = dict(asset="api.acme.test", route="/users/{id}", parameter="id", cwe="CWE-639",
                status=FindingStatus.VERIFIED, confidence=0.85, priority=0.55,
                p_exploit=0.8, business_impact=0.9, asset_criticality=0.9)
    base.update(kw)
    return Finding(**base)


# --- redaction ---

@pytest.mark.parametrize("raw,gone", [
    ("Authorization: Bearer eyJx.y.z", "eyJx"),
    ("Cookie: session=abc123", "abc123"),
    ("contact victim@corp.com", "victim@corp.com"),
    ("token=supersecretvalue", "supersecretvalue"),
    ("key AKIAIOSFODNN7EXAMPLE here", "AKIAIOSFODNN7EXAMPLE"),
])
def test_redact_removes_secrets(raw, gone):
    assert gone not in redact(raw)


def test_redact_preserves_none():
    assert redact(None) is None


# --- report ---

def test_build_report_structure():
    r = build_report(_finding(), _evidence(), program_handle="acme")
    assert "IDOR" in r.title
    assert r.cwe == "CWE-639"
    assert r.severity == "high"
    assert r.remediation  # CWE-specific remediation present
    assert "authorized scope" in r.scope_compliance
    md = r.to_markdown()
    assert md.startswith("# ")
    assert "## Steps to reproduce" in md


def test_report_evidence_is_redacted():
    md = build_report(_finding(), _evidence(), program_handle="acme").to_markdown()
    assert "secret" not in md and "eyJa" not in md and "v@corp.com" not in md


# --- quality gates ---

def test_quality_all_pass_for_good_finding():
    gates = evaluate_quality(_finding(), _evidence(), in_scope=True, redacted=True, is_duplicate=False)
    assert is_submittable(gates)


def test_hypothesis_is_not_submittable():
    gates = evaluate_quality(_finding(status=FindingStatus.CANDIDATE), _evidence())
    assert not is_submittable(gates)


def test_no_evidence_not_submittable():
    gates = evaluate_quality(_finding(), None)
    assert not is_submittable(gates)


def test_duplicate_not_submittable():
    gates = evaluate_quality(_finding(), _evidence(), is_duplicate=True)
    assert not is_submittable(gates)


# --- dedup ---

def test_dedup_internal_exact_fingerprint():
    prior = _finding()
    other = _finding()
    res = is_duplicate(other, prior_findings=[prior])
    assert res.is_duplicate and res.matches[0][0] == "internal"


def test_dedup_public_corpus_host_cwe():
    corpus = [DisclosedReport(report_id="900", cwe="CWE-639", asset_identifier="api.acme.test")]
    res = is_duplicate(_finding(), corpus=corpus)
    assert res.is_duplicate and res.matches[0][0] == "public"


def test_dedup_no_match():
    corpus = [DisclosedReport(report_id="900", cwe="CWE-79", asset_identifier="other.test")]
    assert not is_duplicate(_finding(), corpus=corpus).is_duplicate


# --- pipeline ---

def test_pipeline_submittable():
    pkg = prepare_submission(_finding(), _evidence(), program_handle="acme", in_scope=True)
    assert pkg.submittable and not pkg.duplicate
    assert pkg.blocking_reasons == []
    assert "secret" not in pkg.markdown


def test_pipeline_blocks_duplicate():
    corpus = [DisclosedReport(report_id="900", cwe="CWE-639", asset_identifier="api.acme.test")]
    pkg = prepare_submission(_finding(), _evidence(), corpus=corpus)
    assert pkg.duplicate
    assert not pkg.submittable
    assert "not_duplicate" in pkg.blocking_reasons


def test_pipeline_blocks_out_of_scope_hypothesis():
    pkg = prepare_submission(_finding(status=FindingStatus.CANDIDATE), None, in_scope=False)
    assert not pkg.submittable
    assert set(pkg.blocking_reasons) >= {"reproducible", "verified", "in_scope"}


def test_scope_derived_from_authorization_cannot_be_widened():
    # Caller lies in_scope=True, but the authorization does not cover the asset.
    from types import SimpleNamespace

    auth = SimpleNamespace(targets=["api.acme.test", "*.acme.test"])
    out = _finding(asset="evil.example.com")
    pkg = prepare_submission(out, _evidence(), authorization=auth, in_scope=True)
    assert "in_scope" in pkg.blocking_reasons and not pkg.submittable


def test_scope_derived_authorization_allows_in_scope_asset():
    from types import SimpleNamespace

    auth = SimpleNamespace(targets=["api.acme.test"])
    pkg = prepare_submission(_finding(asset="api.acme.test"), _evidence(), authorization=auth, in_scope=True)
    assert "in_scope" not in pkg.blocking_reasons
