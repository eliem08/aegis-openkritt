"""Nuclei adapter (Phase 3) — the safety story is template allowlisting.

A signed, Aegis-maintained manifest is the only source of runnable templates.
Everything unsigned, tampered, unknown, locally referenced, or on a prohibited
protocol is rejected; approved results become FINDING candidates, never verified
findings.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from aegis.adapters import (
    EventKind,
    ExecutionEnvelope,
    ManifestError,
    NucleiAdapter,
    NucleiConfig,
    RejectReason,
    TemplateEntry,
    new_template_manifest,
    sign_manifest,
)
from aegis.adapters.nuclei import PROHIBITED_PROTOCOLS
from aegis.policy.signing import HmacSignatureVerifier

FIXTURES = Path(__file__).parent / "fixtures"
KID, SECRET = "manifest-key", "manifest-secret"
SIGNER = "aegis-secops"
STUB = "/opt/aegis/tools/nuclei"

# Template contents used for checksum/integrity tests.
TEMPLATES = {
    "tech-detect": b"id: tech-detect\ninfo:\n  severity: info\n",
    "exposed-config": b"id: exposed-config\ninfo:\n  severity: medium\n",
    "portscan": b"id: portscan\ninfo:\n  severity: info\n",
}


def _sha(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def verifier() -> HmacSignatureVerifier:
    return HmacSignatureVerifier({KID: SECRET})


def entries(signer=SIGNER):
    return [
        TemplateEntry("tech-detect", _sha(TEMPLATES["tech-detect"]), signer, "info", "http", ("tech",)),
        TemplateEntry("exposed-config", _sha(TEMPLATES["exposed-config"]), signer, "medium", "http",
                      ("exposure",)),
        TemplateEntry("portscan", _sha(TEMPLATES["portscan"]), signer, "info", "http"),
    ]


def manifest(*, signed=True, signer=SIGNER, allowed=("http", "ssl", "dns")):
    m = new_template_manifest(
        manifest_id="aegis-nuclei-v1", executable_digest="", template_commit="abc123def",
        entries=entries(signer), trusted_signers={SIGNER}, allowed_protocols=allowed,
    )
    return sign_manifest(m, verifier(), KID) if signed else m


def envelope(adapter, target="api.example.test"):
    return ExecutionEnvelope.for_manifest(
        adapter.manifest, tenant_id="t", engagement_id="e", scan_id="s", stage_id="st",
        task_id="tk", target=target, scope_digest="d", idempotency_key="k",
    )


def adapter(**kw):
    return NucleiAdapter(manifest(), STUB, allow_unpinned=True, verifier=verifier(), **kw)


# --- manifest signing --------------------------------------------------------

def test_valid_manifest_verifies():
    manifest().verify(verifier())   # no raise


def test_unsigned_manifest_is_rejected():
    with pytest.raises(ManifestError, match="unsigned"):
        manifest(signed=False).verify(verifier())


def test_tampered_manifest_signature_is_rejected():
    m = manifest()
    m.template_commit = "tampered-commit"      # content changed after signing
    with pytest.raises(ManifestError, match="invalid"):
        m.verify(verifier())


def test_entry_from_untrusted_signer_is_rejected():
    m = manifest(signer="rogue")
    with pytest.raises(ManifestError, match="untrusted signer"):
        m.verify(verifier())


def test_manifest_allowing_a_prohibited_protocol_is_rejected():
    with pytest.raises(ManifestError, match="prohibited protocol"):
        manifest(allowed=("http", "network")).verify(verifier())


# --- template validation -----------------------------------------------------

def test_unknown_template_is_rejected():
    assert manifest().validate("not-in-manifest").reason == RejectReason.UNKNOWN


def test_locally_referenced_template_is_rejected():
    for local in ("../../etc/passwd.yaml", "/tmp/x.yml", "custom/mine.yaml"):
        assert manifest().validate(local).reason == RejectReason.LOCAL_REF


def test_tampered_checksum_is_rejected():
    v = manifest().validate("tech-detect", checksum="0" * 64)
    assert v.reason == RejectReason.TAMPERED


def test_prohibited_protocol_is_rejected():
    assert manifest().validate("portscan", protocol="network").reason == RejectReason.PROHIBITED


def test_approved_template_passes():
    assert manifest().validate("tech-detect", checksum=_sha(TEMPLATES["tech-detect"]),
                               protocol="http").ok


# --- pre-scan integrity ------------------------------------------------------

def test_preflight_flags_tampered_and_missing_template_files():
    tampered = dict(TEMPLATES, **{"exposed-config": b"id: exposed-config\n# BACKDOOR\n"})

    def loader(tid):
        return tampered[tid]                    # 'portscan' missing from this dict? it's present

    verdicts = adapter().preflight(loader)
    assert verdicts["tech-detect"].ok
    assert verdicts["exposed-config"].reason == RejectReason.TAMPERED

    def missing_loader(tid):
        if tid == "portscan":
            raise FileNotFoundError(tid)
        return TEMPLATES[tid]

    verdicts = adapter().preflight(missing_loader)
    assert verdicts["portscan"].reason == RejectReason.MISSING
    assert verdicts["tech-detect"].ok


# --- command construction ----------------------------------------------------

def test_command_disables_dangerous_features():
    argv = adapter().build_command(envelope(adapter()))
    joined = " ".join(argv)
    assert "-disable-update-check" in argv       # no auto-update mid-scan
    assert "-no-interactsh" in argv              # OAST off
    assert "-headless=false" in argv and "-dast=false" in argv
    # every prohibited protocol is explicitly excluded
    et = argv[argv.index("-exclude-type") + 1]
    assert all(p in et for p in PROHIBITED_PROTOCOLS)


def test_command_runs_only_approved_template_ids():
    a = adapter()
    argv = a.build_command(envelope(a))
    ids = argv[argv.index("-template-id") + 1].split(",")
    assert set(ids) == {"tech-detect", "exposed-config", "portscan"}


def test_effective_protocols_intersect_manifest_and_authorization():
    a = NucleiAdapter(manifest(allowed=("http", "ssl", "dns")), STUB, allow_unpinned=True,
                      verifier=verifier(), config=NucleiConfig(authorized_protocols=("http",)))
    argv = a.build_command(envelope(a))
    types = argv[argv.index("-type") + 1].split(",")
    assert types == ["http"]                     # dns/ssl allowed by manifest but not authorized


def test_adapter_refuses_an_invalid_manifest_at_construction():
    with pytest.raises(ManifestError):
        NucleiAdapter(manifest(signed=False), STUB, allow_unpinned=True, verifier=verifier())


# --- result parsing ----------------------------------------------------------

def run_fixture(a):
    env = envelope(a)
    lines = (FIXTURES / "nuclei-3.3.0.jsonl").read_text(encoding="utf-8").strip().splitlines()
    return [e for line in lines if (e := a.parse_line(line, env)) is not None]


def test_approved_results_become_finding_candidates_with_provenance():
    a = adapter()
    findings = [e for e in run_fixture(a) if e.kind == EventKind.FINDING]
    names = {f.data["template_id"] for f in findings}
    assert names == {"tech-detect", "exposed-config"}
    ec = next(f for f in findings if f.data["template_id"] == "exposed-config")
    assert ec.data["severity"] == "medium" and ec.data["template_commit"] == "abc123def"
    assert ec.data["matched_at"].endswith("/.env")
    assert ec.data["verified"] is False and ec.confidence < 1.0


def test_unapproved_and_prohibited_results_are_blocking_rejections():
    a = adapter()
    diags = [e for e in run_fixture(a) if e.kind == EventKind.DIAGNOSTIC]
    codes = {d.data["code"] for d in diags}
    assert RejectReason.UNKNOWN in codes          # evil-injected
    assert RejectReason.PROHIBITED in codes       # portscan reported as network
    assert RejectReason.LOCAL_REF in codes        # ../../etc/passwd.yaml
    assert all(d.data["blocking"] for d in diags)


def test_terminal_reports_quarantine_when_templates_were_rejected():
    a = adapter()
    events = run_fixture(a)
    terminal = a.interpret_result(_ok_result(), envelope(a))
    assert terminal.data["findings"] == 2
    assert terminal.data["status"] == "quarantined"   # rejects present -> not trustworthy
    assert terminal.data["rejected_templates"]


def test_findings_are_not_assets():
    from aegis.graph import Normalizer
    from aegis.policy.scope import ScopeGuard

    a = adapter()
    findings = [e for e in run_fixture(a) if e.kind == EventKind.FINDING]
    result = Normalizer(scope=ScopeGuard(["api.example.test"]),
                        engagement_id="e", scan_id="s").normalize(findings)
    assert result.assets == {}                    # findings go to the evidence pipeline


def _ok_result():
    from aegis.process import ProcessOutcome, ProcessResult

    return ProcessResult(outcome=ProcessOutcome.SUCCEEDED, exit_code=0)
