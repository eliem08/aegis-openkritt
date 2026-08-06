"""JS-secret lane: deterministic extraction, redaction, scoring, ranking (no network)."""

from __future__ import annotations

from aegis.ai.js_secret_hunt import (
    Candidate, SecretFinding, SecretTriage, _score, extract_candidates, hunt_js_secrets,
)

_JS = """
const stripePub = "pk_live_51H8xQe2eZvKYlo2CabcdefghijklmnZZ";
const AWS_SECRET_KEY = "aws_secret: wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY0";
const gh = "ghp_ABCdefGHIjklMNOpqrsTUVwxyz0123456789";
const maps = "AIzaSyDaGmWKa4JsXZ_HjGw7ISLn_3namBGewQ0";
"""


def test_extracts_high_signal_secrets():
    cands = extract_candidates(_JS, source="app.js")
    kinds = {c.kind for c in cands}
    assert "github-token" in kinds
    assert "stripe-publishable-key" in kinds
    assert "google-api-key" in kinds


def test_never_emits_raw_value():
    cands = extract_candidates(_JS, source="app.js")
    for c in cands:
        assert "ghp_ABCdefGHIjklMNOpqrsTUVwxyz0123456789" not in c.redacted
        assert "..." in c.redacted or len(c.redacted) <= 12   # redacted form
        # full github token never appears verbatim in the context snippet either
        assert "ghp_ABCdefGHIjklMNOpqrsTUVwxyz0123456789" not in c.context


def test_public_pattern_flagged():
    cands = {c.kind: c for c in extract_candidates(_JS, source="a.js")}
    assert cands["stripe-publishable-key"].is_public_pattern is True
    assert cands["github-token"].is_public_pattern is False


def test_scoring_downranks_public_and_ranks_secret_by_severity():
    c = Candidate(kind="x", line=1, redacted="ab...cd", context="", is_public_pattern=False)
    secret_hi = SecretTriage(verdict="secret", severity="critical", confidence=0.9, likely_live=0.9)
    public = SecretTriage(verdict="public", is_public_client_key=True, confidence=0.9, likely_live=0.9)
    assert _score(c, secret_hi) > _score(c, public)
    # public verdict collapses to the low base regardless of confidence
    assert _score(c, public) < 0.5


def test_hunt_ranks_secret_above_public_with_fake_client():
    # a fake client that classifies by the candidate kind embedded in the prompt
    class FakeClient:
        def complete_json(self, messages):
            u = messages[-1]["content"]
            if "github-token" in u:
                return {"verdict": "secret", "severity": "high", "confidence": 0.9,
                        "likely_live": 0.8, "is_public_client_key": False, "reason": "live PAT"}
            return {"verdict": "public", "severity": "info", "confidence": 0.9,
                    "likely_live": 0.1, "is_public_client_key": True, "reason": "browser key"}

    findings = hunt_js_secrets({"app.js": _JS}, FakeClient())
    assert findings, "expected findings"
    assert findings[0].kind == "github-token"          # secret ranked first
    assert findings[0].triage.verdict == "secret"
    # a public one is present but ranked below and flagged
    pubs = [f for f in findings if f.triage.is_public_client_key]
    assert pubs and all(f.score < findings[0].score for f in pubs)


def test_triage_error_degrades_to_unknown():
    class BoomClient:
        def complete_json(self, messages):
            raise RuntimeError("api down")

    findings = hunt_js_secrets({"app.js": _JS}, BoomClient())
    assert findings and all(f.triage.verdict == "unknown" for f in findings)
