"""Static contract for the Aegis-owned, content-pinned Semgrep rules."""

from __future__ import annotations

from pathlib import Path

from aegis.process import directory_sha256


ROOT = Path(__file__).resolve().parents[2]
RULES = ROOT / "config" / "scanners" / "semgrep" / "rules"
DIGEST_FILE = ROOT / "config" / "scanners" / "semgrep" / "rules.sha256"


def test_semgrep_rule_bundle_matches_approved_digest():
    approved = DIGEST_FILE.read_text(encoding="utf-8").strip()
    assert len(approved) == 64
    assert directory_sha256(RULES) == approved


def test_semgrep_bundle_is_aegis_owned_and_has_no_remote_config():
    content = "\n".join(path.read_text(encoding="utf-8") for path in RULES.glob("*.yml"))
    assert "source: aegis-owned" in content
    assert "--config auto" not in content
    assert "semgrep.dev" not in content
    assert "autofix" not in content.lower()
