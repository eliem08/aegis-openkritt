"""High-signal scanner coverage, provenance and corroboration tests."""

from __future__ import annotations

import json
from pathlib import Path

from aegis.ai import carpet_sweep as cs
from aegis.ai.tool_registry import TOOLS, _parse_detect_secrets, _parse_semgrep


def test_detect_secrets_is_registered_for_the_secrets_lane():
    tool = next(t for t in TOOLS if t.name == "detect-secrets")
    assert "secrets" in tool.lanes
    assert "--no-verify" in tool.cmd          # scanner must not call providers/network
    assert "--all-files" in tool.cmd


def test_detect_secrets_parser_redacts_secret_and_preserves_provenance():
    payload = {
        "version": "1.5.0",
        "results": {
            "app/settings.py": [{
                "type": "AWS Access Key",
                "line_number": 12,
                "hashed_secret": "must-not-leak",
                "is_verified": False,
            }]
        },
    }
    rows = _parse_detect_secrets(payload)
    assert len(rows) == 1
    row = rows[0]
    assert row["json_answer"]["vulnerability_type"] == "CWE-798"
    assert row["json_answer"]["file_path"] == "app/settings.py"
    assert row["scanner_metadata"]["secret_type"] == "AWS Access Key"
    assert "must-not-leak" not in json.dumps(row)
    assert row["validation_status"] == "unverified"


def test_semgrep_parser_keeps_rule_signal_metadata():
    rows = _parse_semgrep({"results": [{
        "check_id": "aegis-python-web-command-injection",
        "path": "app.py",
        "start": {"line": 9},
        "extra": {
            "severity": "ERROR",
            "message": "request data reaches command sink",
            "metadata": {
                "cwe": "CWE-78",
                "class": "command-injection",
                "confidence": "HIGH",
                "precision": "high",
                "validation": "source-to-sink",
            },
        },
    }]})
    row = rows[0]
    assert row["confidence"] == 0.90
    assert row["scanner_metadata"]["rule_id"] == "aegis-python-web-command-injection"
    assert row["scanner_metadata"]["validation"] == "source-to-sink"
    assert row["json_answer"]["vulnerability_type"] == "CWE-78"


def test_carpet_corroborates_independent_scanners(tmp_path):
    first = cs.Hit("p", "p", "h1", 5000, "o/r", "gitleaks", "CWE-798", "high",
                   "config.py", 7, "secret", signal=0.85, detectors=["gitleaks"])
    second = cs.Hit("p", "p", "h1", 5000, "o/r", "detect-secrets", "CWE-798", "medium",
                    "config.py", 7, "secret", signal=0.68,
                    detectors=["detect-secrets"])
    path = str(tmp_path / "hits.json")
    ranked = cs._persist([], [first, second], path)
    assert len(ranked) == 1
    assert ranked[0].corroborated is True
    assert ranked[0].evidence_count == 2
    assert set(ranked[0].detectors) == {"gitleaks", "detect-secrets"}


def test_high_signal_hit_ranks_above_pattern_only_hit():
    strong = cs.Hit("p", "p", "h1", 5000, "o/strong", "semgrep", "CWE-78", "high",
                    "app.py", 10, "taint", signal=0.90)
    weak = cs.Hit("p", "p", "h1", 5000, "o/weak", "semgrep", "generic", "high",
                  "app.py", 10, "pattern", signal=0.30)
    assert strong.score() > weak.score()


def test_web_taint_rules_are_packaged_and_content_pinned():
    root = Path(__file__).resolve().parents[2]
    packaged = root / "src" / "aegis" / "ai" / "rules" / "web-taint.yml"
    pinned = root / "config" / "scanners" / "semgrep" / "rules" / "aegis-web-taint.yml"
    assert packaged.read_text(encoding="utf-8") == pinned.read_text(encoding="utf-8")
    text = packaged.read_text(encoding="utf-8")
    assert "mode: taint" in text
    assert "validation: source-to-sink" in text
    assert "source: aegis-owned" in text
