from __future__ import annotations

import hashlib
import json

from aegis.ai.jarvis.asset_cli_executor import LocalCliExecution
from aegis.ai.jarvis.asset_normalizers import normalize_local_cli_execution


def _execution(tool: str, payload, method="scan"):
    raw = json.dumps(payload).encode()
    empty = hashlib.sha256(b"").hexdigest()
    return LocalCliExecution(
        tool=tool,
        method=method,
        returncode=0,
        timed_out=False,
        provenance={
            "tool": tool,
            "status": "ready",
            "version": f"{tool} 1.0",
            "binary_sha256": "a" * 64,
            "execution_mode": "local_cli",
            "shell": False,
            "argv": ["/opt/tool", "/private/artifact"],
        },
        stdout_sha256=hashlib.sha256(raw).hexdigest(),
        stderr_sha256=empty,
        stdout_size=len(raw),
        stderr_size=0,
        outputs=(),
        workspace="",
        retained_workspace=False,
        raw_stdout=raw,
        raw_stderr=b"",
        output_file=b"",
    )


def test_grype_reuses_existing_parser_and_attaches_compact_runtime_provenance():
    execution = _execution(
        "grype",
        {
            "matches": [
                {
                    "vulnerability": {
                        "id": "CVE-2099-0001",
                        "severity": "High",
                        "description": "example package vulnerability",
                    },
                    "artifact": {
                        "name": "demo",
                        "version": "1.0",
                        "locations": [{"path": "/app/demo"}],
                    },
                }
            ]
        },
        method="artifact-vulnerability-scan",
    )
    normalized = normalize_local_cli_execution(execution)
    assert len(normalized.candidates) == 1
    row = normalized.candidates[0]
    assert row["validation_status"] == "unverified"
    assert row["source"] == "aegis:tool:grype"
    assert row["scanner_runtime"]["binary_sha256"] == "a" * 64
    assert "argv" not in row["scanner_runtime"]
    assert row["asset_execution"]["method"] == "artifact-vulnerability-scan"
    assert normalized.observations[0].data["candidate_count"] == 1


def test_syft_is_inventory_observation_not_a_fake_vulnerability():
    normalized = normalize_local_cli_execution(
        _execution(
            "syft",
            {"artifacts": [{"name": "a"}, {"name": "b"}], "source": {"type": "file"}},
            method="artifact-sbom",
        )
    )
    assert normalized.candidates == ()
    assert normalized.observations[0].kind == "sbom_inventory"
    assert normalized.observations[0].data["packages"] == 2


def test_unknown_extractor_stays_observation_even_with_json_output():
    normalized = normalize_local_cli_execution(
        _execution("apktool", {"looks": "security-ish"}, method="decode")
    )
    assert normalized.candidates == ()
    assert normalized.observations[0].kind == "tool_observation"
    assert normalized.observations[0].data["normalizer"] == \
        "no-vulnerability-parser-registered"


def test_malformed_json_never_creates_candidates():
    execution = _execution("grype", {})
    execution = LocalCliExecution(
        **{
            **execution.__dict__,
            "raw_stdout": b"not-json",
            "stdout_sha256": hashlib.sha256(b"not-json").hexdigest(),
            "stdout_size": 8,
        }
    )
    normalized = normalize_local_cli_execution(execution)
    assert normalized.candidates == ()
    assert normalized.observations[0].kind == "tool_observation"
