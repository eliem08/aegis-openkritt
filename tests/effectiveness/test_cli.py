import json
from datetime import UTC, datetime

from aegis.cli import main
from aegis.production.operator_manifest import document_digest


def lineage_document():
    manifest = {
        "schema_version": 1, "run_id": "run-1", "mode": "dry_run",
        "created_at": datetime.now(UTC).isoformat(), "operator_id": "operator",
        "program_handle": "program", "selected_assets": ["asset"],
    }
    manifest["manifest_digest"] = document_digest(manifest)
    return {
        "manifest": manifest,
        "lineage": {
            "run_id": "run-1", "mission_id": "mission-1",
            "opportunity_id": "opportunity-1", "technique": "authorization-boundary",
            "program_id": "program", "asset_id": "asset", "weakness_family": "authz",
            "asset_class": "web_api", "authentication_mode": "authenticated",
            "execution_mode": "dynamic", "evidence_digest": "a" * 64,
            "created_at": manifest["created_at"],
        },
        "facts": ["opportunity_generated", "finding_reproduced"],
    }


def test_cli_ingests_lineage_records_outcome_and_reports(tmp_path, capsys):
    database = tmp_path / "effectiveness.db"
    lineage_path = tmp_path / "lineage.json"
    lineage_path.write_text(json.dumps(lineage_document()), encoding="utf-8")
    assert main([
        "effectiveness", "ingest-run", "--backend", "sqlite", "--database", str(database),
        "--input", str(lineage_path),
    ]) == 0
    subject_id = json.loads(capsys.readouterr().out)["subject_id"]
    outcome = {
        "subject_id": subject_id, "state": "accepted", "submitted_severity": "high",
        "triaged_severity": "medium", "bounty_usd": None,
        "submitted_at": "2026-08-01T00:00:00+00:00",
        "triaged_at": "2026-08-02T00:00:00+00:00",
        "resolved_at": "2026-08-03T00:00:00+00:00", "human_review_minutes": "20",
        "model_api_cost_usd": "1.25", "compute_cost_usd": "0.75",
        "analyst_note": "reviewed", "operator_id": "operator",
        "source_digest": "d" * 64, "idempotency_key": "outcome-1",
    }
    outcome_path = tmp_path / "outcome.json"
    outcome_path.write_text(json.dumps(outcome), encoding="utf-8")
    assert main([
        "effectiveness", "record-outcome", "--backend", "sqlite", "--database",
        str(database), "--input", str(outcome_path),
    ]) == 2
    assert "outcome not confirmed" in capsys.readouterr().out
    assert main([
        "effectiveness", "record-outcome", "--backend", "sqlite", "--database",
        str(database), "--input", str(outcome_path), "--confirm",
    ]) == 0
    capsys.readouterr()
    assert main([
        "effectiveness", "report", "--backend", "sqlite", "--database", str(database),
    ]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["overall"]["accepted"] == 1
    assert report["overall"]["realized_profit_usd"] is None


def test_cli_production_sqlite_fails_closed(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("AEGIS_PRODUCTION", "1")
    result = main([
        "effectiveness", "report", "--backend", "sqlite", "--database",
        str(tmp_path / "ledger.db"),
    ])
    assert result == 1
    assert "forbidden" in capsys.readouterr().err
