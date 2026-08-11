from __future__ import annotations

import json

from aegis.production.health import HealthStatus, build_health_report


def test_health_fails_closed_and_keeps_dependencies_distinct():
    report = build_health_report(
        None,
        env={"AEGIS_HEALTH_REQUIRED": "policy_authority,database"},
        settings_error=ValueError("production configuration missing"),
    )
    cells = {cell.name: cell for cell in report.cells}
    assert report.ready is False
    assert cells["policy_authority"].status is HealthStatus.FAILED
    assert cells["database"].status is HealthStatus.WAITING
    assert cells["playwright"].status in {
        HealthStatus.NOT_REQUIRED, HealthStatus.WAITING, HealthStatus.READY,
    }
    assert {"ct_provider", "private_oast", "android_runtime", "grpc_prerequisites"} <= cells.keys()


def test_health_extra_required_probe_controls_verdict():
    report = build_health_report(
        None,
        env={"AEGIS_HEALTH_REQUIRED": "custom"},
        settings_error=ValueError("not required by this test"),
        extra_probes={"custom": lambda: "bounded probe passed"},
    )
    # Policy authority is always required and therefore still blocks an invalid production config.
    assert report.ready is False
    custom = next(cell for cell in report.cells if cell.name == "custom")
    assert custom.required and custom.status is HealthStatus.READY


def test_health_document_is_machine_readable_and_contains_no_credentials():
    report = build_health_report(
        None,
        env={"AEGIS_HEALTH_REQUIRED": "policy_authority"},
        settings_error=ValueError("configuration unavailable"),
    )
    encoded = json.dumps(report.document())
    assert '"schema_version": 1' in encoded
    assert '"ready": false' in encoded
    assert "AEGIS_API_KEYS" not in encoded


def test_effectiveness_learning_degrades_without_blocking_hunting_health():
    report = build_health_report(
        None,
        env={
            "AEGIS_HEALTH_REQUIRED": "custom",
            "AEGIS_EFFECTIVENESS_BACKEND": "sqlite",
        },
        settings_error=ValueError("policy remains the independent blocker"),
        extra_probes={"custom": lambda: "ready"},
    )
    effectiveness = next(cell for cell in report.cells if cell.name == "effectiveness_learning")
    assert effectiveness.status is HealthStatus.DEGRADED
    assert effectiveness.required is False


def test_effectiveness_learning_fails_when_explicitly_required():
    report = build_health_report(
        None,
        env={
            "AEGIS_HEALTH_REQUIRED": "effectiveness_learning",
            "AEGIS_EFFECTIVENESS_BACKEND": "sqlite",
        },
        settings_error=ValueError("configuration unavailable"),
    )
    effectiveness = next(cell for cell in report.cells if cell.name == "effectiveness_learning")
    assert effectiveness.status is HealthStatus.FAILED and effectiveness.required
