"""Observability (Phase 5): spans/metrics/logs, pseudonymous tenants, redaction."""

from __future__ import annotations

import pytest

from aegis.observ import MetricNames, Telemetry

AWS = "AKIAIOSFODNN7EXAMPLE"


def tel():
    return Telemetry(tenant_salt="s")


# --- spans -------------------------------------------------------------------

def test_span_records_name_duration_and_status():
    t = tel()
    with t.span("scan.run", scan_id="s1"):
        pass
    span = t.exporter.spans[0]
    assert span.name == "scan.run" and span.status == "ok" and span.duration_ms >= 0


def test_span_marks_error_and_reraises():
    t = tel()
    with pytest.raises(ValueError):
        with t.span("adapter.parse"):
            raise ValueError("boom")
    assert t.exporter.spans[0].status == "error"


# --- metrics -----------------------------------------------------------------

def test_counter_histogram_and_gauge_record():
    t = tel()
    t.counter(MetricNames.GATEWAY_BLOCKS).inc(reason="out_of_scope")
    t.histogram(MetricNames.POLICY_LATENCY).observe(12.5)
    t.gauge(MetricNames.TASK_AGE).set(30, state="queued")

    kinds = {(m.name, m.kind, m.value) for m in t.exporter.metrics}
    assert (MetricNames.GATEWAY_BLOCKS, "counter", 1.0) in kinds
    assert (MetricNames.POLICY_LATENCY, "histogram", 12.5) in kinds
    assert (MetricNames.TASK_AGE, "gauge", 30.0) in kinds


def test_enumerated_metric_names_are_defined():
    for name in ("SENSITIVE_QUARANTINES", "FINDING_VERIFICATION", "SNAPSHOT_COVERAGE",
                 "NOTIFICATION_DELIVERY", "REPORT_GATE_FAILURES", "RESERVATION_LATENCY"):
        assert getattr(MetricNames, name)


# --- pseudonymous tenants ----------------------------------------------------

def test_tenant_ids_are_pseudonymous_everywhere():
    t = tel()
    with t.span("x", tenant_id="tenant-a"):
        pass
    t.counter(MetricNames.REQUEST_RATE).inc(tenant_id="tenant-a")
    t.log("info", "hello", tenant="tenant-a")

    assert t.exporter.spans[0].attributes["tenant_id"].startswith("tnt_")
    assert t.exporter.metrics[0].labels["tenant_id"].startswith("tnt_")
    assert t.exporter.logs[0].fields["tenant"].startswith("tnt_")
    # the raw tenant id never appears anywhere
    blob = str(vars(t.exporter))
    assert "tenant-a" not in blob


def test_pseudonym_is_stable_and_distinct():
    t = tel()
    assert t.pseudonymize("tenant-a") == t.pseudonymize("tenant-a")
    assert t.pseudonymize("tenant-a") != t.pseudonymize("tenant-b")


# --- redaction ---------------------------------------------------------------

def test_secrets_are_redacted_from_logs_and_spans():
    t = tel()
    t.log("warn", "leaked", detail=f"body had {AWS}")
    with t.span("probe", note=f"key {AWS}"):
        pass
    assert AWS not in str(t.exporter.logs[0].fields)
    assert AWS not in str(t.exporter.spans[0].attributes)
