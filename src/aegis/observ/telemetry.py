"""Observability (Phase 5 §Observability and SLOs).

An OpenTelemetry-shaped facade — spans, metrics, and structured logs — over a
pluggable exporter (in-memory for tests; a real OTel SDK in production). Two
privacy rules are enforced here so no call site can forget them:

* **tenant identifiers are pseudonymous** in general telemetry (a stable salted
  hash, never the raw id), and
* every attribute/field is run through the sensitive-data redactor, so a stray
  secret in a log line or span attribute cannot leak through telemetry.

The metric names the spec enumerates live in :class:`MetricNames` so every signal
has one canonical key.
"""

from __future__ import annotations

import hashlib
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone

from aegis.sensitive import redact

TENANT_KEYS = frozenset({"tenant_id", "tenant"})


class MetricNames:
    POLICY_LATENCY = "aegis.policy.decision.latency_ms"
    RESERVATION_LATENCY = "aegis.reservation.latency_ms"
    POLICY_DENIALS = "aegis.policy.denials"                 # label: reason
    TASK_AGE = "aegis.task.age_seconds"                     # label: state
    LEASE_EXPIRY = "aegis.lease.expiries"
    REQUEST_RATE = "aegis.gateway.requests"
    GATEWAY_BLOCKS = "aegis.gateway.blocks"                 # label: reason
    RETRIES = "aegis.adapter.retries"
    TARGET_HEALTH = "aegis.target.health"                  # label: state
    ADAPTER_ERRORS = "aegis.adapter.errors"                # labels: adapter, version
    OUTPUT_SCHEMA_MISMATCH = "aegis.adapter.output_schema_mismatch"
    SENSITIVE_QUARANTINES = "aegis.sensitive.quarantines"  # label: category
    SNAPSHOT_COVERAGE = "aegis.snapshot.coverage"          # label: complete/partial
    FINDING_VERIFICATION = "aegis.finding.verification"    # label: verified/hypothesis
    NOTIFICATION_DELIVERY = "aegis.notification.delivery"  # label: final_status
    REPORT_GATE_FAILURES = "aegis.report.quality_gate_failures"


@dataclass
class SpanRecord:
    name: str
    attributes: dict
    duration_ms: float
    status: str          # ok | error
    started_at: datetime


@dataclass
class MetricRecord:
    name: str
    kind: str            # counter | histogram | gauge
    value: float
    labels: dict


@dataclass
class LogRecord:
    level: str
    message: str
    fields: dict
    at: datetime


@dataclass
class InMemoryExporter:
    spans: list = field(default_factory=list)
    metrics: list = field(default_factory=list)
    logs: list = field(default_factory=list)


class Telemetry:
    def __init__(self, *, tenant_salt: str = "aegis", exporter: InMemoryExporter | None = None) -> None:
        self._salt = tenant_salt
        self.exporter = exporter or InMemoryExporter()

    # -- spans --------------------------------------------------------------

    @contextmanager
    def span(self, name: str, **attributes):
        start = time.monotonic()
        attrs = self._clean(attributes)
        status = "ok"
        try:
            yield attrs
        except Exception:
            status = "error"
            raise
        finally:
            self.exporter.spans.append(SpanRecord(
                name=name, attributes=attrs, duration_ms=(time.monotonic() - start) * 1000,
                status=status, started_at=_now()))

    # -- metrics ------------------------------------------------------------

    def counter(self, name: str) -> "_Metric":
        return _Metric(self, name, "counter")

    def histogram(self, name: str) -> "_Metric":
        return _Metric(self, name, "histogram")

    def gauge(self, name: str) -> "_Metric":
        return _Metric(self, name, "gauge")

    def _emit_metric(self, name, kind, value, labels) -> None:
        self.exporter.metrics.append(MetricRecord(name, kind, float(value), self._clean(labels)))

    # -- logs ---------------------------------------------------------------

    def log(self, level: str, message: str, **fields) -> None:
        self.exporter.logs.append(LogRecord(level, message, self._clean(fields), _now()))

    # -- privacy ------------------------------------------------------------

    def pseudonymize(self, tenant_id: str) -> str:
        digest = hashlib.sha256(f"{self._salt}:{tenant_id}".encode("utf-8")).hexdigest()[:12]
        return f"tnt_{digest}"

    def _clean(self, mapping: dict) -> dict:
        cleaned = {}
        for key, value in (mapping or {}).items():
            if key in TENANT_KEYS and value is not None:
                cleaned[key] = self.pseudonymize(str(value))
            else:
                cleaned[key] = redact(value)           # never leak a secret via telemetry
        return cleaned


@dataclass
class _Metric:
    telemetry: Telemetry
    name: str
    kind: str

    def inc(self, amount: float = 1.0, **labels) -> None:
        self.telemetry._emit_metric(self.name, self.kind, amount, labels)

    def observe(self, value: float, **labels) -> None:
        self.telemetry._emit_metric(self.name, self.kind, value, labels)

    def set(self, value: float, **labels) -> None:
        self.telemetry._emit_metric(self.name, self.kind, value, labels)


def _now() -> datetime:
    return datetime.now(timezone.utc)
