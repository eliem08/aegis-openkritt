"""Notifications (Phase 4 §Continuous monitoring and subscans).

Typed destinations with **encrypted secret references** (never inline tokens),
**idempotent** deliveries keyed by a dedupe key, each recording attempts, response
class, and final status. Messages carry **sanitized summaries and deep links** —
never raw evidence or credentials — enforced by running the payload through the
sensitive-data redactor before it leaves.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime

from aegis.sensitive import SensitiveDataClassifier, redact


class DestinationKind:
    SLACK = "slack"
    WEBHOOK = "webhook"
    EMAIL = "email"


@dataclass(frozen=True)
class Destination:
    kind: str
    address: str                 # channel/url/mailbox
    secret_ref: str              # opaque ref into the secrets service; never a token


@dataclass(frozen=True)
class Notification:
    dedupe_key: str              # idempotency key
    destination: Destination
    summary: str                 # sanitized human summary
    deep_link: str               # link into the product; not raw evidence
    fields: dict = field(default_factory=dict)


@dataclass
class DeliveryRecord:
    delivery_id: str
    dedupe_key: str
    destination_kind: str
    attempts: int
    response_class: str          # 2xx | 4xx | 5xx | error
    final_status: str            # delivered | failed | duplicate | blocked
    at: datetime


# The sender performs the actual transport and returns a response class.
Sender = Callable[[Destination, dict], str]


class Notifier:
    def __init__(self, sender: Sender, *, secrets=None, max_attempts: int = 3,
                 classifier: SensitiveDataClassifier | None = None,
                 on_record: Callable[[DeliveryRecord], None] | None = None) -> None:
        self._sender = sender
        self._secrets = secrets
        self._max_attempts = max_attempts
        self._classifier = classifier or SensitiveDataClassifier()
        self._on_record = on_record
        self._delivered: dict[str, DeliveryRecord] = {}     # dedupe_key -> record

    def send(self, notification: Notification) -> DeliveryRecord:
        # Idempotent: a dedupe key that already succeeded is never re-sent.
        existing = self._delivered.get(notification.dedupe_key)
        if existing is not None and existing.final_status in ("delivered", "blocked"):
            return self._record(DeliveryRecord(
                uuid.uuid4().hex, notification.dedupe_key, notification.destination.kind,
                attempts=0, response_class="duplicate", final_status="duplicate", at=_now()))

        payload = self._sanitize(notification)
        if payload is None:
            # A summary that still contains sensitive data is blocked, not sent.
            rec = DeliveryRecord(uuid.uuid4().hex, notification.dedupe_key,
                                 notification.destination.kind, attempts=0,
                                 response_class="blocked", final_status="blocked", at=_now())
            self._delivered[notification.dedupe_key] = rec
            return self._record(rec)

        response_class, attempts = self._deliver_with_retry(notification.destination, payload)
        final = "delivered" if response_class == "2xx" else "failed"
        rec = DeliveryRecord(uuid.uuid4().hex, notification.dedupe_key,
                             notification.destination.kind, attempts=attempts,
                             response_class=response_class, final_status=final, at=_now())
        if final == "delivered":
            self._delivered[notification.dedupe_key] = rec
        return self._record(rec)

    # -- internals ----------------------------------------------------------

    def _sanitize(self, notification: Notification) -> dict | None:
        payload = {
            "summary": redact(notification.summary),
            "deep_link": notification.deep_link,
            "fields": redact(notification.fields),
        }
        # Defense in depth: if anything sensitive survived, do not deliver.
        if self._classifier.classify(payload).sensitive:
            return None
        return payload

    def _deliver_with_retry(self, destination: Destination, payload: dict) -> tuple[str, int]:
        attempts = 0
        response_class = "error"
        for attempts in range(1, self._max_attempts + 1):
            try:
                response_class = self._sender(destination, payload)
            except Exception:
                response_class = "error"
            if response_class == "2xx" or response_class == "4xx":
                break   # success, or a client error that will not be fixed by retry
        return response_class, attempts

    def _record(self, rec: DeliveryRecord) -> DeliveryRecord:
        if self._on_record is not None:
            self._on_record(rec)
        return rec


def _now() -> datetime:
    return datetime.now(UTC)
