"""The sensitive-data quarantine boundary (Phase 4 §Sensitive-data classifier).

When the classifier flags an artifact, five things must happen atomically, and
this is the single place that guarantees them:

1. the current path is **cancelled**;
2. the raw artifact is **quarantined, encrypted at rest** (never stored in the
   clear, never in normal product data);
3. only a **redacted classification event** reaches normal product data;
4. an **operator escalation** is created;
5. **report rendering is blocked** until the item is reviewed or safely discarded.

The raw value is available only through the encrypted blob, which needs the
secrets-service key to open — so a sensitive value cannot leak into the graph, an
API response, or a report by construction.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from aegis.api.crypto import Encryptor, NullEncryptor

from .classifier import Category, Classification, redact


@dataclass(frozen=True)
class QuarantineOutcome:
    quarantine_id: str
    cancelled: bool                      # (1) the path is stopped
    encrypted_artifact: str              # (2) ciphertext; opaque without the key
    classification_event: dict           # (3) redacted — safe for normal product data
    escalation: dict                     # (4) operator escalation
    report_blocked: bool                 # (5) blocks report rendering
    category: str
    method: str
    created_at: str

    def open(self, encryptor: Encryptor):
        """Decrypt the raw artifact — operator/review use only."""
        return json.loads(encryptor.decrypt(self.encrypted_artifact))


class SensitiveDataBoundary:
    """Turns a sensitive classification into a fully-contained quarantine."""

    def __init__(self, *, encryptor: Encryptor | None = None) -> None:
        self._enc = encryptor or NullEncryptor()

    def quarantine(self, artifact, classification: Classification, *, context: dict | None = None) -> QuarantineOutcome:
        if not classification.sensitive:
            raise ValueError("quarantine() called for a non-sensitive classification")
        now = datetime.now(UTC).isoformat()
        qid = uuid.uuid4().hex
        ctx = dict(context or {})

        encrypted = self._enc.encrypt(json.dumps(artifact, default=str))
        redacted_summary = redact(artifact, classification.matches)

        classification_event = {
            "quarantine_id": qid,
            "sensitive": True,
            "category": classification.category.value,
            "method": classification.method.value,
            # only redacted descriptors — never the raw value
            "markers": sorted({m.redacted for m in classification.matches}),
            "categories": sorted(c.value for c in classification.categories),
            "redacted": redacted_summary,
            "context": {k: ctx[k] for k in ("tenant_id", "engagement_id", "scan_id", "task_id") if k in ctx},
            "created_at": now,
        }
        escalation = {
            "escalation_id": uuid.uuid4().hex,
            "quarantine_id": qid,
            "reason": f"sensitive data ({classification.category.value}) encountered; path cancelled",
            "severity": _escalation_severity(classification.category),
            "status": "open",
            "created_at": now,
            **{k: ctx[k] for k in ("tenant_id", "engagement_id", "scan_id", "task_id") if k in ctx},
        }
        return QuarantineOutcome(
            quarantine_id=qid, cancelled=True, encrypted_artifact=encrypted,
            classification_event=classification_event, escalation=escalation,
            report_blocked=True, category=classification.category.value,
            method=classification.method.value, created_at=now,
        )


def _escalation_severity(category: Category) -> str:
    return {
        Category.PRIVATE_KEY: "critical",
        Category.CREDENTIAL: "critical",
        Category.SESSION_TOKEN: "high",
        Category.FINANCIAL: "high",
        Category.DIRECT_IDENTIFIER: "high",
        Category.USER_CONTENT: "medium",
    }.get(category, "high")
