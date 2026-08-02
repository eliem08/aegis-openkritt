"""Sensitive-data classifier + quarantine boundary (Phase 4).

Deterministic patterns, structured fields, entropy, context, and tenant markers
classify credentials/tokens/keys/financial/identifiers; ML may raise but never
downgrade a deterministic match; and a flagged artifact is fully contained
(cancel, encrypt-at-rest, redacted event, escalation, report-block).
"""

from __future__ import annotations

import json

import pytest

from aegis.api.crypto import FernetEncryptor, generate_key
from aegis.sensitive import (
    Category,
    Classification,
    ClassifierConfig,
    Method,
    SensitiveDataBoundary,
    SensitiveDataClassifier,
    redact,
)

clf = SensitiveDataClassifier()

RSA_KEY = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"
JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N"
AWS = "AKIAIOSFODNN7EXAMPLE"
VISA = "4111 1111 1111 1111"       # passes Luhn
SSN = "123-45-6789"


# --- deterministic categories ------------------------------------------------

@pytest.mark.parametrize("text,category", [
    (RSA_KEY, Category.PRIVATE_KEY),
    (AWS, Category.CREDENTIAL),
    (JWT, Category.SESSION_TOKEN),
    (f"Authorization: Bearer {JWT}", Category.SESSION_TOKEN),
    (VISA, Category.FINANCIAL),
    (SSN, Category.DIRECT_IDENTIFIER),
])
def test_deterministic_patterns_are_classified(text, category):
    result = clf.classify(text)
    assert result.sensitive and result.category == category
    assert result.method == Method.DETERMINISTIC


def test_invalid_card_number_is_not_financial():
    # 16 digits that fail Luhn are not a card.
    assert not clf.classify("1234 5678 9012 3456").sensitive


def test_structured_field_is_sensitive_regardless_of_value():
    result = clf.classify({"username": "alice", "password": "hunter2"})
    assert result.sensitive and result.category == Category.CREDENTIAL
    assert result.method == Method.STRUCTURED_FIELD


def test_nested_structures_are_scanned():
    artifact = {"data": {"items": [{"note": "ok"}, {"set-cookie": "session=abc"}]}}
    assert clf.classify(artifact).sensitive


def test_high_entropy_token_is_flagged():
    result = clf.classify("config value: Zx9Kd8fQ2mNpW4vT7bR1cY6hJ3sL0aE5uG8iO2kX4nZ")
    assert result.sensitive and any(m.method == Method.ENTROPY for m in result.matches)


def test_context_assignment_is_flagged():
    result = clf.classify("the request body was password=correct-horse")
    assert result.sensitive and any(m.method == Method.CONTEXT for m in result.matches)


def test_ordinary_content_is_clean():
    result = clf.classify({"title": "Welcome", "body": "Our store sells shoes and hats."})
    assert not result.sensitive and result.category == Category.CLEAN


# --- tenant markers ----------------------------------------------------------

def test_tenant_marker_is_flagged():
    c = SensitiveDataClassifier(ClassifierConfig(tenant_markers=("CANARY-acme-42",)))
    assert c.classify("leaked value CANARY-acme-42 here").sensitive


def test_tenant_pattern_is_flagged():
    c = SensitiveDataClassifier(ClassifierConfig(tenant_patterns=(r"ACME-\d{6}",)))
    assert c.classify("internal id ACME-123456").sensitive


# --- ML cannot downgrade -----------------------------------------------------

def test_ml_may_raise_suspicion_on_otherwise_clean_input():
    def ml_hook(_artifact):
        return Classification(True, Category.USER_CONTENT, Method.ML, [], confidence=0.9)

    result = clf.classify("nothing obviously secret", ml_hook=ml_hook)
    assert result.sensitive and result.method == Method.ML
    assert result.confidence <= 0.8            # ML confidence is capped


def test_ml_cannot_downgrade_a_deterministic_match():
    def ml_hook_says_clean(_artifact):
        return Classification(False, Category.CLEAN, Method.ML, [])

    # A real private key stays sensitive no matter what the ML hook says
    # (the hook is not even consulted once a deterministic match exists).
    result = clf.classify(RSA_KEY, ml_hook=ml_hook_says_clean)
    assert result.sensitive and result.category == Category.PRIVATE_KEY
    assert result.method == Method.DETERMINISTIC


def test_highest_severity_category_wins():
    artifact = {"email": "a@b.test", "private_key": RSA_KEY}
    result = clf.classify(artifact)
    assert result.category == Category.PRIVATE_KEY      # outranks user-content email


# --- redaction ---------------------------------------------------------------

def test_redaction_removes_raw_values():
    artifact = {"password": "hunter2", "note": f"key {AWS} and jwt {JWT}"}
    red = redact(artifact)
    assert red["password"] == "[redacted]"
    assert AWS not in json.dumps(red) and JWT not in json.dumps(red)


# --- quarantine boundary -----------------------------------------------------

def boundary():
    return SensitiveDataBoundary(encryptor=FernetEncryptor(generate_key()))


def test_quarantine_enforces_all_five_actions():
    b = boundary()
    artifact = {"response_body": f"secret {AWS}", "url": "https://api.example.test/x"}
    outcome = b.quarantine(clf.classify(artifact), classification=clf.classify(artifact)) \
        if False else b.quarantine(artifact, clf.classify(artifact),
                                   context={"tenant_id": "t", "scan_id": "s"})

    assert outcome.cancelled is True                     # (1) path cancelled
    assert outcome.encrypted_artifact and AWS not in outcome.encrypted_artifact  # (2) encrypted
    assert outcome.report_blocked is True                # (5) report blocked
    # (3) redacted classification event — no raw value anywhere in it
    event_json = json.dumps(outcome.classification_event)
    assert AWS not in event_json and outcome.classification_event["sensitive"] is True
    assert outcome.classification_event["category"] == "credential"
    assert outcome.classification_event["context"]["tenant_id"] == "t"
    # (4) operator escalation
    assert outcome.escalation["status"] == "open" and outcome.escalation["severity"] == "critical"


def test_quarantined_raw_value_is_recoverable_only_with_the_key():
    key = generate_key()
    b = SensitiveDataBoundary(encryptor=FernetEncryptor(key))
    artifact = {"body": f"token {JWT}"}
    outcome = b.quarantine(artifact, clf.classify(artifact))
    # opaque without the key
    assert JWT not in outcome.encrypted_artifact
    # recoverable with it (operator review)
    assert outcome.open(FernetEncryptor(key)) == artifact


def test_boundary_refuses_a_clean_classification():
    b = boundary()
    with pytest.raises(ValueError):
        b.quarantine({"title": "hello"}, clf.classify({"title": "hello"}))
