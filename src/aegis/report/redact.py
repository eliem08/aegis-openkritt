"""Evidence redaction (Master Prompt §7; P1 #23).

Before any evidence is stored or put in a report, strip credentials and
unrelated personal data: auth headers, cookies, bearer tokens, JWTs, API keys,
emails, and card-like numbers. Redaction is conservative and pattern-based —
it favours over-redacting a secret to leaking one.
"""

from __future__ import annotations

import re

from aegis.model import EvidenceBundle, InteractionStep

# (pattern, replacement) applied in order. Case-insensitive where relevant.
_RULES: list[tuple[re.Pattern[str], str]] = [
    # Whole auth/cookie header lines.
    (re.compile(r"(?im)^(authorization:\s*).*$"), r"\1[REDACTED]"),
    (re.compile(r"(?im)^(proxy-authorization:\s*).*$"), r"\1[REDACTED]"),
    (re.compile(r"(?im)^(set-cookie:\s*).*$"), r"\1[REDACTED]"),
    (re.compile(r"(?im)^(cookie:\s*).*$"), r"\1[REDACTED]"),
    (re.compile(r"(?im)^(x-api-key:\s*).*$"), r"\1[REDACTED]"),
    # Inline bearer tokens.
    (re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]+"), "Bearer [REDACTED]"),
    # JWTs (three base64url segments).
    (re.compile(r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"), "[REDACTED_JWT]"),
    # Common key/token assignments in JSON/query.
    (re.compile(r'(?i)("?(?:api[_-]?key|access[_-]?token|secret|password|token)"?\s*[:=]\s*)"?[^"&\s,}]+"?'),
     r"\1[REDACTED]"),
    # AWS access key ids.
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED_AWS_KEY]"),
    # Emails.
    (re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"), "[REDACTED_EMAIL]"),
    # Card-like numbers (13–16 digits, optional spaces/dashes).
    (re.compile(r"\b(?:\d[ -]?){13,16}\b"), "[REDACTED_CC]"),
]


def redact(text: str | None) -> str | None:
    if not text:
        return text
    for pattern, replacement in _RULES:
        text = pattern.sub(replacement, text)
    return text


def redact_step(step: InteractionStep) -> InteractionStep:
    return step.model_copy(
        update={
            "request": redact(step.request),
            "response": redact(step.response),
            "summary": redact(step.summary) or step.summary,
            "sanitized": True,
        }
    )


def redact_evidence(bundle: EvidenceBundle) -> EvidenceBundle:
    return bundle.model_copy(
        update={
            "steps": [redact_step(s) for s in bundle.steps],
            "observed": redact(bundle.observed) or "",
            "expected": redact(bundle.expected) or "",
        }
    )
