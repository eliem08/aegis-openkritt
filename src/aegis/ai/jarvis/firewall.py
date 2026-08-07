"""Prompt-injection and egress controls for untrusted repository content."""

from __future__ import annotations

import re
from dataclasses import dataclass

_INSTRUCTION_PATTERNS = (
    re.compile(r"\bignore (all|any|the|previous|prior) instructions\b", re.IGNORECASE),
    re.compile(r"\bsystem prompt\b", re.IGNORECASE),
    re.compile(r"\bdeveloper message\b", re.IGNORECASE),
    re.compile(r"\bexfiltrat(e|ion)\b", re.IGNORECASE),
    re.compile(r"\bupload\b.{0,30}\b(secret|credential|source|token|key)\b", re.IGNORECASE),
    re.compile(r"\bdisable\b.{0,30}\b(safety|policy|guard|filter)\b", re.IGNORECASE),
)

_SECRET_PATTERNS = (
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
)


@dataclass(frozen=True)
class ContentAssessment:
    untrusted_instructions: bool
    secret_like_material: bool
    external_egress_allowed: bool
    reasons: tuple[str, ...]


def assess_untrusted_content(
    text: str,
    *,
    external_egress_authorized: bool,
) -> ContentAssessment:
    instruction = any(pattern.search(text) for pattern in _INSTRUCTION_PATTERNS)
    secret = any(pattern.search(text) for pattern in _SECRET_PATTERNS)
    reasons: list[str] = []

    if instruction:
        reasons.append("instruction_like_repository_content")
    if secret:
        reasons.append("secret_like_material")
    if not external_egress_authorized:
        reasons.append("external_egress_not_authorized")

    return ContentAssessment(
        untrusted_instructions=instruction,
        secret_like_material=secret,
        external_egress_allowed=external_egress_authorized and not secret,
        reasons=tuple(reasons),
    )


def envelope_untrusted_source(path: str, content: str) -> str:
    """Wrap repository text so model-facing prompts cannot confuse it with instructions."""
    return (
        "<UNTRUSTED_REPOSITORY_DATA>\n"
        f"<PATH>{path}</PATH>\n"
        "<CONTENT>\n"
        f"{content}\n"
        "</CONTENT>\n"
        "</UNTRUSTED_REPOSITORY_DATA>"
    )
