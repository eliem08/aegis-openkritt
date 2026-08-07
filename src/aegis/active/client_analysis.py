"""Client-side script analysis (report-corpus driven).

Three client-side anti-patterns recur across the corpus and are statically
visible in first-party JS:

* ``postMessage(data, '*')`` — sends data to *any* origin (the review-platform
  OAuth-code leak; the payment card skimmer);
* a ``message`` listener with **no ``event.origin`` check** — accepts messages
  from any framing site (the card skimmer's disabled origin check);
* an **unanchored host/origin allowlist** — ``origin.indexOf(trusted)`` /
  ``.includes(...)`` instead of an exact/anchored match (the unanchored-allowlist
  reflected XSS and the in-app-browser "contains-domain" bypass).

Purely static analysis over acquired JavaScript; findings carry a line and a
redacted snippet and are candidates (``verified=False``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

from aegis.sensitive import redact

_POSTMESSAGE_WILDCARD = re.compile(r"\.postMessage\s*\(\s*[^,]+,\s*(['\"])\*\1")
_MESSAGE_LISTENER = re.compile(r"addEventListener\s*\(\s*(['\"])message\1|\bonmessage\s*=")
_ORIGIN_CHECK = re.compile(r"\.origin\b")
# Substring/contains tests on a host/origin — unanchored allowlists.
_UNANCHORED_HOST = re.compile(
    r"\b(hostname|host|origin|referrer|domain)\b\s*\.\s*(indexOf|includes|search|match)\s*\(", re.IGNORECASE)


class ClientIssue(str, Enum):
    POSTMESSAGE_WILDCARD_TARGET = "postmessage_wildcard_target"
    MESSAGE_LISTENER_NO_ORIGIN_CHECK = "message_listener_no_origin_check"
    UNANCHORED_HOST_CHECK = "unanchored_host_check"


@dataclass(frozen=True)
class ClientFinding:
    issue: ClientIssue
    source_url: str
    line: int
    snippet: str            # redacted
    confidence: float
    verified: bool = False


def analyze_client_script(js_text: str, source_url: str) -> list[ClientFinding]:
    lines = (js_text or "").splitlines()
    findings: list[ClientFinding] = []
    has_origin_check = any(_ORIGIN_CHECK.search(line) for line in lines)

    for line_no, line in enumerate(lines, start=1):
        snippet = str(redact(line)).strip()[:120]
        if _POSTMESSAGE_WILDCARD.search(line):
            findings.append(ClientFinding(ClientIssue.POSTMESSAGE_WILDCARD_TARGET,
                                          source_url, line_no, snippet, 0.8))
        if _MESSAGE_LISTENER.search(line) and not has_origin_check:
            # A message handler that never consults event.origin trusts any framer.
            findings.append(ClientFinding(ClientIssue.MESSAGE_LISTENER_NO_ORIGIN_CHECK,
                                          source_url, line_no, snippet, 0.6))
        if _UNANCHORED_HOST.search(line):
            findings.append(ClientFinding(ClientIssue.UNANCHORED_HOST_CHECK,
                                          source_url, line_no, snippet, 0.6))
    return findings
