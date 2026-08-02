"""High-value secrets in first-party JavaScript (report-corpus driven).

A recurring corpus cluster: a live credential — a Bearer/API token, an RPC
provider key, a JWT, a hardcoded private key — shipped inside a *first-party* JS
bundle (often with a year-long cache header). This runs the sensitive-data
classifier over acquired JavaScript and reports only the high-value categories,
with the bundle's URL, line, and a redacted snippet. A secret in a *first-party*
bundle scores higher than one in a third-party library (which is often that
library's own public key). Purely analytical over JS already fetched in scope;
every finding is a candidate (``verified=False``) that never carries the raw value.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

from aegis.policy.scope import ScopeGuard
from aegis.sensitive import Category, SensitiveDataClassifier, redact

# Only these categories matter in a JS bundle; emails/PII are handled elsewhere.
HIGH_VALUE_CATEGORIES = (Category.CREDENTIAL, Category.SESSION_TOKEN, Category.PRIVATE_KEY)


@dataclass(frozen=True)
class JsSecretFinding:
    category: str
    method: str
    source_url: str
    first_party: bool
    line: int
    context: str            # redacted snippet — never the raw value
    confidence: float
    verified: bool = False


def analyze_javascript_secrets(
    js_text: str, source_url: str, *, scope_hosts=(), classifier: SensitiveDataClassifier | None = None,
) -> list[JsSecretFinding]:
    clf = classifier or SensitiveDataClassifier()
    first_party = _is_first_party(source_url, scope_hosts)

    findings: list[JsSecretFinding] = []
    seen: set[tuple[str, int]] = set()
    for line_no, line in enumerate((js_text or "").splitlines(), start=1):
        result = clf.classify(line)
        if not result.sensitive:
            continue
        for match in result.matches:
            if match.category not in HIGH_VALUE_CATEGORIES:
                continue
            key = (match.category.value, line_no)
            if key in seen:
                continue
            seen.add(key)
            findings.append(JsSecretFinding(
                category=match.category.value, method=match.method.value, source_url=source_url,
                first_party=first_party, line=line_no, context=str(redact(line))[:120],
                confidence=0.9 if first_party else 0.4,
            ))
    return findings


def _is_first_party(source_url: str, scope_hosts) -> bool:
    host = (urlsplit(source_url).hostname or "").lower()
    hosts = list(scope_hosts)
    if not hosts:
        return True                     # no scope given — cannot rule it out
    return ScopeGuard(hosts).is_allowed(host)
