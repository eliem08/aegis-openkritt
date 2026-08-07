"""Sensitive-data classifier (Phase 4 §Sensitive-data classifier).

Classifies raw artifacts — HTTP, browser, tool, and OAST output — *before*
normalization, so nothing sensitive is ever written to normal product data. It
combines five independent signals:

* **deterministic patterns** (private keys, AWS keys, JWTs, credit cards via Luhn,
  SSNs, ...),
* **structured-field rules** (a field literally named ``password``/``token``/
  ``ssn`` is sensitive regardless of value),
* **Shannon entropy** (long high-entropy strings look like secrets),
* **context** (a value adjacent to ``password=`` or in an ``Authorization``
  header), and
* **tenant-configured markers** (canaries and per-engagement patterns).

It distinguishes credentials, session tokens, private keys, financial data, direct
identifiers, and unrelated user content. A machine-learning hook may *raise*
suspicion but can never downgrade a deterministic sensitive match.
"""

from __future__ import annotations

import math
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum


class Category(str, Enum):
    CLEAN = "clean"
    CREDENTIAL = "credential"
    SESSION_TOKEN = "session_token"
    PRIVATE_KEY = "private_key"
    FINANCIAL = "financial"
    DIRECT_IDENTIFIER = "direct_identifier"
    USER_CONTENT = "user_content"          # unrelated personal content; sensitive-lite


class Method(str, Enum):
    DETERMINISTIC = "deterministic"
    STRUCTURED_FIELD = "structured_field"
    ENTROPY = "entropy"
    CONTEXT = "context"
    TENANT_MARKER = "tenant_marker"
    ML = "ml"


# Categories that a machine-learning signal alone may flag, but which a
# deterministic match always outranks (order = severity, high first).
_SEVERITY = [
    Category.PRIVATE_KEY, Category.CREDENTIAL, Category.SESSION_TOKEN,
    Category.FINANCIAL, Category.DIRECT_IDENTIFIER, Category.USER_CONTENT,
]


@dataclass(frozen=True)
class Match:
    category: Category
    method: Method
    field: str = ""
    redacted: str = ""            # a safe, non-reversible descriptor — never the value


@dataclass
class Classification:
    sensitive: bool
    category: Category
    method: Method
    matches: list[Match] = field(default_factory=list)
    confidence: float = 1.0

    @property
    def categories(self) -> set[Category]:
        return {m.category for m in self.matches}


# --- deterministic patterns ------------------------------------------------

_PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")
# Full PEM block, used for redaction so no fragment (incl. the END marker) survives.
_PRIVATE_KEY_BLOCK = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----", re.DOTALL)
_AWS_KEY = re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA)[0-9A-Z]{16}\b")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b")
_GCP_KEY = re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")
_SLACK = re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")
_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._-]{16,}")
_SSN = re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")
_CARD = re.compile(r"\b(?:\d[ -]?){13,19}\b")
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

_DETERMINISTIC = [
    (Category.PRIVATE_KEY, _PRIVATE_KEY),
    (Category.CREDENTIAL, _AWS_KEY),
    (Category.CREDENTIAL, _GCP_KEY),
    (Category.CREDENTIAL, _SLACK),
    (Category.SESSION_TOKEN, _JWT),
    (Category.SESSION_TOKEN, _BEARER),
    (Category.DIRECT_IDENTIFIER, _SSN),
]

# Field names whose *presence* makes a structured record sensitive.
_SENSITIVE_FIELDS = {
    "password": Category.CREDENTIAL, "passwd": Category.CREDENTIAL, "pwd": Category.CREDENTIAL,
    "secret": Category.CREDENTIAL, "api_key": Category.CREDENTIAL, "apikey": Category.CREDENTIAL,
    "client_secret": Category.CREDENTIAL, "private_key": Category.PRIVATE_KEY,
    "authorization": Category.SESSION_TOKEN, "session": Category.SESSION_TOKEN,
    "session_id": Category.SESSION_TOKEN, "access_token": Category.SESSION_TOKEN,
    "refresh_token": Category.SESSION_TOKEN, "id_token": Category.SESSION_TOKEN,
    "cookie": Category.SESSION_TOKEN, "set-cookie": Category.SESSION_TOKEN,
    "ssn": Category.DIRECT_IDENTIFIER, "national_id": Category.DIRECT_IDENTIFIER,
    "passport": Category.DIRECT_IDENTIFIER, "card_number": Category.FINANCIAL,
    "cardnumber": Category.FINANCIAL, "cc_number": Category.FINANCIAL, "cvv": Category.FINANCIAL,
    "iban": Category.FINANCIAL, "account_number": Category.FINANCIAL,
}

_CONTEXT_HINTS = re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key|authorization)\s*[=:]\s*\S")


@dataclass
class ClassifierConfig:
    entropy_min_length: int = 24
    entropy_threshold: float = 4.0        # bits/char; base64/hex secrets sit ~4.5-5
    tenant_markers: tuple[str, ...] = ()  # exact canary/marker strings
    tenant_patterns: tuple[str, ...] = () # extra regex
    detect_user_content: bool = True      # emails etc. as unrelated-user content


class SensitiveDataClassifier:
    def __init__(self, config: ClassifierConfig | None = None) -> None:
        self.config = config or ClassifierConfig()
        self._tenant_re = [re.compile(p) for p in self.config.tenant_patterns]

    def classify(self, artifact, *, ml_hook: Callable[[object], Classification | None] | None = None) -> Classification:
        matches: list[Match] = []
        self._scan(artifact, matches, field_name="")

        # A deterministic/structured/marker match is authoritative.
        if matches:
            return self._resolve(matches, ml_downgradeable=False)

        # ML may only *add* suspicion, never remove a deterministic verdict.
        if ml_hook is not None:
            ml = ml_hook(artifact)
            if ml is not None and ml.sensitive:
                m = Match(ml.category, Method.ML, redacted=f"ml:{ml.category.value}")
                return Classification(True, ml.category, Method.ML, [m], confidence=min(ml.confidence, 0.8))

        return Classification(False, Category.CLEAN, Method.DETERMINISTIC, [])

    # -- scanning -----------------------------------------------------------

    def _scan(self, value, matches: list[Match], *, field_name: str) -> None:
        if isinstance(value, dict):
            for key, sub in value.items():
                key_l = str(key).strip().lower()
                if key_l in _SENSITIVE_FIELDS and _non_empty(sub):
                    matches.append(Match(_SENSITIVE_FIELDS[key_l], Method.STRUCTURED_FIELD,
                                         field=str(key), redacted=f"field:{key_l}"))
                self._scan(sub, matches, field_name=str(key))
        elif isinstance(value, (list, tuple)):
            for item in value:
                self._scan(item, matches, field_name=field_name)
        elif isinstance(value, str):
            self._scan_text(value, matches, field_name)

    def _scan_text(self, text: str, matches: list[Match], field_name: str) -> None:
        for category, pattern in _DETERMINISTIC:
            if pattern.search(text):
                matches.append(Match(category, Method.DETERMINISTIC, field=field_name,
                                     redacted=f"pattern:{category.value}"))
        for card in _CARD.findall(text):
            digits = re.sub(r"\D", "", card)
            if 13 <= len(digits) <= 19 and _luhn(digits):
                matches.append(Match(Category.FINANCIAL, Method.DETERMINISTIC, field=field_name,
                                     redacted="pattern:card"))
        for marker in self.config.tenant_markers:
            if marker and marker in text:
                matches.append(Match(Category.CREDENTIAL, Method.TENANT_MARKER, field=field_name,
                                     redacted="tenant:marker"))
        for rx in self._tenant_re:
            if rx.search(text):
                matches.append(Match(Category.CREDENTIAL, Method.TENANT_MARKER, field=field_name,
                                     redacted="tenant:pattern"))
        if _CONTEXT_HINTS.search(text):
            matches.append(Match(Category.CREDENTIAL, Method.CONTEXT, field=field_name,
                                 redacted="context:credential-assignment"))
        # Entropy: a long token that looks like a secret.
        for token in re.findall(r"[A-Za-z0-9+/=_-]{%d,}" % self.config.entropy_min_length, text):
            if _shannon_entropy(token) >= self.config.entropy_threshold:
                matches.append(Match(Category.CREDENTIAL, Method.ENTROPY, field=field_name,
                                     redacted="entropy:high"))
                break
        if self.config.detect_user_content and _EMAIL.search(text):
            matches.append(Match(Category.USER_CONTENT, Method.DETERMINISTIC, field=field_name,
                                 redacted="pattern:email"))

    def _resolve(self, matches: list[Match], *, ml_downgradeable: bool) -> Classification:
        # A more authoritative method wins first (a deterministic/structured match
        # beats an entropy/context heuristic), then highest severity within it — so
        # a precise JWT->session-token is not overridden by an entropy->credential
        # guess that merely has a higher severity rank.
        ranked = sorted(matches, key=lambda m: (_method_rank(m.method), _SEVERITY.index(m.category)))
        top = ranked[0]
        return Classification(True, top.category, top.method, list(matches), confidence=1.0)


# --- helpers ---------------------------------------------------------------

def _non_empty(value) -> bool:
    return value not in (None, "", [], {}, ())


def _method_rank(method: Method) -> int:
    order = [Method.DETERMINISTIC, Method.STRUCTURED_FIELD, Method.TENANT_MARKER,
             Method.CONTEXT, Method.ENTROPY, Method.ML]
    return order.index(method)


def _luhn(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def redact(value, matches: list[Match] | None = None):
    """Produce a safe, redacted copy for a classification event — no raw values."""
    if isinstance(value, dict):
        out = {}
        for key, sub in value.items():
            if str(key).strip().lower() in _SENSITIVE_FIELDS:
                out[key] = "[redacted]"
            else:
                out[key] = redact(sub)
        return out
    if isinstance(value, (list, tuple)):
        return [redact(v) for v in value]
    if isinstance(value, str):
        red = _PRIVATE_KEY_BLOCK.sub("[redacted]", value)   # whole PEM block first
        for _cat, pattern in _DETERMINISTIC:
            red = pattern.sub("[redacted]", red)
        red = _CARD.sub(lambda m: "[redacted]" if _luhn(re.sub(r"\D", "", m.group())) else m.group(), red)
        return red
    return value
