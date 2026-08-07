"""Identifier enumeration-risk analysis (Phase 3 extension).

Informed by real broken-access-control reports where the *enumerability* of an
object identifier is what turns a single IDOR into mass exposure ("sequential
number", "enumerate 800,000+ records"). Given a sample of object identifiers, this
scores how predictable they are, so a BOLA candidate on a sequential id is flagged
with its true impact rather than treated like one on an opaque UUID.

Purely analytical and read-only — it inspects identifiers already observed during
authorized discovery and never generates traffic.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)
_INT = re.compile(r"^\d+$")
_HEX = re.compile(r"^[0-9a-f]+$", re.IGNORECASE)


class IdentifierKind(str, Enum):
    SEQUENTIAL_INT = "sequential_int"
    SMALL_INT = "small_int"
    TIMESTAMP = "timestamp"
    UUID = "uuid"
    HIGH_ENTROPY = "high_entropy"
    OPAQUE = "opaque"
    MIXED = "mixed"


@dataclass(frozen=True)
class IdentifierProfile:
    kind: IdentifierKind
    enumeration_risk: float          # 0.0 (opaque) .. 1.0 (trivially enumerable)
    reason: str
    samples: int

    @property
    def enumerable(self) -> bool:
        return self.enumeration_risk >= 0.6


def analyze_identifiers(values) -> IdentifierProfile:
    samples = [str(v).strip() for v in values if str(v).strip()]
    n = len(samples)
    if n == 0:
        return IdentifierProfile(IdentifierKind.OPAQUE, 0.0, "no samples", 0)

    if all(_UUID.match(v) for v in samples):
        return IdentifierProfile(IdentifierKind.UUID, 0.05, "UUIDv4 identifiers", n)

    if all(_INT.match(v) for v in samples):
        return _analyze_ints(samples)

    # Long high-entropy tokens (hex/base62) are hard to guess.
    if all(len(v) >= 16 and _looks_random(v) for v in samples):
        return IdentifierProfile(IdentifierKind.HIGH_ENTROPY, 0.1,
                                 "long high-entropy tokens", n)

    if any(_INT.match(v) for v in samples):
        return IdentifierProfile(IdentifierKind.MIXED, 0.55,
                                 "mixed numeric/opaque identifiers", n)

    return IdentifierProfile(IdentifierKind.OPAQUE, 0.2, "opaque identifiers", n)


def _analyze_ints(samples: list[str]) -> IdentifierProfile:
    ints = sorted({int(v) for v in samples})     # dedupe: repeats are not gaps
    n = len(ints)
    # Unix-second timestamps (roughly 2001..2035) look numeric but are dated.
    if all(1_000_000_000 <= v <= 2_100_000_000 for v in ints) and n >= 2:
        return IdentifierProfile(IdentifierKind.TIMESTAMP, 0.45,
                                 "timestamp-like integers (partially predictable)", n)
    if n >= 2:
        gaps = [b - a for a, b in zip(ints, ints[1:])]
        if all(g == 1 for g in gaps):
            return IdentifierProfile(IdentifierKind.SEQUENTIAL_INT, 0.98,
                                     "consecutive integer ids — trivially enumerable", n)
        if max(gaps) <= 100:
            return IdentifierProfile(IdentifierKind.SEQUENTIAL_INT, 0.9,
                                     "near-sequential integer ids — easily enumerable", n)
    magnitude = ints[-1]
    if magnitude < 10_000_000:
        return IdentifierProfile(IdentifierKind.SMALL_INT, 0.75,
                                 "small integer ids — enumerable by brute force", n)
    return IdentifierProfile(IdentifierKind.SMALL_INT, 0.6,
                             "large integer ids — enumerable but wide range", n)


def _looks_random(value: str) -> bool:
    # Not purely numeric and not obviously structured; entropy proxy = distinct chars.
    if _INT.match(value):
        return False
    distinct = len(set(value.lower()))
    return distinct >= min(10, len(value) // 2)
