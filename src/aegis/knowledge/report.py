"""Normalized disclosed-report model (Master Prompt §3 LEARN, §8 enrichment).

A ``DisclosedReport`` is a single past bug-bounty finding — from HackerOne
hacktivity, a program's disclosed reports, or any exported corpus — reduced to
the fields we learn from: the weakness (CWE), the asset it hit, severity, and
bounty. The corpus of these becomes historical priors that inform which test
classes to prioritise and how confident to be in a new finding.

The model is tolerant (``extra="ignore"``) so real-world exports with extra
keys ingest cleanly.
"""

from __future__ import annotations

import re
from datetime import datetime
from enum import IntEnum

from pydantic import BaseModel, ConfigDict, field_validator


class Severity(IntEnum):
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value) -> Severity:
        if value is None or value == "":
            return cls.NONE
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            # numeric could be a CVSS-ish score or an enum ordinal
            if 0 <= value <= 4 and float(value).is_integer():
                return cls(int(value))
            return _cvss_to_severity(float(value))
        key = str(value).strip().upper()
        aliases = {"INFO": "NONE", "INFORMATIONAL": "NONE", "NONE": "NONE"}
        key = aliases.get(key, key)
        try:
            return cls[key]
        except KeyError:
            return cls.NONE

    @property
    def label(self) -> str:
        return self.name.lower()


def _cvss_to_severity(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
    return Severity.NONE


_CWE_RE = re.compile(r"cwe[-_ ]?(\d+)", re.IGNORECASE)


def normalize_cwe(value: str | int | None) -> str:
    """Return a canonical ``CWE-<n>`` string, or '' if none can be parsed."""
    if value is None:
        return ""
    if isinstance(value, int) and not isinstance(value, bool):
        return f"CWE-{value}"
    s = str(value).strip()
    if s.isdigit():
        return f"CWE-{int(s)}"
    m = _CWE_RE.search(s)
    return f"CWE-{int(m.group(1))}" if m else ""


class DisclosedReport(BaseModel):
    model_config = ConfigDict(extra="ignore")

    report_id: str
    source: str = "hackerone"
    program: str = ""
    title: str = ""
    weakness: str = ""
    cwe: str = ""
    severity: Severity = Severity.NONE
    asset_type: str = ""
    asset_identifier: str = ""
    substate: str = ""
    bounty: float | None = None
    disclosed_at: datetime | None = None
    summary: str = ""
    url: str | None = None
    tags: list[str] = []

    @field_validator("cwe", mode="before")
    @classmethod
    def _norm_cwe(cls, v):
        return normalize_cwe(v)

    @field_validator("severity", mode="before")
    @classmethod
    def _norm_sev(cls, v):
        return Severity.parse(v)

    @field_validator("asset_type", mode="before")
    @classmethod
    def _norm_asset_type(cls, v):
        return (str(v or "")).strip().lower()

    @property
    def weakness_key(self) -> str:
        """Grouping key: prefer CWE, fall back to the weakness name."""
        return self.cwe or (self.weakness.strip().lower() or "unknown")
