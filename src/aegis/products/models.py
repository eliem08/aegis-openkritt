"""Shared product contract.

The engine's lingua franca is the "report row" — a dict shaped like::

    {"json_answer": {"vulnerability_type", "file_path", "line", "summary", ...},
     "severity", "source", "confidence",
     "validation": {"verdict": "confirmed|false_positive|unresolved", ...},
     "reproduction": {"verdict": "reproduced|refuted|error|...", ...},
     "corroboration": {"count", "engines"}}

Products consume/emit these rows but present a stable :class:`ProductFinding`/:class:`ProductResult`
to a buyer, with the evidence stage derived — never asserted — from the row's own verdicts.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# The standing honesty contract, surfaced on every product result.
HONESTY = (
    "Candidates are unverified hypotheses. 'confirmed' means the citation validator matched the "
    "claim against pinned source; 'reproduced' is set ONLY by real local execution of a "
    "deterministic oracle, never by model confidence. Nothing here is submitted anywhere."
)

# Canonical evidence stages (mirror aegis.ai.agentic_os.EvidenceStage, kept as plain strings so
# the product layer has no hard import dependency on the kernel).
STAGE_CANDIDATE = "candidate"
STAGE_SOURCE_SUPPORTED = "source_supported"
STAGE_REPRODUCED = "locally_reproduced"
STAGE_REFUTED = "refuted"


@dataclass
class Evidence:
    """The strongest evidence a finding currently carries."""

    stage: str = STAGE_CANDIDATE
    verdict: str = "unresolved"  # detected | confirmed | reproduced | refuted | unresolved
    detail: str = ""

    def public(self) -> dict:
        return {"stage": self.stage, "verdict": self.verdict, "detail": self.detail}


def evidence_from_row(row: dict) -> Evidence:
    """Derive the honest evidence stage from a row's own validation/reproduction verdicts.

    Precedence: real reproduction > citation-validator confirmation > refutation > raw candidate.
    We never promote a row past what its recorded verdicts justify.
    """
    repro = (row.get("reproduction") or {}).get("verdict")
    if repro == "reproduced":
        return Evidence(STAGE_REPRODUCED, "reproduced", "confirmed by local execution oracle")
    val = (row.get("validation") or {})
    verdict = val.get("verdict") or row.get("validation_status")
    if verdict == "confirmed":
        return Evidence(STAGE_SOURCE_SUPPORTED, "confirmed", val.get("reason", ""))
    if verdict == "false_positive":
        return Evidence(STAGE_REFUTED, "refuted", val.get("reason", ""))
    if verdict in (None, "", "unverified"):
        # scanner rows arrive unverified — they are detections, not yet validated
        return Evidence(STAGE_CANDIDATE, "detected", "scanner/LLM candidate, not yet validated")
    return Evidence(STAGE_CANDIDATE, "unresolved", val.get("reason", ""))


@dataclass
class ProductFinding:
    """A buyer-facing finding, independent of which engine row produced it."""

    id: str
    title: str
    cwe: str
    file: str
    line: int
    severity: str
    confidence: float
    source: str
    evidence: Evidence = field(default_factory=Evidence)
    meta: dict = field(default_factory=dict)
    raw: dict = field(default_factory=dict, repr=False)

    @classmethod
    def from_row(cls, row: dict, *, index: int = 0) -> "ProductFinding":
        ja = row.get("json_answer") or {}
        cwe = str(ja.get("vulnerability_type") or row.get("cwe") or "")
        file = str(ja.get("file_path") or row.get("path") or "")
        try:
            line = int(ja.get("line") or row.get("line") or 0)
        except (TypeError, ValueError):
            line = 0
        conf = row.get("confidence")
        if conf is None:
            conf = (row.get("validation") or {}).get("confidence", 0.0)
        try:
            conf = round(float(conf), 3)
        except (TypeError, ValueError):
            conf = 0.0
        title = str(ja.get("summary") or ja.get("vulnerability_type") or row.get("rule") or "finding")
        fid = f"{file}:{line}:{cwe}" if file else f"finding-{index}"
        return cls(
            id=fid,
            title=title[:200],
            cwe=cwe,
            file=file,
            line=line,
            severity=str(row.get("severity") or ja.get("severity") or "medium"),
            confidence=conf,
            source=str(row.get("source") or row.get("tool") or "aegis"),
            evidence=evidence_from_row(row),
            raw=row,
        )

    def public(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "cwe": self.cwe,
            "file": self.file,
            "line": self.line,
            "severity": self.severity,
            "confidence": self.confidence,
            "source": self.source,
            "evidence": self.evidence.public(),
            **({"meta": self.meta} if self.meta else {}),
        }


def to_rows(obj) -> list[dict]:
    """Normalize a finding / report / list-of-findings into a list of engine rows."""
    if obj is None:
        return []
    if isinstance(obj, dict):
        if isinstance(obj.get("vulnerabilities"), list):
            return list(obj["vulnerabilities"])
        return [obj]
    if isinstance(obj, (list, tuple)):
        return [r for r in obj if isinstance(r, dict)]
    raise TypeError(f"cannot interpret {type(obj).__name__} as findings")


def to_report(rows: list[dict], *, repository: str = "", commit: str = "") -> dict:
    """Wrap rows in the engine's report envelope."""
    return {
        "scan": {"repository": repository, "commit": commit, "scope_digest": "source-review"},
        "vulnerabilities": list(rows),
    }


# Severity ordering for ranking (higher = worse).
_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "informational": 0}


def severity_rank(sev: str) -> int:
    return _SEV_RANK.get((sev or "").strip().casefold(), 2)


@dataclass
class ProductResult:
    """Uniform result for every product."""

    product: str
    target: str
    findings: list[ProductFinding] = field(default_factory=list)
    stats: dict = field(default_factory=dict)
    honesty: str = HONESTY

    def ranked(self) -> list[ProductFinding]:
        """Reproduced first, then confirmed, then by severity, then confidence."""
        order = {"reproduced": 3, "confirmed": 2, "detected": 1, "unresolved": 0, "refuted": -1}

        def key(f: ProductFinding):
            return (
                order.get(f.evidence.verdict, 0),
                severity_rank(f.severity),
                f.confidence,
            )

        return sorted(self.findings, key=key, reverse=True)

    def count(self, verdict: str) -> int:
        return sum(1 for f in self.findings if f.evidence.verdict == verdict)

    @property
    def reproduced(self) -> list[ProductFinding]:
        return [f for f in self.findings if f.evidence.verdict == "reproduced"]

    @property
    def confirmed(self) -> list[ProductFinding]:
        return [f for f in self.findings if f.evidence.verdict == "confirmed"]

    def to_dict(self) -> dict:
        return {
            "product": self.product,
            "target": self.target,
            "findings": [f.public() for f in self.ranked()],
            "stats": {
                **self.stats,
                "total": len(self.findings),
                "reproduced": self.count("reproduced"),
                "confirmed": self.count("confirmed"),
                "detected": self.count("detected"),
                "refuted": self.count("refuted"),
                "unresolved": self.count("unresolved"),
            },
            "honesty": self.honesty,
        }
