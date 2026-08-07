"""Retrieval-augmented detection: show the generator real disclosed bugs of this class.

Aegis already has a knowledge base of past *disclosed* bug-bounty reports
(``aegis.knowledge.ReportCorpus``), but the generator never saw it. Ensemble sampling
raises recall by brute force (N× cost); retrieval raises the *per-sample* hit rate by
teaching the model what genuine, paid findings of the weakness class under review look
like — and, because disclosed reports are real resolved bugs, it also sharpens
precision (the model calibrates to what actually gets accepted, not what looks scary).

Given a bounded task, this picks the most relevant disclosed reports for that agent
kind + language and formats them into a compact exemplar block appended to the
generator prompt. Pure scoring so retrieval is deterministic and testable; degrades to
"no exemplars" when the corpus is empty or missing.
"""

from __future__ import annotations

import os
from pathlib import Path

from .agents.contracts import AgentKind

#: Which weakness families each specialized agent should learn from. Keyed to the
#: CWE ids and name fragments that appear in disclosed reports.
_KIND_SIGNATURES: dict[AgentKind, tuple[str, ...]] = {
    AgentKind.AUTHENTICATION: ("cwe-287", "cwe-306", "cwe-384", "cwe-521", "cwe-613",
                               "auth", "login", "session", "jwt", "mfa", "2fa"),
    AgentKind.AUTHORIZATION: ("cwe-639", "cwe-285", "cwe-863", "cwe-862", "cwe-732",
                              "idor", "bola", "bfla", "authoriz", "access control",
                              "privilege", "tenant", "ownership"),
    AgentKind.INJECTION: ("cwe-89", "cwe-78", "cwe-79", "cwe-94", "cwe-943", "cwe-611",
                          "cwe-74", "inject", "sqli", "xss", "rce", "command", "template"),
    AgentKind.SSRF_PARSERS: ("cwe-918", "cwe-22", "cwe-98", "ssrf", "traversal",
                             "path", "redirect", "parser", "deserial"),
    AgentKind.SECRETS_CRYPTO: ("cwe-798", "cwe-327", "cwe-330", "cwe-522", "cwe-347",
                               "secret", "crypto", "signature", "random", "token", "key"),
    AgentKind.SUPPLY_CHAIN: ("cwe-1104", "cwe-829", "dependency", "supply", "confusion"),
    AgentKind.BUSINESS_LOGIC: ("cwe-841", "cwe-840", "race", "logic", "replay", "nonce"),
    AgentKind.CLIENT_API: ("cwe-79", "cwe-352", "xss", "csrf", "cors", "prototype"),
    AgentKind.SMART_CONTRACT: ("reentran", "cwe-841", "overflow", "underflow", "access control",
                               "access-control", "signature", "replay", "oracle", "rounding",
                               "precision", "liquidation", "slippage", "mev", "accounting",
                               "inflation", "flashloan", "initialization", "dos", "withdrawal",
                               "redeem", "smart contract", "solidity"),
}

_EXT_LANG = {
    ".go": "go", ".py": "python", ".rb": "ruby", ".php": "php", ".js": "javascript",
    ".ts": "typescript", ".java": "java", ".rs": "rust", ".sol": "solidity", ".cs": "c#",
}


def _language(task) -> str:
    for source in task.source_slices:
        lang = _EXT_LANG.get(Path(source.path).suffix.lower())
        if lang:
            return lang
    return ""


def score_report(report, kind: AgentKind, language: str = "") -> float:
    """Relevance of a disclosed report to this agent kind + language (0 = irrelevant).

    Class match dominates (does the report's CWE/weakness belong to this kind?), then
    source-code relevance, then real-impact signals (bounty, severity), then language."""
    signatures = _KIND_SIGNATURES.get(kind, ())
    haystack = " ".join([
        report.cwe or "", report.weakness or "", report.title or "",
        " ".join(report.tags or []),
    ]).lower()
    class_hits = sum(1 for sig in signatures if sig in haystack)
    if class_hits == 0:
        return 0.0                                    # wrong weakness class -> skip
    score = 3.0 * min(class_hits, 3)
    if (report.asset_type or "").lower() in ("source_code", "source code"):
        score += 2.0                                  # code bugs teach code review best
    sev = str(getattr(report.severity, "value", report.severity) or "").lower()
    score += {"critical": 2.0, "high": 1.5, "medium": 0.75}.get(sev, 0.0)
    if report.bounty:
        score += min(1.5, (report.bounty / 5000.0))   # real money = real, impactful bug
    if language and language in haystack:
        score += 1.0
    return round(score, 3)


class KnowledgeRetriever:
    """Rank a disclosed-report corpus for a task and format few-shot exemplars."""

    def __init__(self, corpus, *, max_exemplars: int = 3) -> None:
        self._reports = list(corpus) if corpus is not None else []
        self._max = max(1, max_exemplars)

    def __bool__(self) -> bool:
        return bool(self._reports)

    def retrieve(self, task, *, k: int | None = None) -> list:
        language = _language(task)
        scored = [(score_report(r, task.kind, language), r) for r in self._reports]
        scored = [(s, r) for s, r in scored if s > 0]
        # highest score first; report_id as a stable tiebreak for determinism
        scored.sort(key=lambda sr: (-sr[0], getattr(sr[1], "report_id", "")))
        return [r for _, r in scored[: (k or self._max)]]

    def exemplar_text(self, reports: list) -> str:
        if not reports:
            return ""
        lines = [
            "\n## Real disclosed vulnerabilities of this class (for calibration)",
            "These are genuine, resolved bug-bounty findings similar to what you are "
            "reviewing. Use them to recognise the real, exploitable shape of this "
            "weakness — and the bar that got them accepted. Do not copy them; find the "
            "analogous flaw if it exists in the supplied code, and report nothing if it "
            "does not.",
        ]
        for report in reports:
            sev = str(getattr(report.severity, "value", report.severity) or "n/a")
            cwe = report.cwe or report.weakness or "?"
            title = (report.title or report.summary or "").strip()[:160]
            bounty = f", ${int(report.bounty)}" if report.bounty else ""
            lines.append(f"- [{cwe}, {sev}{bounty}] {title}")
        return "\n".join(lines)

    def augment(self, task) -> str:
        """Positive exemplars (real disclosed bugs of the class) plus negative exemplars
        (the shapes that get rejected) — teaching recall and precision together."""
        from .negative_examples import negative_examples_text
        return self.exemplar_text(self.retrieve(task)) + negative_examples_text()


def load_default_corpus():
    """Load the corpus at ``AEGIS_KNOWLEDGE_CORPUS`` (a .jsonl), or None if unset/absent."""
    path = os.environ.get("AEGIS_KNOWLEDGE_CORPUS", "").strip()
    if not path or not Path(path).is_file():
        return None
    try:
        from aegis.knowledge.corpus import ReportCorpus
        return ReportCorpus.from_jsonl(path)
    except Exception:
        return None
