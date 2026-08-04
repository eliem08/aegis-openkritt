"""Retrieval-augmented detection."""

from __future__ import annotations

from aegis.ai.agents.contracts import AgentKind, AgentTask, SourceSlice
from aegis.ai.knowledge_retrieval import KnowledgeRetriever, score_report


class _Report:
    """Minimal disclosed-report stand-in matching the fields the retriever reads."""
    def __init__(self, report_id, cwe="", weakness="", title="", severity="none",
                 asset_type="", bounty=None, tags=None):
        self.report_id = report_id
        self.cwe = cwe
        self.weakness = weakness
        self.title = title
        self.severity = severity
        self.asset_type = asset_type
        self.bounty = bounty
        self.tags = tags or []
        self.summary = title


def _task(kind, path="app/api.php"):
    return AgentTask(kind=kind, target="x",
                     source_slices=[SourceSlice(path=path, content="x")])


def test_score_requires_class_match():
    idor = _Report("1", cwe="CWE-639", asset_type="source_code")
    assert score_report(idor, AgentKind.AUTHORIZATION) > 0
    assert score_report(idor, AgentKind.SECRETS_CRYPTO) == 0.0     # wrong class -> 0


def test_score_rewards_code_bounty_and_severity():
    weak = _Report("1", cwe="CWE-639")
    strong = _Report("2", cwe="CWE-639", asset_type="source_code",
                     severity="critical", bounty=5000)
    assert score_report(strong, AgentKind.AUTHORIZATION) > score_report(weak, AgentKind.AUTHORIZATION)


def test_retrieve_picks_relevant_class_and_is_deterministic():
    corpus = [
        _Report("idor-1", cwe="CWE-639", title="IDOR in invoice API",
                asset_type="source_code", severity="high", bounty=2000),
        _Report("sqli-1", cwe="CWE-89", title="SQLi in search", severity="high"),
        _Report("idor-2", cwe="CWE-639", title="BOLA on user endpoint",
                asset_type="source_code", severity="critical", bounty=4000),
        _Report("xss-1", cwe="CWE-79", title="stored XSS"),
    ]
    r = KnowledgeRetriever(corpus, max_exemplars=2)
    got = r.retrieve(_task(AgentKind.AUTHORIZATION))
    ids = [x.report_id for x in got]
    assert ids == ["idor-2", "idor-1"]                             # authz class, best first
    assert r.retrieve(_task(AgentKind.AUTHORIZATION)) == got       # deterministic


def test_exemplar_text_is_compact_and_labelled():
    corpus = [_Report("1", cwe="CWE-918", title="SSRF via image proxy",
                      asset_type="source_code", severity="high", bounty=3000)]
    r = KnowledgeRetriever(corpus)
    text = r.augment(_task(AgentKind.SSRF_PARSERS))
    assert "disclosed vulnerabilities of this class" in text
    assert "CWE-918" in text and "SSRF via image proxy" in text and "$3000" in text
    assert "Do not copy them" in text                              # anti-copy guard


def test_empty_or_irrelevant_corpus_yields_no_exemplars():
    assert not KnowledgeRetriever([])
    assert KnowledgeRetriever([]).augment(_task(AgentKind.INJECTION)) == ""
    only_xss = KnowledgeRetriever([_Report("1", cwe="CWE-79")])
    assert only_xss.augment(_task(AgentKind.SECRETS_CRYPTO)) == ""  # nothing relevant


def test_language_boosts_matching_reports():
    php = _Report("php", cwe="CWE-89", title="SQL injection php search")
    generic = _Report("gen", cwe="CWE-89", title="SQL injection")
    task = _task(AgentKind.INJECTION, path="src/Api.php")
    assert score_report(php, AgentKind.INJECTION, "php") > score_report(generic, AgentKind.INJECTION, "php")
