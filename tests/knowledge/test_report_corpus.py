import pytest

from aegis.knowledge import DisclosedReport, ReportCorpus, Severity, normalize_cwe


@pytest.mark.parametrize(
    "raw,expected",
    [("CWE-79", "CWE-79"), ("cwe_639", "CWE-639"), ("79", "CWE-79"), (200, "CWE-200"), ("nope", ""), (None, "")],
)
def test_normalize_cwe(raw, expected):
    assert normalize_cwe(raw) == expected


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("high", Severity.HIGH),
        ("Critical", Severity.CRITICAL),
        ("info", Severity.NONE),
        ("", Severity.NONE),
        (9.5, Severity.CRITICAL),
        (5.0, Severity.MEDIUM),
    ],
)
def test_severity_parse(raw, expected):
    assert Severity.parse(raw) == expected


def test_report_normalizes_fields():
    r = DisclosedReport(report_id="1", cwe="cwe-639", severity="High", asset_type="URL")
    assert r.cwe == "CWE-639"
    assert r.severity == Severity.HIGH
    assert r.asset_type == "url"


def test_report_ignores_extra_keys():
    r = DisclosedReport(report_id="1", something_new="ignored")  # extra="ignore"
    assert r.report_id == "1"


def test_weakness_key_prefers_cwe():
    assert DisclosedReport(report_id="1", cwe="CWE-79", weakness="XSS").weakness_key == "CWE-79"
    assert DisclosedReport(report_id="2", weakness="Weird Bug").weakness_key == "weird bug"


def test_corpus_filter(corpus):
    assert len(corpus.filter(cwe="CWE-639")) == 3
    assert len(corpus.filter(asset_type="android")) == 1
    assert len(corpus.filter(min_severity=Severity.CRITICAL)) == 1
    assert len(corpus.filter(program="initech")) == 1


def test_corpus_jsonl_roundtrip(tmp_path, corpus):
    path = tmp_path / "c.jsonl"
    corpus.to_jsonl(path)
    reloaded = ReportCorpus.from_jsonl(path)
    assert len(reloaded) == len(corpus)
    assert reloaded.filter(cwe="CWE-639")


def test_corpus_jsonl_skips_blank_and_comment_lines(tmp_path):
    path = tmp_path / "c.jsonl"
    path.write_text(
        '# comment\n\n{"report_id":"1","cwe":"CWE-79"}\n', encoding="utf-8"
    )
    assert len(ReportCorpus.from_jsonl(path)) == 1


def test_corpus_jsonl_reports_bad_line(tmp_path):
    path = tmp_path / "c.jsonl"
    path.write_text('{"report_id":"1"}\n{not json}\n', encoding="utf-8")
    with pytest.raises(ValueError, match="line 2"):
        ReportCorpus.from_jsonl(path)
