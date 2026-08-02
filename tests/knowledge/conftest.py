import pytest

from aegis.knowledge import CorpusInsights, DisclosedReport, ReportCorpus


def _r(rid, cwe, weakness, asset_type="url", program="acme", severity="high", bounty=1000):
    return DisclosedReport(
        report_id=rid, program=program, cwe=cwe, weakness=weakness,
        asset_type=asset_type, severity=severity, bounty=bounty,
    )


@pytest.fixture
def corpus() -> ReportCorpus:
    return ReportCorpus(
        [
            _r("1", "CWE-639", "IDOR", bounty=2000),
            _r("2", "CWE-639", "IDOR", bounty=3000),
            _r("3", "CWE-639", "IDOR", bounty=2500),
            _r("4", "CWE-79", "XSS", severity="medium", bounty=500),
            _r("5", "CWE-918", "SSRF", severity="critical", bounty=5000),
            _r("6", "CWE-798", "Hardcoded creds", asset_type="android", program="initech", bounty=800),
        ]
    )


@pytest.fixture
def insights(corpus) -> CorpusInsights:
    return CorpusInsights(corpus)
