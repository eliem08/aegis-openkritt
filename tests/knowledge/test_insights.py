from aegis.knowledge import CorpusInsights, ReportCorpus


def test_weakness_frequency_sorted(insights):
    stats = insights.weakness_frequency()
    assert stats[0].key == "CWE-639"  # most common
    assert stats[0].count == 3
    assert abs(stats[0].share - 0.5) < 1e-9  # 3 of 6


def test_avg_bounty(insights):
    idor = next(s for s in insights.weakness_frequency() if s.key == "CWE-639")
    assert idor.avg_bounty == (2000 + 3000 + 2500) / 3


def test_by_asset_type(insights):
    by = insights.by_asset_type()
    assert "url" in by and "android" in by
    assert by["url"][0].key == "CWE-639"


def test_priors_sum_to_one(insights):
    priors = insights.priors_for(asset_type="url")
    assert abs(sum(priors.values()) - 1.0) < 1e-9
    assert priors["CWE-639"] == 0.6  # 3 of 5 url reports


def test_priors_empty_for_unknown_subset(insights):
    assert insights.priors_for(asset_type="hardware") == {}


def test_base_rate(insights):
    assert insights.base_rate("CWE-639", asset_type="url") == 0.6
    assert insights.base_rate("CWE-000", asset_type="url") == 0.0


def test_empty_corpus_is_safe():
    ins = CorpusInsights(ReportCorpus())
    assert ins.weakness_frequency() == []
    assert ins.priors_for() == {}
    assert ins.base_rate("CWE-79") == 0.0
