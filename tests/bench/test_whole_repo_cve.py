from aegis.bench.real_cve import RealCaseResult, ScanObservation
from aegis.bench.whole_repo_cve import WholeRepositoryResult


def test_whole_repository_metric_is_separate_and_counts_miss_classes():
    result = WholeRepositoryResult((
        RealCaseResult("hit", "detected"),
        RealCaseResult("detector", "detector_missed"),
        RealCaseResult("discovery", "discovery_missed"),
        RealCaseResult("unavailable", "unavailable"),
    ))
    summary = result.summary()
    assert summary["metric"] == "whole_repository_discovery_recall"
    assert summary["whole_repository_discovery_recall"] == 0.3333
    assert summary["detector_misses"] == 1
    assert summary["discovery_misses"] == 1
    assert summary["scored"] == 3


def test_scan_observation_retains_raw_detector_hits_separately():
    observation = ScanObservation(
        detectors=[], attempted=["semgrep"], raw_detectors=["semgrep"],
    )
    assert observation.any_ran
    assert not observation.detectors and observation.raw_detectors == ["semgrep"]
