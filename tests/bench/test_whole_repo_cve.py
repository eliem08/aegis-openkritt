from aegis.bench.real_cve import RealCaseResult, ScanObservation, _matching_survivors
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
    assert summary["unavailable"] == 1
    assert summary["invalid"] == 0
    assert summary["scored"] == 3


def test_scan_observation_retains_raw_detector_hits_separately():
    observation = ScanObservation(
        detectors=[], attempted=["semgrep"], raw_detectors=["semgrep"],
    )
    assert observation.any_ran
    assert not observation.detectors and observation.raw_detectors == ["semgrep"]


def test_raw_detector_classification_accepts_normalized_finding_dicts(monkeypatch):
    class Bridge:
        def __init__(self, *args, **kwargs):
            pass

        def scan(self, *_args, **_kwargs):
            return [type("Result", (), {"ran": True, "tool": "semgrep", "error": ""})()]

        def findings(self, _results):
            return [{
                "source": "aegis:tool:semgrep", "metadata": {"cwe": "CWE-79", "rule_id": "xss"},
                "json_answer": {"file_path": "src/app.py", "summary": "CWE-79 xss"},
                "severity": "high", "confidence": 0.9,
            }]

    monkeypatch.setattr("aegis.ai.tool_bridge.ToolBridge", Bridge)
    monkeypatch.setattr("aegis.ai.tool_bridge.available_tools", lambda _lane: [
        type("Tool", (), {"name": "semgrep"})()
    ])
    case = type("Case", (), {
        "required_tools": ("semgrep",), "path_hint": "src/app.py",
        "expected": lambda self: "cwe-79",
    })()
    observed = _matching_survivors(".", case, narrow_to_advisory_path=False)
    assert observed.raw_detectors == ["semgrep"]
