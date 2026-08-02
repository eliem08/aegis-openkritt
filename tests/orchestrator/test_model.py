from aegis.model import (
    Asset,
    AttackSurface,
    Candidate,
    Route,
    SSVCDecision,
    priority_score,
    ssvc_decision,
)


def test_surface_merge_dedups_hosts_and_routes():
    a = AttackSurface(assets=[Asset(host="api.example.test", routes=[Route(method="GET", path="/a")])])
    b = AttackSurface(
        assets=[
            Asset(host="api.example.test", routes=[Route(method="GET", path="/a"), Route(method="GET", path="/b")], technologies=["nginx"]),
            Asset(host="app.example.test"),
        ]
    )
    merged = a.merge(b)
    assert merged.hosts() == {"api.example.test", "app.example.test"}
    api = merged.get("api.example.test")
    assert {r.path for r in api.routes} == {"/a", "/b"}  # /a not duplicated
    assert api.technologies == ["nginx"]


def test_surface_merge_none_is_noop():
    a = AttackSurface(assets=[Asset(host="api.example.test")])
    assert a.merge(None).hosts() == {"api.example.test"}


def test_merge_does_not_mutate_original():
    a = AttackSurface(assets=[Asset(host="api.example.test")])
    a.merge(AttackSurface(assets=[Asset(host="app.example.test")]))
    assert a.hosts() == {"api.example.test"}  # original untouched


def test_evidence_reproducibility(make_evidence):
    assert make_evidence(reproducible=True).is_reproducible
    assert not make_evidence(reproducible=False).is_reproducible


def test_candidate_fingerprint_stability():
    c1 = Candidate(asset="API.example.test", route="/u", parameter="id", cwe="cwe-639")
    c2 = Candidate(asset="api.example.test", route="/u", parameter="id", cwe="CWE-639")
    assert c1.fingerprint() == c2.fingerprint()  # case-normalised


def test_priority_score():
    c = Candidate(
        asset="a",
        confidence=0.5,
        p_exploit=0.8,
        business_impact=0.5,
        asset_criticality=1.0,
        exposure_multiplier=1.0,
    )
    assert priority_score(c) == 0.8 * 0.5 * 1.0 * 1.0 * 0.5


def test_ssvc_thresholds():
    assert ssvc_decision(0.6) == SSVCDecision.ACT
    assert ssvc_decision(0.3) == SSVCDecision.ATTEND
    assert ssvc_decision(0.1) == SSVCDecision.TRACK
