"""Audit-saturation target ranking."""

from __future__ import annotations

from aegis.hunt.saturation import TargetSignals, findability, rank_targets


def test_advisory_heavy_repo_scores_lower_than_unmined():
    mined = TargetSignals("big/famous", stars=90000, advisories=40, pushed_days_ago=1)
    fresh = TargetSignals("small/quiet", stars=8, advisories=0, pushed_days_ago=10)
    assert findability(fresh) > findability(mined)


def test_audit_history_dominates_attention():
    # a low-star repo with many advisories is still harder than a high-star repo with none
    audited_small = TargetSignals("a/audited", stars=20, advisories=30, pushed_days_ago=5)
    starred_clean = TargetSignals("b/starred", stars=20000, advisories=0, pushed_days_ago=5)
    assert findability(starred_clean) > findability(audited_small)


def test_recency_breaks_ties_toward_active_code():
    active = TargetSignals("x/active", stars=50, advisories=1, pushed_days_ago=5)
    stale = TargetSignals("x/stale", stars=50, advisories=1, pushed_days_ago=2000)
    assert findability(active) > findability(stale)


def test_scores_are_bounded_0_1():
    for s in [TargetSignals("z/z"), TargetSignals("m/m", stars=10**7, advisories=10**4),
              TargetSignals("s/s", stars=0, advisories=0, pushed_days_ago=0)]:
        assert 0.0 <= findability(s) <= 1.0


def test_rank_is_softest_first_and_deterministic():
    sigs = [
        TargetSignals("k8s/k8s", stars=100000, advisories=50, pushed_days_ago=1),
        TargetSignals("mid/mid", stars=300, advisories=2, pushed_days_ago=20),
        TargetSignals("soft/soft", stars=12, advisories=0, pushed_days_ago=15),
    ]
    ranked = rank_targets(sigs)
    assert [r[0] for r in ranked] == ["soft/soft", "mid/mid", "k8s/k8s"]
    assert rank_targets(sigs) == ranked                       # deterministic


def test_owncloud_shape_beats_giant_shape():
    # the session's real signal: owncloud-shaped (mid, some history) should rank above
    # a Circle/k8s-shaped giant when we're choosing where to spend effort
    owncloud_like = TargetSignals("owncloud/core", stars=8500, advisories=6, pushed_days_ago=10)
    giant_like = TargetSignals("kubernetes/kubernetes", stars=100000, advisories=60, pushed_days_ago=1)
    assert findability(owncloud_like) > findability(giant_like)
