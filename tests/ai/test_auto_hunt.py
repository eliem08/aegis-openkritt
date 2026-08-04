"""Autonomous, EV-ranked hunt orchestration (hunt function injected — no network)."""

from __future__ import annotations

from aegis.ai.auto_hunt import (
    AutoHunter, AutoHuntConfig, HuntOutcome, HuntTarget, expected_value, rank_targets,
)


def _t(repo, findability=0.5, reward=1000.0, handle="h"):
    return HuntTarget(repository=repo, handle=handle, reward_ceiling=reward, findability=findability)


def test_expected_value_scales_with_findability_and_reward():
    cfg = AutoHuntConfig()
    soft_rich = _t("a", findability=0.9, reward=5000)
    hard_poor = _t("b", findability=0.2, reward=200)
    assert expected_value(soft_rich, cfg) > expected_value(hard_poor, cfg)
    assert expected_value(_t("z", findability=0, reward=9999), cfg) == 0.0


def test_rank_is_ev_desc_and_drops_below_min_ev():
    cfg = AutoHuntConfig(min_ev=50)
    targets = [_t("low", 0.1, 300), _t("high", 0.9, 5000), _t("mid", 0.5, 1000)]
    ranked = rank_targets(targets, cfg)
    repos = [t.repository for t, _ in ranked]
    assert repos[0] == "high"                              # best EV first
    assert "low" not in repos                              # below min_ev dropped


def test_hunter_hunts_top_targets_within_budget():
    hunted = []
    def hunt_fn(target, samples):
        hunted.append(target.repository)
        return HuntOutcome(target=target, confirmed=1 if target.repository == "high" else 0)
    targets = [_t("high", 0.9, 5000), _t("mid", 0.5, 1000), _t("low", 0.3, 400)]
    session = AutoHunter(hunt_fn, config=AutoHuntConfig(max_targets=2)).run(targets)
    assert hunted == ["high", "mid"]                       # only top-2 by EV, in order
    assert session.confirmed_total == 1
    assert session.status == "completed"


def test_hunter_isolates_a_failing_target():
    def hunt_fn(target, samples):
        if target.repository == "boom":
            raise RuntimeError("clone failed")
        return HuntOutcome(target=target, confirmed=2)
    targets = [_t("boom", 0.9, 5000), _t("good", 0.8, 4000)]
    session = AutoHunter(hunt_fn, config=AutoHuntConfig(max_targets=2)).run(targets)
    assert session.confirmed_total == 2                    # good target still ran
    errored = [o for o in session.outcomes if o.error]
    assert errored and "clone failed" in errored[0].error


def test_events_are_emitted_for_progress():
    events = []
    def hunt_fn(target, samples):
        return HuntOutcome(target=target, confirmed=0)
    AutoHunter(hunt_fn, config=AutoHuntConfig(max_targets=1),
               on_event=lambda kind, data: events.append(kind)).run([_t("a")])
    assert events[0] == "ranked" and "hunt_start" in events and events[-1] == "completed"


def test_session_summary_shape():
    def hunt_fn(target, samples):
        return HuntOutcome(target=target, confirmed=1, poc_dir="reports/poc/a",
                           findings=[{"cwe": "CWE-287", "location": "a.php:10"}])
    session = AutoHunter(hunt_fn, config=AutoHuntConfig(max_targets=1)).run([_t("a", 0.9, 5000)])
    s = session.summary()
    assert s["confirmed_total"] == 1 and s["targets_hunted"] == 1
    assert s["results"][0]["findings"][0]["cwe"] == "CWE-287"
    assert s["ranked"][0]["ev"] > 0


def test_build_targets_from_ranking(tmp_path):
    import json
    from aegis.ai.auto_hunt_run import build_targets_from_ranking
    p = tmp_path / "rank.json"
    p.write_text(json.dumps([
        {"repository": "owncloud/core", "handle": "owncloud", "reward_ceiling": 5000,
         "findability": 0.76, "subpath": "apps/dav"},
        {"repository": "0xABC", "kind": "contract", "reward_ceiling": 10000},
        {"bad": "row"},                                    # dropped (no repository)
    ]), encoding="utf-8")
    targets = build_targets_from_ranking(p)
    assert len(targets) == 2
    assert targets[0].repository == "owncloud/core" and targets[0].reward_ceiling == 5000
    assert targets[1].kind == "contract"


def test_make_hunt_fn_is_importable():
    # the production wiring imports cleanly (it wires clone/hunt/validate/poc lazily)
    from aegis.ai.auto_hunt_run import make_hunt_fn
    assert callable(make_hunt_fn(report_root="reports"))
