"""The unified review console model: merge, rank, de-duplicate, source-label."""

from __future__ import annotations

from aegis.model import Candidate
from aegis.report import build_console


def _c(worker, cwe, *, asset="api.test", route="", conf=0.6, bi=0.6, impact="", verified=False):
    return Candidate(asset=asset, route=route, worker=worker, cwe=cwe, confidence=conf,
                     p_exploit=conf, business_impact=bi, impact=impact,
                     evidence_id="ev-1" if verified else None)


def test_merges_sources_and_labels_them():
    model = build_console([
        _c("analyzer:auth_posture", "CWE-306", route="/orders"),
        _c("analyzer:contract", "CWE-841", asset="Vault.sol", bi=0.95, impact="critical"),
        _c("integration:openkritt", "CWE-284", asset="Vault.sol", bi=0.8, impact="high"),
    ], scan_id="s1")
    assert model["scan_id"] == "s1"
    assert model["totals"]["candidates"] == 3
    assert set(model["sources"]) == {"aegis", "contract", "open-kritt"}
    assert model["totals"]["by_source"] == {"aegis": 1, "contract": 1, "open-kritt": 1}


def test_ranked_by_priority_descending():
    model = build_console([
        _c("analyzer:x", "CWE-1", conf=0.2, bi=0.2),
        _c("analyzer:contract", "CWE-841", asset="V.sol", conf=0.8, bi=0.95, impact="critical"),
    ])
    ranks = [it["rank"] for it in model["items"]]
    assert ranks == [1, 2]
    assert model["items"][0]["severity"] == "critical"      # highest priority first
    assert model["items"][0]["priority"] >= model["items"][1]["priority"]


def test_duplicates_collapse_by_fingerprint():
    dup_a = _c("integration:openkritt", "CWE-841", asset="Vault.sol", route="/w", conf=0.5)
    dup_b = _c("analyzer:contract", "CWE-841", asset="Vault.sol", route="/w", conf=0.7)
    model = build_console([dup_a, dup_b])
    assert model["totals"]["candidates"] == 1               # same asset/route/cwe family
    assert model["items"][0]["duplicate_count"] == 2


def test_status_reflects_verification():
    model = build_console([
        _c("analyzer:x", "CWE-1", verified=True),
        _c("integration:openkritt", "CWE-2", verified=False),
    ])
    assert model["totals"]["verified"] == 1 and model["totals"]["hypotheses"] == 1


def test_empty_is_well_formed():
    model = build_console([])
    assert model["items"] == [] and model["totals"]["candidates"] == 0
