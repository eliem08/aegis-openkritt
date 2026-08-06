"""Disclosed-report feed — Bugcrowd crowdstream mapping, filtering, estimates, store."""

from __future__ import annotations

from pathlib import Path

from aegis.ai import disclosed_reports as dr

_CROWD = {"results": [
    {"id": "1", "engagement_name": "Acme BBP", "engagement_code": "acme",
     "engagement_path": "/engagements/acme", "priority": 1, "amount": 5000,
     "crowdstream_amount_visible": True, "substate": "resolved", "target": "SQLi in /api",
     "submission_state_text": "Rewarded", "disclosed": "2026-08-05"},
    {"id": "2", "engagement_name": "Globex BBP", "engagement_code": "globex",
     "engagement_path": "/engagements/globex", "priority": 2, "amount": 0,
     "crowdstream_amount_visible": False, "substate": "unresolved", "target": "SSRF",
     "submission_state_text": "Accepted", "disclosed": "2026-08-05"},
    {"id": "3", "engagement_name": "State VDP", "engagement_code": "state-vdp",
     "priority": 3, "substate": "resolved", "target": "XSS"},               # VDP -> dropped
    {"id": "4", "engagement_name": "Noise Co", "engagement_code": "noise",
     "priority": 4, "substate": "not_applicable", "target": "junk"},        # N/A -> dropped
    {"id": "5", "engagement_name": "curl", "engagement_code": "curl",
     "priority": 5, "substate": "informational", "crowdstream_amount_visible": False,
     "target": "AI slop"},                                                  # curl slop -> dropped
]}


def _fake(url):
    return _CROWD if "crowdstream" in url else {}


def test_fetch_filters_vdp_and_noise():
    got = dr.fetch_bugcrowd(_fake)
    ids = {d.id for d in got}
    assert ids == {"bc:1", "bc:2"}                       # VDP, N/A, curl-slop all dropped


def test_visible_amount_kept_hidden_estimated():
    got = {d.id: d for d in dr.fetch_bugcrowd(_fake)}
    assert got["bc:1"].amount == 5000 and got["bc:1"].amount_estimated is False
    # hidden P2 -> estimated band
    assert got["bc:2"].amount == 2000 and got["bc:2"].amount_estimated is True


def test_severity_from_priority():
    got = {d.id: d for d in dr.fetch_bugcrowd(_fake)}
    assert got["bc:1"].severity == "critical" and got["bc:2"].severity == "high"


def test_basic_summary_present():
    got = dr.fetch_bugcrowd(_fake)
    assert all(d.summary for d in got)
    assert "est" in {d.id: d for d in got}["bc:2"].summary


def test_hackerone_degrades_empty():
    assert dr.fetch_hackerone(_fake) == []


def test_collect_dedupes_and_stores(tmp_path: Path):
    store = tmp_path / "disclosed_reports.json"
    s1 = dr.collect(store, fetch_json=_fake)
    assert s1["new"] == 2 and s1["platforms"] == ["bugcrowd"]
    s2 = dr.collect(store, fetch_json=_fake)               # same feed again
    assert s2["new"] == 0                                  # dedup by id
    rows = dr.load(tmp_path)
    assert len(rows) == 2


def test_llm_summary_used_when_client_given(tmp_path: Path):
    class _C:
        def complete_json(self, msgs, **k):
            return {"summary": "IDOR letting any user read others' invoices."}
    store = tmp_path / "disclosed_reports.json"
    dr.collect(store, fetch_json=_fake, client=_C())
    rows = dr.load(tmp_path)
    assert any("IDOR" in r.get("summary", "") for r in rows)


def test_llm_summary_degrades_on_error(tmp_path: Path):
    class _Bad:
        def complete_json(self, msgs, **k):
            raise RuntimeError("boom")
    store = tmp_path / "disclosed_reports.json"
    dr.collect(store, fetch_json=_fake, client=_Bad())     # must not crash
    assert len(dr.load(tmp_path)) == 2
