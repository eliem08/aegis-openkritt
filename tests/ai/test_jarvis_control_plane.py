from __future__ import annotations

from aegis.ai.jarvis_control_plane import (
    AUTHORITIES,
    Responsibility,
    authority_for,
    source_review_guard_report,
    validate_authority_map,
)


def test_control_plane_has_one_owner_per_responsibility():
    validate_authority_map()
    responsibilities = [item.responsibility for item in AUTHORITIES]
    assert len(responsibilities) == len(set(responsibilities))
    assert authority_for(Responsibility.NETWORK_POLICY).module == "aegis.gateway"
    assert authority_for(Responsibility.MODEL_TRANSPORT).module == "aegis.model_gateway"
    assert authority_for(Responsibility.ENGAGEMENT_SCHEDULER).module == "aegis.scheduler"
    assert authority_for(Responsibility.FINDING_MISSION).module == \
        "aegis.ai.jarvis.mission_scheduler"


def test_source_review_keeps_target_network_layers_dormant():
    report = source_review_guard_report()
    assert "finding_lifecycle" in report["source_review_live"]
    assert "security_reasoning_graph" in report["source_review_live"]
    assert "network_policy" in report["target_network_dormant"]
    assert "active_detector_loop" in report["target_network_dormant"]
    assert len(report["tier3"]) >= 8
    assert all(not item["approved"] for item in report["tier3"])
    assert all("network" in item["reason"] for item in report["tier3"])
