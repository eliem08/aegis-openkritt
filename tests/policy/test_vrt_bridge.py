"""Tests for the VRT -> weakness-family hunt bridge."""

from __future__ import annotations

from aegis.ai.jarvis.vrt_bridge import (
    _BY_ID,
    _CATEGORY_FAMILIES,
    _SPECIFIC_FAMILY,
    families_for_vrt,
    hunt_plan_for_vrt,
)
from aegis.policy.vrt_coverage import HuntLane


def test_idor_maps_to_authz_family_source_web():
    p = hunt_plan_for_vrt("Broken Access Control (BAC)", "Insecure Direct Object References (IDOR)")
    assert p.lane is HuntLane.SOURCE_WEB and p.pursuable
    assert "authz" in p.family_ids


def test_sql_injection_maps_to_injection():
    assert "injection" in hunt_plan_for_vrt("Server-Side Injection", "SQL Injection").family_ids


def test_command_injection_specific_wins_and_is_source():
    p = hunt_plan_for_vrt("Insecure OS/Firmware", "Command Injection")
    assert p.lane is HuntLane.SOURCE_WEB
    assert p.family_ids == ("injection",)


def test_ssrf_specific_maps_to_ssrf():
    assert "ssrf" in hunt_plan_for_vrt("Server Security Misconfiguration",
                                       "Server-Side Request Forgery (SSRF)").family_ids


def test_smart_contract_is_crypto_lane_with_pipeline_note():
    p = hunt_plan_for_vrt("Smart Contract Misconfiguration", "Reentrancy Attack")
    assert p.lane is HuntLane.SOURCE_CRYPTO and p.pursuable
    assert p.families == ()
    assert "pipeline" in p.note.lower()


def test_dos_off_has_no_families():
    p = hunt_plan_for_vrt("Application-Level Denial-of-Service (DoS)", "Critical Impact and/or Easy Difficulty")
    assert p.lane is HuntLane.CATEGORICALLY_OFF and not p.pursuable
    assert p.families == ()


def test_out_of_boundary_no_families():
    p = hunt_plan_for_vrt("Automotive Security Misconfiguration", "RF Hub")
    assert not p.pursuable and p.families == ()


def test_every_mapped_family_id_exists_in_catalog():
    ids = set()
    for fam_ids in _CATEGORY_FAMILIES.values():
        ids.update(fam_ids)
    ids.update(fid for _, fid in _SPECIFIC_FAMILY)
    unknown = ids - set(_BY_ID)
    assert not unknown, f"bridge references non-existent family ids: {unknown}"


def test_families_for_vrt_dedups():
    fams = families_for_vrt("Server Security Misconfiguration")
    assert len(fams) == len({f.family_id for f in fams})
