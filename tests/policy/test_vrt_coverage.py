"""Tests for the VRT coverage map — lane routing + categorical-off safety rules."""

from __future__ import annotations

from aegis.policy.vrt_coverage import HuntLane, classify, pursuable_now


def test_access_control_is_source_web():
    c = classify("Broken Access Control (BAC)", "Insecure Direct Object References (IDOR)")
    assert c.lane is HuntLane.SOURCE_WEB and c.pursuable


def test_server_side_injection_rce_is_source_web():
    assert classify("Server-Side Injection", "Remote Code Execution (RCE)").lane is HuntLane.SOURCE_WEB


def test_smart_contract_is_crypto_lane():
    c = classify("Smart Contract Misconfiguration", "Reentrancy Attack")
    assert c.lane is HuntLane.SOURCE_CRYPTO and c.pursuable


def test_dos_is_categorically_off():
    c = classify("Application-Level Denial-of-Service (DoS)", "Critical Impact and/or Easy Difficulty")
    assert c.lane is HuntLane.CATEGORICALLY_OFF and not c.pursuable


def test_dos_specific_overrides_friendly_category():
    # DoS under AI Application Security (a SOURCE_WEB category) must still be OFF.
    c = classify("AI Application Security", "Denial-of-Service (DoS)")
    assert c.lane is HuntLane.CATEGORICALLY_OFF and not c.pursuable


def test_captcha_bypass_is_off_even_under_web_category():
    c = classify("Server Security Misconfiguration", "CAPTCHA")
    assert c.lane is HuntLane.CATEGORICALLY_OFF


def test_command_injection_is_source_despite_firmware_category():
    # Command Injection is filed under Insecure OS/Firmware (OUT_OF_BOUNDARY) but is source-reviewable.
    c = classify("Insecure OS/Firmware", "Command Injection")
    assert c.lane is HuntLane.SOURCE_WEB and c.pursuable


def test_automotive_and_ad_out_of_boundary():
    assert not pursuable_now("Automotive Security Misconfiguration", "RF Hub")
    assert not pursuable_now("Active Directory (AD)", "Kerberos Abuse")


def test_cloud_is_live_only_but_pursuable_via_gate():
    c = classify("Cloud Security", "Identity and Access Management (IAM) Misconfigurations")
    assert c.lane is HuntLane.LIVE_ONLY and c.pursuable


def test_unknown_category_fails_to_governed_live_lane():
    c = classify("Some Brand New Category", "whatever")
    assert c.lane is HuntLane.LIVE_ONLY and c.pursuable
    assert "unknown" in c.reason
