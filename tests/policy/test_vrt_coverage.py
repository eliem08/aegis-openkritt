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


# --- leaf-level routing: coarse source-web categories split correctly ---------

def test_security_headers_leaf_is_live_not_source():
    # Filed under Server Security Misconfiguration (source_web) but only confirmable live.
    c = classify("Server Security Misconfiguration", "Lack of Security Headers")
    assert c.lane is HuntLane.LIVE_ONLY and c.pursuable


def test_ssl_and_dns_leaves_are_live():
    assert classify("Server Security Misconfiguration", "Insecure SSL").lane is HuntLane.LIVE_ONLY
    assert classify("Server Security Misconfiguration", "Misconfigured DNS").lane is HuntLane.LIVE_ONLY


def test_mail_spoofing_leaf_is_live():
    c = classify("Server Security Misconfiguration", "Mail Server Misconfiguration")
    assert c.lane is HuntLane.LIVE_ONLY


def test_ssrf_still_source_web_regression():
    # SSRF sink is source-reviewable — the source-web override must still win.
    c = classify("Server Security Misconfiguration", "Server-Side Request Forgery (SSRF)")
    assert c.lane is HuntLane.SOURCE_WEB and c.pursuable


def test_hardcoded_password_is_source_despite_firmware_category():
    c = classify("Insecure OS/Firmware", "Hardcoded Password")
    assert c.lane is HuntLane.SOURCE_WEB and c.pursuable


def test_ai_model_extraction_is_live_not_source():
    # AI Application Security is source_web by default, but model extraction needs a live model.
    c = classify("AI Application Security", "Model Extraction")
    assert c.lane is HuntLane.LIVE_ONLY and c.pursuable


def test_side_channel_power_is_out_of_boundary():
    # Cryptographic Weakness is source_web, but power analysis needs hardware.
    c = classify("Cryptographic Weakness", "Side-Channel Attack Power Analysis Attack")
    assert c.lane is HuntLane.OUT_OF_BOUNDARY and not c.pursuable


def test_timing_side_channel_is_live():
    c = classify("Cryptographic Weakness", "Side-Channel Attack Timing Attack")
    assert c.lane is HuntLane.LIVE_ONLY and c.pursuable


def test_binary_planting_is_out_of_boundary():
    c = classify("Client-Side Injection", "Binary Planting Default Folder Privilege Escalation")
    assert c.lane is HuntLane.OUT_OF_BOUNDARY and not c.pursuable
