"""Supply-chain policy (Phase 5): SBOM, image pinning, severity gate."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from aegis.supply import (
    Component,
    PolicyException,
    Severity,
    SeverityPolicy,
    UnpinnedImage,
    Vulnerability,
    generate_sbom,
    verify_image_pin,
)

NOW = datetime(2026, 8, 2, tzinfo=timezone.utc)
DIGEST = "a" * 64


# --- SBOM + license notices --------------------------------------------------

def test_sbom_retains_license_notices():
    sbom = generate_sbom([
        Component("nuclei", "3.3.0", license="MIT", distributed=True),
        Component("cryptography", "43.0", license="Apache-2.0"),
    ])
    notices = {n["name"]: n["license"] for n in sbom.notices()}
    assert notices == {"nuclei": "MIT", "cryptography": "Apache-2.0"}


def test_copyleft_in_the_distributed_set_is_surfaced():
    sbom = generate_sbom([
        Component("nuclei", "3.3.0", license="MIT", distributed=True),
        Component("some-gpl-tool", "1.0", license="GPL-3.0", distributed=True),
    ])
    flagged = [c.name for c in sbom.copyleft_in_distribution()]
    assert flagged == ["some-gpl-tool"]                # clean-room design ships none of these


# --- image pinning -----------------------------------------------------------

def test_digest_pinned_image_is_accepted():
    assert verify_image_pin(f"registry/aegis/nuclei@sha256:{DIGEST}") == DIGEST


@pytest.mark.parametrize("ref", [
    "registry/aegis/nuclei:latest",
    "registry/aegis/nuclei:3.3.0",
    "registry/aegis/nuclei@sha256:short",
])
def test_floating_or_invalid_image_is_rejected(ref):
    with pytest.raises(UnpinnedImage):
        verify_image_pin(ref)


# --- severity gate -----------------------------------------------------------

def policy():
    return SeverityPolicy(max_allowed=Severity.MEDIUM)


def test_release_blocked_by_a_high_severity_vulnerability():
    result = policy().evaluate([Vulnerability("CVE-1", "openssl", Severity.HIGH)])
    assert result.blocked and result.blocking[0].vuln_id == "CVE-1"


def test_below_policy_vulnerabilities_do_not_block():
    result = policy().evaluate([
        Vulnerability("CVE-2", "x", Severity.LOW), Vulnerability("CVE-3", "y", Severity.MEDIUM)])
    assert not result.blocked


def test_time_limited_exception_unblocks_a_specific_vulnerability():
    vulns = [Vulnerability("CVE-9", "libz", Severity.CRITICAL)]
    exc = PolicyException("CVE-9", "vendor fix ETA 2 weeks", "op", NOW + timedelta(days=14))
    result = policy().evaluate(vulns, [exc], now=NOW)
    assert not result.blocked and result.exempted[0].vuln_id == "CVE-9"


def test_expired_exception_does_not_unblock():
    vulns = [Vulnerability("CVE-9", "libz", Severity.CRITICAL)]
    exc = PolicyException("CVE-9", "stale", "op", NOW - timedelta(days=1))
    result = policy().evaluate(vulns, [exc], now=NOW)
    assert result.blocked                              # expired exception is ignored


def test_exception_only_applies_to_its_own_vulnerability():
    vulns = [Vulnerability("CVE-A", "a", Severity.CRITICAL),
             Vulnerability("CVE-B", "b", Severity.HIGH)]
    exc = PolicyException("CVE-A", "approved", "op", NOW + timedelta(days=1))
    result = policy().evaluate(vulns, [exc], now=NOW)
    assert result.blocked and [v.vuln_id for v in result.blocking] == ["CVE-B"]
