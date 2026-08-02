"""OAST-backed SSRF detection (report-corpus driven).

A vulnerable URL parameter makes the server fetch our private-OAST callback; the
matched interaction confirms blind SSRF. A non-vulnerable parameter produces no
interaction and no finding.
"""

from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from urllib.parse import urlsplit

from aegis.active import candidate_ssrf_params, run_ssrf_probes
from aegis.api.crypto import FernetEncryptor, generate_key
from aegis.oast import Interaction, PrivateOastConfig, PrivateOastService

NOW = datetime(2026, 8, 3, tzinfo=timezone.utc)


def principal(tenant="tenant-a"):
    return SimpleNamespace(tenant_id=tenant, name="agent")


def oast_service():
    return PrivateOastService(
        PrivateOastConfig(oast_domain="oast.aegis.internal", is_production=True),
        encryptor=FernetEncryptor(generate_key()), clock=lambda: NOW)


class FakeTarget:
    """Fetches the callback only when the *vulnerable* parameter is set."""

    def __init__(self, oast, vulnerable_param):
        self.oast = oast
        self.vuln = vulnerable_param
        self.sent = []

    def probe(self, name, value):
        self.sent.append((name, value))
        if name == self.vuln and "//" in value:
            host = urlsplit(value).hostname       # the planted probe address
            # Fetching the callback first resolves its host -> a DNS interaction
            # (the canonical, always-fires OAST-SSRF signal).
            self.oast.ingest(Interaction(protocol="dns", host=host,
                                         remote_address="10.0.0.9", raw="A? probe",
                                         observed_at=NOW))
        return SimpleNamespace(status_code=200)


# --- parameter filtering -----------------------------------------------------

def test_candidate_params_selects_url_like_names():
    picked = candidate_ssrf_params(["q", "page", "callback", "image_url", "id", "webhook"])
    assert set(picked) == {"callback", "image_url", "webhook"}
    assert "q" not in picked and "id" not in picked


# --- detection ---------------------------------------------------------------

def test_vulnerable_parameter_is_confirmed_via_oast():
    oast = oast_service()
    reg = oast.register(principal(), engagement_id="e", scan_id="s", reservation_id="r")
    target = FakeTarget(oast, vulnerable_param="webhook")

    findings = run_ssrf_probes(
        params=["callback", "webhook", "image"], route="/api/import",
        probe=target.probe, oast=oast, session_ref=reg.session_ref, principal=principal())

    assert len(findings) == 1
    f = findings[0]
    assert f.parameter == "webhook" and f.protocol == "dns"
    assert f.probe_address.endswith("oast.aegis.internal")


def test_non_vulnerable_target_yields_no_findings():
    oast = oast_service()
    reg = oast.register(principal(), engagement_id="e", scan_id="s", reservation_id="r")
    target = FakeTarget(oast, vulnerable_param="__none__")   # never fetches

    findings = run_ssrf_probes(
        params=["callback", "webhook"], route="/api/import",
        probe=target.probe, oast=oast, session_ref=reg.session_ref, principal=principal())
    assert findings == []


def test_callback_targets_our_private_oast_not_the_target():
    oast = oast_service()
    reg = oast.register(principal(), engagement_id="e", scan_id="s", reservation_id="r")
    target = FakeTarget(oast, vulnerable_param="url")
    run_ssrf_probes(params=["url"], route="/x", probe=target.probe,
                    oast=oast, session_ref=reg.session_ref, principal=principal())
    # every value we planted points at our OAST domain — never an arbitrary host
    assert all("oast.aegis.internal" in value for _name, value in target.sent)


def test_each_parameter_gets_a_distinct_probe():
    oast = oast_service()
    reg = oast.register(principal(), engagement_id="e", scan_id="s", reservation_id="r")
    target = FakeTarget(oast, vulnerable_param="__none__")
    run_ssrf_probes(params=["a", "b", "c"], route="/x", probe=target.probe,
                    oast=oast, session_ref=reg.session_ref, principal=principal())
    addresses = {value for _n, value in target.sent}
    assert len(addresses) == 3                    # unique callback per parameter
