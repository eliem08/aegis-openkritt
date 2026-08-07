"""OAST-backed SSRF detection (Phase 3/4 — report-corpus driven).

Server-side request forgery is all over the corpus (SQL functions fetching cloud
metadata, data-source providers, webhook/URL params, DNS rebinding). The safe,
general way to confirm *blind* SSRF is out-of-band: plant a unique callback
address on our **private** OAST for one URL-accepting parameter, send the request,
and see whether an interaction arrives on that exact probe. Because the callback
is our own tenant-scoped OAST (never an attacker host or the target itself), there
is no untrusted egress, and the OAST only turns an interaction into evidence when
it matches an outstanding authorized probe.

Transport-agnostic: the caller supplies a ``probe(param, value)`` that issues the
request through the gateway. This detector only orchestrates the callbacks.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

# Parameter names that commonly carry a URL a server will fetch.
SSRF_PARAM_HINTS = (
    "url", "uri", "link", "callback", "webhook", "image", "img", "src", "target",
    "dest", "destination", "redirect", "redirect_uri", "feed", "endpoint", "host",
    "proxy", "fetch", "load", "source", "site", "domain", "address", "avatar",
    "logo", "document", "pdf", "import", "data", "xml", "next", "return", "continue",
)


@dataclass(frozen=True)
class SsrfFinding:
    parameter: str
    route: str
    probe_address: str
    protocol: str
    remote_address: str
    confidence: float = 0.9
    verified: bool = False        # an OAST match is strong, but the evidence
                                  # pipeline still finalizes it


def candidate_ssrf_params(param_names) -> list[str]:
    """Filter discovered parameters to those that plausibly accept a URL."""
    out = []
    for name in param_names:
        low = str(name).lower()
        if any(hint == low or hint in low for hint in SSRF_PARAM_HINTS):
            out.append(str(name))
    return out


def run_ssrf_probes(
    *, params, route: str, probe: Callable[[str, str], object], oast, session_ref: str,
    principal, scheme: str = "http",
) -> list[SsrfFinding]:
    """For each candidate parameter, plant an OAST probe, send it, and confirm.

    ``probe(param, value)`` issues the request with ``param=value`` (through the
    gateway). ``oast`` is a :class:`~aegis.oast.PrivateOastService`.
    """
    findings: list[SsrfFinding] = []
    for name in params:
        token = oast.plant_probe(session_ref, principal)
        callback = f"{scheme}://{token.address}/aegis-ssrf"
        probe(name, callback)                       # the target may fetch this
        # An interaction on this exact probe means the server made the request.
        for interaction in oast.poll(session_ref, principal):
            if interaction.host == token.address.lower():
                findings.append(SsrfFinding(
                    parameter=name, route=route, probe_address=token.address,
                    protocol=interaction.protocol, remote_address=interaction.remote_address))
                break
    return findings
