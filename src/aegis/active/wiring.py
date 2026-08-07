"""Stage-wiring for the clean-room active engines (Phase 3).

The parameter and route engines are transport-agnostic on purpose. This module
mounts them on a ``benign_request_mutation`` stage by routing every probe through
the :class:`~aegis.gateway.ScopedExecutionGateway` — so each request is scope-
checked, method-checked, DNS-pinned, and counted against the request budget
before it leaves — and turning their results into typed :class:`AdapterEvent`s
(``parameter`` / ``route``) that the normalizer folds into the asset graph.

A gateway block is not an error to paper over: for route enumeration a blocked
probe reads as an unhealthy host (which quarantines it); for parameter discovery
it stops the run with an incomplete diagnostic. Nothing here can widen the
capability the caller declared.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import urlencode, urlsplit

from aegis.adapters import EventKind, ExecutionEnvelope, event_from
from aegis.gateway import GatewayBlocked

from . import parameters as pmod
from . import routes as rmod

CAPABILITY = "benign_request_mutation"
PARAM_SOURCE = "param-discovery"
ROUTE_SOURCE = "route-discovery"


@dataclass
class TransportResponse:
    status: int
    headers: dict = field(default_factory=dict)
    body: str = ""
    redirect_location: str = ""


# A transport turns an authorized (method, url) into a response. Production wires
# it to the scope-enforcing httpx transport; tests pass a fake.
Transport = Callable[[str, str], TransportResponse]


class GatewayProbe:
    """Adapts an engine's probe callable to go through the gateway + transport."""

    def __init__(self, gateway, transport: Transport, *, base_url: str, method: str = "GET") -> None:
        self._gateway = gateway
        self._transport = transport
        self._base = base_url.rstrip("/")
        self._method = method.upper()

    def _send(self, method: str, url: str) -> TransportResponse:
        self._gateway.require(method, url)          # raises GatewayBlocked on deny/budget
        return self._transport(method, url)

    def param_probe(self, params: dict) -> pmod.ProbeResponse:
        url = self._base + ("?" + urlencode(params) if params else "")
        r = self._send(self._method, url)
        return pmod.ProbeResponse(status=r.status, headers=r.headers, body=r.body,
                                  redirect_location=r.redirect_location)

    def route_probe(self, method: str, path: str) -> rmod.ProbeResponse:
        url = self._base + (path if path.startswith("/") else "/" + path)
        try:
            r = self._send(method, url)
        except GatewayBlocked:
            # A destination the gateway won't allow reads as an unhealthy host, so
            # the enumerator quarantines it instead of guessing.
            return rmod.ProbeResponse(status=0, error=True)
        return rmod.ProbeResponse(status=r.status, body=r.body,
                                  error=r.status == 0 or r.status >= 500)


def run_parameter_stage(
    envelope: ExecutionEnvelope, candidates: list[str], *, gateway, transport: Transport,
    base_url: str, method: str = "GET", config: pmod.DiscoveryConfig | None = None,
) -> list:
    """Discover parameters through the gateway; emit PARAMETER events."""
    probe = GatewayProbe(gateway, transport, base_url=base_url, method=method)
    engine = pmod.ParameterDiscovery(probe.param_probe, config or pmod.DiscoveryConfig(method=method))
    route = urlsplit(base_url).path or "/"
    try:
        result = engine.discover(candidates)
    except GatewayBlocked as exc:
        return [event_from(EventKind.DIAGNOSTIC, envelope,
                           {"code": "gateway_blocked", "message": exc.reason,
                            "host": exc.host, "blocking": False},
                           source=PARAM_SOURCE, confidence=0.0)]

    events = []
    for p in result.parameters:
        events.append(event_from(
            EventKind.PARAMETER, envelope,
            {"name": p.name, "location": "query", "method": method, "route": route,
             "reflected": p.reflected, "evidence": p.evidence},
            source=PARAM_SOURCE, confidence=p.confidence,
        ))
    if not result.complete:
        events.append(event_from(EventKind.DIAGNOSTIC, envelope,
                                 {"code": result.reason or "incomplete",
                                  "message": "parameter discovery incomplete", "blocking": False},
                                 source=PARAM_SOURCE, confidence=0.0))
    return events


def run_route_stage(
    envelope: ExecutionEnvelope, schema: rmod.RouteSchema, *, gateway, transport: Transport,
    base_url: str, host: str, config: rmod.EnumConfig | None = None,
) -> list:
    """Confirm routes through the gateway; emit ROUTE events for present routes."""
    probe = GatewayProbe(gateway, transport, base_url=base_url)
    enumerator = rmod.RouteEnumerator(probe.route_probe, host=host, config=config)
    result = enumerator.enumerate(schema)

    events = []
    for obs in result.routes:
        events.append(event_from(
            EventKind.ROUTE, envelope,
            {"method": obs.method, "path": obs.path, "host": obs.host, "status": obs.status,
             "discovery_source": "route-enumeration", "evidence": obs.evidence,
             "risks": list(obs.risks)},
            source=ROUTE_SOURCE, confidence=0.9,
        ))
    if not result.complete:
        events.append(event_from(EventKind.DIAGNOSTIC, envelope,
                                 {"code": result.reason or "incomplete", "health": result.health.value,
                                  "message": "route enumeration incomplete", "blocking": False},
                                 source=ROUTE_SOURCE, confidence=0.0))
    return events
