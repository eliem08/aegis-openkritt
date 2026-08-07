"""HTTP fetch boundary for workers without a direct external route."""

from __future__ import annotations

import base64
import ipaddress
import os
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx
from fastapi import FastAPI, Header, HTTPException, Response
from pydantic import BaseModel, Field

from aegis.gateway import GatewayConfig, NetworkProfile, ScopedExecutionGateway
from aegis.policy import ScopeGuard

from .auth import EgressClaims, EgressTokenError, verify_token

MAX_REQUEST_BODY = 1_048_576
MAX_RESPONSE_BODY = 2_097_152
MAX_REDIRECTS = 5
FORWARDED_HEADERS = frozenset({
    "accept", "accept-language", "authorization", "content-type", "cookie",
    "if-none-match", "if-modified-since", "user-agent", "x-requested-with",
})
RETURNED_HEADERS = frozenset({
    "content-type", "content-length", "etag", "last-modified", "location",
})


class FetchRequest(BaseModel):
    method: str = "GET"
    url: str
    headers: dict[str, str] = Field(default_factory=dict)
    body_base64: str | None = None


class FetchResponse(BaseModel):
    status_code: int
    headers: dict[str, str]
    body_base64: str
    final_url: str
    redirects: int


@dataclass(frozen=True)
class UpstreamResponse:
    status_code: int
    headers: dict[str, str]
    body: bytes


Sender = Callable[[str, str, str, dict[str, str], bytes], UpstreamResponse]


@dataclass(frozen=True)
class EgressServiceConfig:
    signing_key: str
    oast_domain: str | None = None

    @classmethod
    def from_env(cls) -> EgressServiceConfig:
        path = os.environ.get("AEGIS_EGRESS_SIGNING_KEY_FILE")
        if not path or not Path(path).is_file():
            raise RuntimeError("AEGIS_EGRESS_SIGNING_KEY_FILE is required")
        key = Path(path).read_text(encoding="utf-8").strip()
        if len(key) < 32:
            raise RuntimeError("egress signing key is too short")
        return cls(signing_key=key, oast_domain=os.environ.get("AEGIS_OAST_DOMAIN") or None)


def _default_sender(method: str, url: str, pinned_ip: str, headers: dict[str, str], body: bytes) -> UpstreamResponse:
    parts = urlsplit(url)
    ip = ipaddress.ip_address(pinned_ip)
    rendered_ip = f"[{ip}]" if ip.version == 6 else str(ip)
    port = f":{parts.port}" if parts.port else ""
    pinned_url = urlunsplit((parts.scheme, rendered_ip + port, parts.path or "/", parts.query, ""))
    outgoing_headers = dict(headers)
    outgoing_headers["host"] = parts.netloc
    with httpx.Client(timeout=httpx.Timeout(10.0), follow_redirects=False, trust_env=False) as client:
        request = client.build_request(method, pinned_url, headers=outgoing_headers, content=body)
        if parts.scheme == "https":
            request.extensions["sni_hostname"] = parts.hostname.encode("idna")
        with client.send(request, stream=True) as response:
            chunks = []
            size = 0
            for chunk in response.iter_bytes():
                size += len(chunk)
                if size > MAX_RESPONSE_BODY:
                    raise HTTPException(status_code=502, detail="upstream response exceeded limit")
                chunks.append(chunk)
            return UpstreamResponse(response.status_code, dict(response.headers), b"".join(chunks))


def _gateway(claims: EgressClaims, resolver=None) -> ScopedExecutionGateway:
    profile = NetworkProfile(claims.profile)
    config = GatewayConfig(
        profile=profile,
        scope=ScopeGuard(claims.scope) if claims.scope else None,
        allowed_providers=claims.allowed_providers,
        oast_host=claims.oast_host,
        allowed_methods=set(claims.allowed_methods) if claims.allowed_methods else None,
        request_budget=claims.request_limit,
    )
    return ScopedExecutionGateway(config, resolver=resolver, tenant_id=claims.tenant_id)


def create_egress_app(
    config: EgressServiceConfig | None = None,
    *,
    budget_backend=None,
    resolver=None,
    sender: Sender | None = None,
) -> FastAPI:
    config = config or EgressServiceConfig.from_env()
    sender = sender or _default_sender
    app = FastAPI(title="aegis scoped egress", docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/healthz")
    def healthz(response: Response):
        connected = budget_backend is None or budget_backend.connected
        if not connected:
            response.status_code = 503
        return {"status": "ok" if connected else "coordination_unavailable"}

    @app.post("/v1/fetch", response_model=FetchResponse)
    def fetch(request: FetchRequest, authorization: str | None = Header(default=None)):
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="missing egress authorization")
        try:
            claims = verify_token(authorization[7:], config.signing_key)
        except EgressTokenError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc
        if request.method.upper() != claims.method.upper() or request.url != claims.destination:
            raise HTTPException(status_code=403, detail="request does not match signed destination")
        try:
            body = base64.b64decode(request.body_base64, validate=True) if request.body_base64 else b""
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="body_base64 is invalid") from exc
        if len(body) > MAX_REQUEST_BODY:
            raise HTTPException(status_code=413, detail="request body exceeded limit")
        headers = {key.lower(): value for key, value in request.headers.items() if key.lower() in FORWARDED_HEADERS}
        gateway = _gateway(claims, resolver=resolver)
        url = request.url
        redirects = 0
        while True:
            if budget_backend is not None:
                remaining = max(1, claims.expires_at - claims.issued_at)
                count = budget_backend.incr_window(
                    f"egress-budget:{claims.tenant_id}:{claims.engagement_id}:{claims.budget_id}", remaining,
                )
                if count > claims.request_limit:
                    raise HTTPException(status_code=429, detail="signed request budget exhausted")
            decision = gateway.authorize(request.method, url)
            if not decision.allowed or not decision.pinned_ip:
                raise HTTPException(status_code=403, detail=decision.reason)
            upstream = sender(request.method.upper(), url, decision.pinned_ip, headers, body)
            location = next((value for key, value in upstream.headers.items() if key.lower() == "location"), None)
            if upstream.status_code not in {301, 302, 303, 307, 308} or not location:
                returned = {key.lower(): value for key, value in upstream.headers.items() if key.lower() in RETURNED_HEADERS}
                return FetchResponse(
                    status_code=upstream.status_code,
                    headers=returned,
                    body_base64=base64.b64encode(upstream.body).decode("ascii"),
                    final_url=url,
                    redirects=redirects,
                )
            redirects += 1
            if redirects > MAX_REDIRECTS:
                raise HTTPException(status_code=502, detail="redirect limit exceeded")
            url = urljoin(url, location)

    return app
