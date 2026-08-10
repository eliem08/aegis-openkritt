"""HTTP fetch boundary for workers without a direct external route."""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import os
import secrets
import socket
import ssl
import struct
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
from .grpc_transport import (
    GRPC_FORWARDED_METADATA,
    GrpcUnaryRequest,
    GrpcUnaryResponse,
    GrpcUnarySender,
    default_grpc_unary_sender,
)

MAX_REQUEST_BODY = 1_048_576
MAX_RESPONSE_BODY = 2_097_152
MAX_REDIRECTS = 5
FORWARDED_HEADERS = frozenset({
    "accept", "accept-language", "authorization", "content-type", "cookie",
    "if-none-match", "if-modified-since", "user-agent", "x-requested-with",
    "idempotency-key", "x-request-id",
})
RETURNED_HEADERS = frozenset({
    "content-type", "content-length", "etag", "last-modified", "location",
    "age", "via", "vary", "cache-control", "cache-status", "x-cache",
    "cf-cache-status", "x-served-by", "x-varnish",
})
WEBSOCKET_FORWARDED_HEADERS = frozenset({
    "authorization", "cookie", "origin", "sec-websocket-protocol", "user-agent",
})
MAX_WEBSOCKET_MESSAGES = 12
MAX_WEBSOCKET_FRAME = 262_144


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
    pinned_ip: str


class WebSocketRequest(BaseModel):
    url: str
    headers: dict[str, str] = Field(default_factory=dict)
    messages: list[str] = Field(default_factory=list, max_length=MAX_WEBSOCKET_MESSAGES)
    receive_limit: int = Field(default=8, ge=1, le=32)
    timeout_seconds: float = Field(default=5.0, gt=0.0, le=30.0)


class WebSocketResponse(BaseModel):
    handshake_status: int
    selected_protocol: str | None = None
    messages: list[str] = Field(default_factory=list)
    close_code: int | None = None


@dataclass(frozen=True)
class UpstreamResponse:
    status_code: int
    headers: dict[str, str]
    body: bytes


Sender = Callable[[str, str, str, dict[str, str], bytes], UpstreamResponse]
WebSocketSender = Callable[
    [str, str, dict[str, str], list[str], int, float], WebSocketResponse,
]


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


def _read_exact(stream, size: int) -> bytes:
    chunks = []
    remaining = size
    while remaining:
        chunk = stream.recv(remaining)
        if not chunk:
            raise ConnectionError("WebSocket peer closed during frame")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _client_frame(opcode: int, payload: bytes) -> bytes:
    if len(payload) > MAX_WEBSOCKET_FRAME:
        raise ValueError("WebSocket message exceeded frame limit")
    mask = secrets.token_bytes(4)
    size = len(payload)
    if size < 126:
        prefix = bytes((0x80 | opcode, 0x80 | size))
    elif size <= 0xFFFF:
        prefix = bytes((0x80 | opcode, 0x80 | 126)) + struct.pack("!H", size)
    else:
        prefix = bytes((0x80 | opcode, 0x80 | 127)) + struct.pack("!Q", size)
    masked = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
    return prefix + mask + masked


def _read_server_frame(stream) -> tuple[int, bool, bytes]:
    first, second = _read_exact(stream, 2)
    final = bool(first & 0x80)
    opcode = first & 0x0F
    if second & 0x80:
        raise ConnectionError("server sent an invalid masked WebSocket frame")
    size = second & 0x7F
    if size == 126:
        size = struct.unpack("!H", _read_exact(stream, 2))[0]
    elif size == 127:
        size = struct.unpack("!Q", _read_exact(stream, 8))[0]
    if size > MAX_WEBSOCKET_FRAME:
        raise ConnectionError("WebSocket response exceeded frame limit")
    return opcode, final, _read_exact(stream, size)


def _default_websocket_sender(
    url: str,
    pinned_ip: str,
    headers: dict[str, str],
    messages: list[str],
    receive_limit: int,
    timeout_seconds: float,
) -> WebSocketResponse:
    """Minimal pinned RFC6455 text client used only by the scoped egress sidecar."""
    parts = urlsplit(url)
    secure = parts.scheme == "wss"
    port = parts.port or (443 if secure else 80)
    raw = socket.create_connection((pinned_ip, port), timeout=timeout_seconds)
    stream = raw
    try:
        if secure:
            stream = ssl.create_default_context().wrap_socket(raw, server_hostname=parts.hostname)
        stream.settimeout(timeout_seconds)
        key = base64.b64encode(secrets.token_bytes(16)).decode("ascii")
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        host = parts.hostname or ""
        default_port = 443 if secure else 80
        host_header = host if port == default_port else f"{host}:{port}"
        lines = [
            f"GET {path} HTTP/1.1", f"Host: {host_header}", "Upgrade: websocket",
            "Connection: Upgrade", f"Sec-WebSocket-Key: {key}",
            "Sec-WebSocket-Version: 13",
        ]
        lines.extend(f"{name}: {value}" for name, value in headers.items())
        stream.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1"))
        response = bytearray()
        while b"\r\n\r\n" not in response:
            response.extend(_read_exact(stream, 1))
            if len(response) > 65_536:
                raise ConnectionError("WebSocket handshake headers exceeded limit")
        header_lines = bytes(response).decode("latin-1").split("\r\n")
        try:
            status = int(header_lines[0].split(" ", 2)[1])
        except (IndexError, ValueError) as exc:
            raise ConnectionError("malformed WebSocket handshake response") from exc
        response_headers = {}
        for line in header_lines[1:]:
            if ":" in line:
                name, value = line.split(":", 1)
                response_headers[name.strip().lower()] = value.strip()
        expected_accept = base64.b64encode(hashlib.sha1(
            (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")
        ).digest()).decode("ascii")
        if status != 101 or response_headers.get("sec-websocket-accept") != expected_accept:
            return WebSocketResponse(handshake_status=status)
        for message in messages:
            stream.sendall(_client_frame(0x1, message.encode("utf-8")))
        received: list[str] = []
        close_code = None
        while len(received) < receive_limit:
            try:
                opcode, final, payload = _read_server_frame(stream)
            except TimeoutError:
                break
            if not final:
                raise ConnectionError("fragmented WebSocket frames are not supported")
            if opcode == 0x8:
                close_code = struct.unpack("!H", payload[:2])[0] if len(payload) >= 2 else 1005
                break
            if opcode == 0x9:
                stream.sendall(_client_frame(0xA, payload))
            elif opcode == 0x1:
                received.append(payload.decode("utf-8"))
            elif opcode not in {0xA}:
                raise ConnectionError("non-text WebSocket frame is unsupported")
        stream.sendall(_client_frame(0x8, struct.pack("!H", 1000)))
        return WebSocketResponse(
            handshake_status=status,
            selected_protocol=response_headers.get("sec-websocket-protocol"),
            messages=received,
            close_code=close_code,
        )
    finally:
        stream.close()


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
    websocket_sender: WebSocketSender | None = None,
    grpc_unary_sender: GrpcUnarySender | None = None,
) -> FastAPI:
    config = config or EgressServiceConfig.from_env()
    sender = sender or _default_sender
    websocket_sender = websocket_sender or _default_websocket_sender
    grpc_unary_sender = grpc_unary_sender or default_grpc_unary_sender
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
        if urlsplit(request.url).scheme not in {"http", "https"}:
            raise HTTPException(status_code=422, detail="fetch requires an HTTP(S) destination")
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
                    pinned_ip=decision.pinned_ip,
                )
            redirects += 1
            if redirects > MAX_REDIRECTS:
                raise HTTPException(status_code=502, detail="redirect limit exceeded")
            url = urljoin(url, location)

    @app.post("/v1/websocket", response_model=WebSocketResponse)
    def websocket_session(
        request: WebSocketRequest, authorization: str | None = Header(default=None),
    ):
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="missing egress authorization")
        try:
            claims = verify_token(authorization[7:], config.signing_key)
        except EgressTokenError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc
        if claims.method.upper() != "GET" or request.url != claims.destination:
            raise HTTPException(status_code=403, detail="request does not match signed destination")
        if urlsplit(request.url).scheme not in {"ws", "wss"}:
            raise HTTPException(status_code=422, detail="WebSocket execution requires ws:// or wss://")
        if len(request.messages) + 1 > claims.request_limit:
            raise HTTPException(status_code=429, detail="signed WebSocket action budget exhausted")
        gateway = _gateway(claims, resolver=resolver)
        decision = gateway.authorize("GET", request.url)
        if not decision.allowed or not decision.pinned_ip:
            raise HTTPException(status_code=403, detail=decision.reason)
        if budget_backend is not None:
            remaining = max(1, claims.expires_at - claims.issued_at)
            key = f"egress-budget:{claims.tenant_id}:{claims.engagement_id}:{claims.budget_id}"
            for _ in range(len(request.messages) + 1):
                if budget_backend.incr_window(key, remaining) > claims.request_limit:
                    raise HTTPException(status_code=429, detail="signed request budget exhausted")
        headers = {
            key.lower(): value for key, value in request.headers.items()
            if key.lower() in WEBSOCKET_FORWARDED_HEADERS
        }
        if any("\r" in value or "\n" in value for value in headers.values()):
            raise HTTPException(status_code=422, detail="WebSocket header contains a line break")
        try:
            return websocket_sender(
                request.url, decision.pinned_ip, headers, request.messages,
                request.receive_limit, request.timeout_seconds,
            )
        except (ConnectionError, OSError, ssl.SSLError, ValueError) as exc:
            raise HTTPException(status_code=502, detail=f"WebSocket backend failed: {exc}") from exc

    @app.post("/v1/grpc/unary", response_model=GrpcUnaryResponse)
    def grpc_unary(
        request: GrpcUnaryRequest, authorization: str | None = Header(default=None),
    ):
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="missing egress authorization")
        try:
            claims = verify_token(authorization[7:], config.signing_key)
        except EgressTokenError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc
        if claims.method.upper() != "POST" or request.url != claims.destination:
            raise HTTPException(status_code=403, detail="request does not match signed destination")
        parts = urlsplit(request.url)
        if parts.scheme not in {"http", "https"}:
            raise HTTPException(status_code=422, detail="gRPC execution requires HTTP(S) authority")
        if not request.service_method.startswith("/") or request.service_method != parts.path:
            raise HTTPException(status_code=422, detail="gRPC method must match the signed URL path")
        gateway = _gateway(claims, resolver=resolver)
        decision = gateway.authorize("POST", request.url)
        if not decision.allowed or not decision.pinned_ip:
            raise HTTPException(status_code=403, detail=decision.reason)
        if budget_backend is not None:
            remaining = max(1, claims.expires_at - claims.issued_at)
            key = f"egress-budget:{claims.tenant_id}:{claims.engagement_id}:{claims.budget_id}"
            if budget_backend.incr_window(key, remaining) > claims.request_limit:
                raise HTTPException(status_code=429, detail="signed request budget exhausted")
        metadata = {
            key.lower(): value for key, value in request.metadata.items()
            if key.lower() in GRPC_FORWARDED_METADATA
        }
        if any("\r" in value or "\n" in value for value in metadata.values()):
            raise HTTPException(status_code=422, detail="gRPC metadata contains a line break")
        try:
            return grpc_unary_sender(request.url, decision.pinned_ip, request, metadata)
        except (RuntimeError, TypeError, ValueError) as exc:
            raise HTTPException(status_code=502, detail=f"gRPC backend failed: {exc}") from exc

    return app
