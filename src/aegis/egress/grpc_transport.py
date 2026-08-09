"""Pinned unary gRPC transport for the scoped egress sidecar."""

from __future__ import annotations

import base64
import json
from collections.abc import Callable
from urllib.parse import urlsplit

from pydantic import BaseModel, Field

MAX_DESCRIPTOR_BYTES = 1_048_576
MAX_GRPC_MESSAGE_BYTES = 2_097_152
GRPC_FORWARDED_METADATA = frozenset({
    "authorization", "cookie", "x-api-key", "x-request-id", "x-tenant-id",
})


class GrpcUnaryRequest(BaseModel):
    url: str
    service_method: str
    request_type: str
    response_type: str
    descriptor_set_base64: str
    request_json: dict[str, object] = Field(default_factory=dict)
    metadata: dict[str, str] = Field(default_factory=dict)
    timeout_seconds: float = Field(default=5.0, gt=0.0, le=30.0)


class GrpcUnaryResponse(BaseModel):
    status: str
    details: str = ""
    response_json: dict[str, object] | None = None


GrpcUnarySender = Callable[
    [str, str, GrpcUnaryRequest, dict[str, str]], GrpcUnaryResponse,
]


def _load_message_types(request: GrpcUnaryRequest):
    try:
        from google.protobuf import descriptor_pb2, descriptor_pool, message_factory

        raw = base64.b64decode(request.descriptor_set_base64, validate=True)
        if not raw or len(raw) > MAX_DESCRIPTOR_BYTES:
            raise ValueError("gRPC descriptor set is empty or exceeded the size limit")
        descriptor_set = descriptor_pb2.FileDescriptorSet.FromString(raw)
        pool = descriptor_pool.DescriptorPool()
        remaining = list(descriptor_set.file)
        while remaining:
            next_round = []
            progressed = False
            for descriptor in remaining:
                try:
                    pool.Add(descriptor)
                    progressed = True
                except TypeError:
                    next_round.append(descriptor)
            if not progressed:
                raise ValueError("gRPC descriptor dependencies could not be resolved")
            remaining = next_round
        request_class = message_factory.GetMessageClass(
            pool.FindMessageTypeByName(request.request_type)
        )
        response_class = message_factory.GetMessageClass(
            pool.FindMessageTypeByName(request.response_type)
        )
        return request_class, response_class
    except (ImportError, KeyError, TypeError, ValueError) as exc:
        raise ValueError(f"invalid or unavailable gRPC descriptor set: {exc}") from exc


def default_grpc_unary_sender(
    url: str,
    pinned_ip: str,
    request: GrpcUnaryRequest,
    metadata: dict[str, str],
) -> GrpcUnaryResponse:
    """Invoke one known unary method against the gateway-pinned address."""
    try:
        import grpc
        from google.protobuf import json_format
    except ImportError as exc:
        raise RuntimeError("grpcio and protobuf are required by the gRPC egress backend") from exc

    request_class, response_class = _load_message_types(request)
    try:
        request_message = json_format.ParseDict(request.request_json, request_class())
    except (TypeError, ValueError) as exc:
        raise ValueError(f"gRPC request does not conform to the registered schema: {exc}") from exc
    serialized = request_message.SerializeToString()
    if len(serialized) > MAX_GRPC_MESSAGE_BYTES:
        raise ValueError("gRPC request exceeded the message size limit")

    parts = urlsplit(url)
    secure = parts.scheme == "https"
    port = parts.port or (443 if secure else 80)
    target = f"{pinned_ip}:{port}"
    options = (
        ("grpc.max_send_message_length", MAX_GRPC_MESSAGE_BYTES),
        ("grpc.max_receive_message_length", MAX_GRPC_MESSAGE_BYTES),
    )
    if secure:
        options = (*options,
                   ("grpc.ssl_target_name_override", parts.hostname or ""),
                   ("grpc.default_authority", parts.hostname or ""))
        channel = grpc.secure_channel(target, grpc.ssl_channel_credentials(), options=options)
    else:
        channel = grpc.insecure_channel(target, options=options)
    try:
        call = channel.unary_unary(
            request.service_method,
            request_serializer=lambda message: message.SerializeToString(),
            response_deserializer=response_class.FromString,
        )
        response = call(
            request_message,
            metadata=tuple(metadata.items()),
            timeout=request.timeout_seconds,
        )
        document = json_format.MessageToDict(
            response, preserving_proto_field_name=True,
        )
        if len(json.dumps(document, sort_keys=True).encode("utf-8")) > MAX_GRPC_MESSAGE_BYTES:
            raise ValueError("gRPC response exceeded the message size limit")
        return GrpcUnaryResponse(status="OK", response_json=document)
    except grpc.RpcError as exc:
        code = exc.code().name if exc.code() is not None else "UNKNOWN"
        details = (exc.details() or "")[:512]
        return GrpcUnaryResponse(status=code, details=details)
    finally:
        channel.close()


__all__ = [
    "GRPC_FORWARDED_METADATA", "GrpcUnaryRequest", "GrpcUnaryResponse", "GrpcUnarySender",
    "MAX_DESCRIPTOR_BYTES", "MAX_GRPC_MESSAGE_BYTES", "default_grpc_unary_sender",
]
