from __future__ import annotations

import base64
import time

from fastapi.testclient import TestClient

from aegis.egress.app import EgressServiceConfig, create_egress_app
from aegis.egress.auth import EgressClaims, issue_token
from aegis.egress.grpc_transport import GrpcUnaryResponse

SECRET = "g" * 48
URL = "https://grpc.example.test/lab.InvoiceService/GetInvoice"


class Budget:
    connected = True

    def __init__(self):
        self.count = 0

    def incr_window(self, _key, _window):
        self.count += 1
        return self.count


def _claims(**overrides):
    now = int(time.time())
    values = dict(
        tenant_id="tenant-a", engagement_id="eng-grpc", profile="target-mutation",
        method="POST", destination=URL, issued_at=now, expires_at=now + 60,
        budget_id="budget-grpc", request_limit=2, scope=["grpc.example.test"],
        allowed_methods=["POST"],
    )
    values.update(overrides)
    return EgressClaims(**values)


def _auth(claims):
    return {"authorization": "Bearer " + issue_token(claims, SECRET, now=claims.issued_at)}


def _request(**overrides):
    values = dict(
        url=URL,
        service_method="/lab.InvoiceService/GetInvoice",
        request_type="lab.InvoiceRequest",
        response_type="lab.InvoiceResponse",
        descriptor_set_base64=base64.b64encode(b"registered-schema").decode("ascii"),
        request_json={"resource_id": "invoice-1"},
        metadata={"authorization": "Bearer owner", "x-unsafe": "drop"},
    )
    values.update(overrides)
    return values


def test_grpc_egress_pins_scope_filters_metadata_and_counts_budget():
    observed = {}
    budget = Budget()

    def sender(url, pinned_ip, request, metadata):
        observed.update(
            url=url, pinned_ip=pinned_ip, method=request.service_method, metadata=metadata,
        )
        return GrpcUnaryResponse(status="OK", response_json={"marker": "controlled"})

    app = create_egress_app(
        EgressServiceConfig(SECRET), budget_backend=budget,
        resolver=lambda _host: ["93.184.216.34"], grpc_unary_sender=sender,
    )
    response = TestClient(app).post(
        "/v1/grpc/unary", headers=_auth(_claims()), json=_request(),
    )
    assert response.status_code == 200
    assert observed == {
        "url": URL,
        "pinned_ip": "93.184.216.34",
        "method": "/lab.InvoiceService/GetInvoice",
        "metadata": {"authorization": "Bearer owner"},
    }
    assert budget.count == 1


def test_grpc_egress_scope_method_and_signed_destination_fail_closed():
    called = []
    sender = lambda *args: called.append(args) or GrpcUnaryResponse(status="OK")
    app = create_egress_app(
        EgressServiceConfig(SECRET), resolver=lambda _host: ["93.184.216.34"],
        grpc_unary_sender=sender,
    )
    client = TestClient(app)
    outside = _claims(
        destination="https://outside.test/lab.InvoiceService/GetInvoice",
        scope=["grpc.example.test"],
    )
    response = client.post(
        "/v1/grpc/unary", headers=_auth(outside),
        json=_request(url=outside.destination),
    )
    assert response.status_code == 403 and called == []

    response = client.post(
        "/v1/grpc/unary", headers=_auth(_claims()),
        json=_request(service_method="/lab.InvoiceService/DeleteInvoice"),
    )
    assert response.status_code == 422 and called == []

    response = client.post(
        "/v1/grpc/unary", headers=_auth(_claims()),
        json=_request(url="https://grpc.example.test/lab.InvoiceService/Other"),
    )
    assert response.status_code == 403 and called == []


def test_grpc_egress_rejects_metadata_injection_and_exhausted_global_budget():
    called = []
    sender = lambda *args: called.append(args) or GrpcUnaryResponse(status="OK")
    app = create_egress_app(
        EgressServiceConfig(SECRET), resolver=lambda _host: ["93.184.216.34"],
        grpc_unary_sender=sender,
    )
    response = TestClient(app).post(
        "/v1/grpc/unary", headers=_auth(_claims()),
        json=_request(metadata={"authorization": "Bearer safe\r\nx-injected: yes"}),
    )
    assert response.status_code == 422 and called == []

    budget = Budget()
    budget.count = 1
    app = create_egress_app(
        EgressServiceConfig(SECRET), budget_backend=budget,
        resolver=lambda _host: ["93.184.216.34"], grpc_unary_sender=sender,
    )
    limited = _claims(request_limit=1)
    response = TestClient(app).post(
        "/v1/grpc/unary", headers=_auth(limited), json=_request(),
    )
    assert response.status_code == 429 and called == []
