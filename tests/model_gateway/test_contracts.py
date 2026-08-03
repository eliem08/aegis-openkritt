import pytest
from pydantic import ValidationError

from aegis.model_gateway import GatewayMessage, ModelGatewayRequest


def _request(**changes):
    data = {
        "tenant_id": "tenant-a",
        "engagement_id": "eng-1",
        "task_id": "task-1",
        "budget_id": "budget-1",
        "messages": [GatewayMessage(role="user", content="return json")],
    }
    data.update(changes)
    return ModelGatewayRequest(**data)


def test_request_is_strict_and_bounded():
    request = _request()
    assert request.contract_version == 1
    assert request.model == "deepseek-v4-flash"
    with pytest.raises(ValidationError):
        _request(unknown=True)
    with pytest.raises(ValidationError):
        _request(model="arbitrary-provider-model")
    with pytest.raises(ValidationError):
        _request(max_tokens=384_001)
    with pytest.raises(ValidationError):
        _request(tenant_id="tenant a")


def test_messages_reject_unknown_roles_and_fields():
    with pytest.raises(ValidationError):
        GatewayMessage(role="tool", content="x")
    with pytest.raises(ValidationError):
        GatewayMessage(role="user", content="x", authorization="secret")
