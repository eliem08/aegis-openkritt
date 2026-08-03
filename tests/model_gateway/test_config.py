from pathlib import Path

import pytest

from aegis.model_gateway import ModelGatewayConfig, ModelGatewayConfigError


def test_config_loads_secrets_from_files(tmp_path: Path):
    key = tmp_path / "provider"
    token = tmp_path / "caller"
    key.write_text("provider-secret", encoding="utf-8")
    token.write_text("x" * 48, encoding="utf-8")
    cfg = ModelGatewayConfig.from_env({
        "AEGIS_MODEL_PROVIDER_KEY_FILE": str(key),
        "AEGIS_MODEL_GATEWAY_TOKEN_FILE": str(token),
    })
    assert cfg.provider_api_key == "provider-secret"
    assert cfg.caller_token == "x" * 48
    assert cfg.provider_origin == "https://api.deepseek.com"


@pytest.mark.parametrize("origin", [
    "http://api.deepseek.com",
    "https://user:pass@api.deepseek.com",
    "https://api.deepseek.com/path",
    "https://api.deepseek.com?key=secret",
])
def test_provider_origin_is_exact_https_origin(origin):
    with pytest.raises(ModelGatewayConfigError):
        ModelGatewayConfig("provider-secret", "x" * 48, provider_origin=origin)


def test_direct_and_file_secret_is_ambiguous(tmp_path: Path):
    path = tmp_path / "key"
    path.write_text("provider-secret", encoding="utf-8")
    with pytest.raises(ModelGatewayConfigError):
        ModelGatewayConfig.from_env({
            "AEGIS_MODEL_PROVIDER_KEY_FILE": str(path),
            "AEGIS_MODEL_PROVIDER_KEY": "also-set",
            "AEGIS_MODEL_GATEWAY_TOKEN": "x" * 48,
        })
