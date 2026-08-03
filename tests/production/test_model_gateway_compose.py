from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_model_gateway_compose_keeps_provider_key_out_of_control_plane():
    text = (ROOT / "compose.production.model.yml").read_text(encoding="utf-8")
    control, gateway = text.split("  model.prod.internal:", 1)
    assert "AEGIS_MODEL_GATEWAY_TOKEN_FILE" in control
    assert "deepseek_api_key" not in control
    assert "DEEPSEEK_API_KEY" not in control
    assert "AEGIS_MODEL_PROVIDER_KEY_FILE: /run/secrets/deepseek_api_key" in gateway


def test_only_gateway_is_dual_homed_to_model_egress():
    text = (ROOT / "compose.production.model.yml").read_text(encoding="utf-8")
    control, gateway = text.split("  model.prod.internal:", 1)
    assert "model_internal" in control
    assert "model_egress" not in control
    service, definitions = gateway.split("networks:\n  model_internal:", 1)
    assert "model_internal:" in service
    assert "model_egress: {}" in service
    assert "internal: true" in definitions
