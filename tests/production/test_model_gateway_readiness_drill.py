from aegis.production.config import ProductionSettings
from aegis.production.drills import _http_health
from aegis.production.readiness import production_deployment_issues


def model_codes(settings):
    return {
        issue.code for issue in production_deployment_issues(settings)
        if issue.code.startswith("model_gateway")
    }


def test_required_model_gateway_uses_internal_origin_and_file_token(tmp_path):
    token = tmp_path / "model-token"
    token.write_text("x" * 48, encoding="utf-8")
    settings = ProductionSettings.from_env({
        "AEGIS_PRODUCTION": "1",
        "AEGIS_REQUIRE_MODEL_GATEWAY": "1",
        "AEGIS_MODEL_GATEWAY_URL": "http://model.prod.internal:8090",
        "AEGIS_MODEL_GATEWAY_TOKEN_FILE": str(token),
        "AEGIS_REQUIRE_OAST": "0",
    })
    assert model_codes(settings) == set()
    assert settings.secret_sources["AEGIS_MODEL_GATEWAY_TOKEN"] == "file"


def test_required_model_gateway_fails_closed_for_missing_or_external_configuration(tmp_path):
    missing = ProductionSettings.from_env({
        "AEGIS_PRODUCTION": "1", "AEGIS_REQUIRE_MODEL_GATEWAY": "1",
        "AEGIS_REQUIRE_OAST": "0",
    })
    assert {"model_gateway_missing", "model_gateway_token_missing"} <= model_codes(missing)

    token = tmp_path / "token"
    token.write_text("x" * 48, encoding="utf-8")
    external = ProductionSettings.from_env({
        "AEGIS_PRODUCTION": "1", "AEGIS_REQUIRE_MODEL_GATEWAY": "1",
        "AEGIS_MODEL_GATEWAY_URL": "https://gateway.example.com",
        "AEGIS_MODEL_GATEWAY_TOKEN_FILE": str(token), "AEGIS_REQUIRE_OAST": "0",
    })
    assert "model_gateway_not_internal" in model_codes(external)


def test_model_drill_targets_dependency_readiness_not_liveness(monkeypatch):
    requested = []

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    def open_request(request, timeout):
        requested.append((request.full_url, timeout))
        return Response()

    monkeypatch.setattr("urllib.request.urlopen", open_request)
    assert _http_health(
        "http://model.prod.internal:8090", "model gateway", endpoint="readyz",
    ) == "model gateway health endpoint passed"
    assert requested == [("http://model.prod.internal:8090/readyz", 5)]


def test_drill_overlay_receives_only_internal_caller_secret():
    text = open("compose.production.model.yml", encoding="utf-8").read()
    drills = text.split("  production-drills:", 1)[1].split("  model.prod.internal:", 1)[0]
    assert "AEGIS_REQUIRE_MODEL_GATEWAY" in drills
    assert "AEGIS_MODEL_GATEWAY_TOKEN_FILE" in drills
    assert "model_internal" in drills
    assert "deepseek_api_key" not in drills
    assert "model_egress" not in drills
