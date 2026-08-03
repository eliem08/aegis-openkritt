from pathlib import Path

import pytest

from aegis.model_gateway.bootstrap import (
    ModelSecretBootstrapError,
    bootstrap_model_secrets,
    main,
)


def test_bootstrap_copies_key_and_generates_separate_token(tmp_path: Path):
    env_file = tmp_path / ".env"
    env_file.write_text("DEEPSEEK_API_KEY=provider-secret\n", encoding="utf-8")
    output = tmp_path / "secrets"
    paths = bootstrap_model_secrets(output, env_file=env_file)
    assert {path.name for path in paths} == {"deepseek_api_key", "model_gateway_token"}
    assert (output / "deepseek_api_key").read_text() == "provider-secret"
    assert len((output / "model_gateway_token").read_text()) >= 48
    assert (output / "model_gateway_token").read_text() != "provider-secret"


def test_bootstrap_refuses_placeholder_or_overwrite(tmp_path: Path):
    env_file = tmp_path / ".env"
    env_file.write_text("DEEPSEEK_API_KEY=your-deepseek-api-key\n", encoding="utf-8")
    with pytest.raises(ModelSecretBootstrapError, match="not configured"):
        bootstrap_model_secrets(tmp_path / "out", env_file=env_file)

    env_file.write_text("DEEPSEEK_API_KEY=provider-secret\n", encoding="utf-8")
    output = tmp_path / "out"
    bootstrap_model_secrets(output, env_file=env_file)
    with pytest.raises(ModelSecretBootstrapError, match="overwrite"):
        bootstrap_model_secrets(output, env_file=env_file)


def test_cli_does_not_print_secret_values(tmp_path: Path, capsys):
    env_file = tmp_path / ".env"
    env_file.write_text("DEEPSEEK_API_KEY=provider-secret\n", encoding="utf-8")
    output = tmp_path / "secrets"
    assert main(["--output", str(output), "--env-file", str(env_file)]) == 0
    printed = capsys.readouterr().out
    assert "provider-secret" not in printed
    assert (output / "model_gateway_token").read_text() not in printed
