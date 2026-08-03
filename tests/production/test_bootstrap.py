from __future__ import annotations

import json

import pytest
from cryptography import x509
from cryptography.fernet import Fernet

from aegis.production.bootstrap import BootstrapRefused, bootstrap, main


def test_bootstrap_creates_complete_nonempty_secret_set(tmp_path, capsys):
    root = tmp_path / "secrets"
    paths = bootstrap(root)
    assert len(paths) == 13
    assert all(path.is_file() and path.stat().st_size > 0 for path in paths)
    api_keys = json.loads((root / "api_keys.json").read_text())
    assert len(api_keys) == 1
    assert next(iter(api_keys.values()))["tenant"] == "tenant-primary"
    Fernet((root / "encryption_key").read_bytes())
    x509.load_pem_x509_certificate((root / "postgres_ca.pem").read_bytes())
    output = capsys.readouterr().out
    assert output == ""


def test_bootstrap_refuses_to_replace_existing_secrets(tmp_path):
    root = tmp_path / "secrets"
    bootstrap(root)
    original = (root / "postgres_password").read_text()
    with pytest.raises(BootstrapRefused):
        bootstrap(root)
    assert (root / "postgres_password").read_text() == original


def test_cli_reports_paths_but_not_secret_values(tmp_path, capsys):
    root = tmp_path / "secrets"
    assert main(["--output", str(root)]) == 0
    output = capsys.readouterr().out
    assert str(root.resolve()) in output
    assert (root / "postgres_password").read_text() not in output
    assert next(iter(json.loads((root / "api_keys.json").read_text()))) not in output
