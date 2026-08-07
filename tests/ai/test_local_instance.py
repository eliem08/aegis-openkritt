"""Disposable local-instance bring-up (no Docker touched in tests)."""
from __future__ import annotations

import pytest
from aegis.ai import local_instance as li
from aegis.ai.local_instance import LocalInstance, LocalInstanceError, has_compose, start_local_instance


def result(code=0, stdout="", stderr=""):
    return type("R", (), {"returncode": code, "stdout": stdout, "stderr": stderr})()


def model():
    return {"services": {"db": {"expose": [5432]}, "web": {"ports": [{"target": 8080}]}}}


def test_has_compose_supports_modern_and_legacy_names(tmp_path):
    assert not has_compose(tmp_path)
    (tmp_path / "compose.yaml").write_text("services: {}", encoding="utf-8")
    assert has_compose(tmp_path)


def test_bring_up_is_opt_in(tmp_path):
    (tmp_path / "compose.yml").write_text("services: {}", encoding="utf-8")
    with pytest.raises(LocalInstanceError, match="opt-in"):
        start_local_instance(tmp_path)


def test_selects_web_service_and_writes_loopback_override(tmp_path, monkeypatch):
    (tmp_path / "compose.yml").write_text("services: {}", encoding="utf-8")
    calls = []
    monkeypatch.setattr(li, "_compose_model", lambda *a: model())
    monkeypatch.setattr(li, "_run", lambda args, **kwargs: calls.append(args) or result())
    monkeypatch.setattr(li, "wait_for_http", lambda *a, **k: True)
    instance = start_local_instance(tmp_path, allow_compose_up=True, host_port=8099)
    try:
        assert instance.base_url == "http://127.0.0.1:8099"
        assert instance.service_name == "web" and instance.container_port == 8080
        override = instance.compose_files[1].read_text()
        assert '127.0.0.1:8099:8080' in override
        assert any("up" in args for args in calls)
    finally:
        instance.down()
    assert not instance.compose_files[1].exists()


def test_requires_explicit_port_when_compose_has_no_web_port(tmp_path, monkeypatch):
    (tmp_path / "docker-compose.yml").write_text("services: {}", encoding="utf-8")
    monkeypatch.setattr(li, "_compose_model", lambda *a: {"services": {"worker": {}}})
    with pytest.raises(LocalInstanceError, match="could not identify"):
        start_local_instance(tmp_path, allow_compose_up=True)


def test_failure_captures_logs_and_tears_down(tmp_path, monkeypatch):
    (tmp_path / "compose.yml").write_text("services: {}", encoding="utf-8")
    calls = []
    monkeypatch.setattr(li, "_compose_model", lambda *a: model())
    monkeypatch.setattr(li, "_run", lambda args, **kwargs: calls.append(args) or
                        result(stdout="application failed to boot" if "logs" in args else ""))
    monkeypatch.setattr(li, "wait_for_http", lambda *a, **k: False)
    with pytest.raises(LocalInstanceError, match="recent logs"):
        start_local_instance(tmp_path, allow_compose_up=True, host_port=8099)
    assert any("down" in args for args in calls)


def test_context_manager_calls_down(tmp_path, monkeypatch):
    source = tmp_path / "compose.yml"; source.write_text("services: {}")
    override = tmp_path / "override.yml"; override.write_text("services: {}")
    calls = []
    instance = LocalInstance("http://127.0.0.1:8099", "aegis-repro-8099", tmp_path,
                             (source, override), _up=True)
    monkeypatch.setattr(li, "_run", lambda args, **kwargs: calls.append(args) or result())
    with instance:
        pass
    assert any("down" in args for args in calls)
