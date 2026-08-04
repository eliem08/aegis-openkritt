"""Disposable local-instance bring-up (no docker touched in tests)."""

from __future__ import annotations

import pytest

from aegis.ai import local_instance as li
from aegis.ai.local_instance import LocalInstance, LocalInstanceError, has_compose, start_local_instance


def test_has_compose(tmp_path):
    assert not has_compose(tmp_path)
    (tmp_path / "docker-compose.yml").write_text("services: {}", encoding="utf-8")
    assert has_compose(tmp_path)


def test_bring_up_is_opt_in(tmp_path):
    (tmp_path / "docker-compose.yml").write_text("services: {}", encoding="utf-8")
    with pytest.raises(LocalInstanceError, match="opt-in"):
        start_local_instance(tmp_path)                    # allow_compose_up defaults False


def test_bring_up_requires_compose_file(tmp_path):
    with pytest.raises(LocalInstanceError, match="no docker-compose"):
        start_local_instance(tmp_path, allow_compose_up=True)


def test_bring_up_tears_down_when_not_ready(tmp_path, monkeypatch):
    (tmp_path / "docker-compose.yml").write_text("services: {}", encoding="utf-8")
    calls = []

    def fake_run(args, cwd=None, timeout=600):
        calls.append(args)
        class _R: returncode = 0; stdout = ""; stderr = ""
        return _R()

    monkeypatch.setattr(li, "_run", fake_run)
    monkeypatch.setattr(li, "wait_for_http", lambda *a, **k: False)   # never ready
    with pytest.raises(LocalInstanceError, match="did not become ready"):
        start_local_instance(tmp_path, allow_compose_up=True, host_port=8099)
    # both up and the teardown down must have run
    assert any("up" in a for a in calls) and any("down" in a for a in calls)


def test_bring_up_success_returns_local_url(tmp_path, monkeypatch):
    (tmp_path / "docker-compose.yml").write_text("services: {}", encoding="utf-8")
    monkeypatch.setattr(li, "_run", lambda *a, **k: type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})())
    monkeypatch.setattr(li, "wait_for_http", lambda *a, **k: True)
    inst = start_local_instance(tmp_path, allow_compose_up=True, host_port=8099)
    try:
        assert inst.base_url == "http://127.0.0.1:8099"
        assert inst.project.startswith("aegis-repro-")
    finally:
        inst.down()


def test_context_manager_calls_down(tmp_path, monkeypatch):
    downed = {"n": 0}
    inst = LocalInstance("http://127.0.0.1:8099", "aegis-repro-8099", tmp_path, _up=True)
    monkeypatch.setattr(li, "_run", lambda *a, **k: downed.__setitem__("n", downed["n"] + 1)
                        or type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})())
    with inst:
        pass
    assert downed["n"] == 1                                # down() ran on exit
