"""Self-hint: the model reads code and produces its own focused lead."""

from __future__ import annotations

from pathlib import Path

from aegis.ai.auto_hint import auto_hint_for, generate_hint, sample_sources


class _FakeClient:
    def __init__(self, payload=None, raise_exc=False):
        self._p = payload or {"lead": "The AJAX handler in admin.php runs a DB query on "
                                       "$_POST without a nonce or capability check",
                              "where": "admin.php:handle_import"}
        self._raise = raise_exc

    def complete_json(self, messages):
        if self._raise:
            raise RuntimeError("boom")
        return self._p


def _repo(tmp_path: Path) -> Path:
    (tmp_path / "admin.php").write_text("<?php function handle_import(){ /* ... */ }", encoding="utf-8")
    (tmp_path / "test").mkdir()
    (tmp_path / "test" / "t.php").write_text("<?php // test", encoding="utf-8")
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / "lib.php").write_text("<?php // dep", encoding="utf-8")
    return tmp_path


def test_sample_skips_tests_and_vendor(tmp_path: Path):
    srcs = sample_sources(_repo(tmp_path))
    paths = [p for p, _ in srcs]
    assert "admin.php" in paths
    assert not any("test" in p or "vendor" in p for p in paths)


def test_generate_hint_formats_lead(tmp_path: Path):
    srcs = sample_sources(_repo(tmp_path))
    hint = generate_hint(_FakeClient(), "acme/plugin", srcs)
    assert "AJAX handler" in hint and "focus:" in hint


def test_empty_sources_no_hint():
    assert generate_hint(_FakeClient(), "a/b", []) == ""


def test_client_error_degrades_to_empty(tmp_path: Path):
    srcs = sample_sources(_repo(tmp_path))
    assert generate_hint(_FakeClient(raise_exc=True), "a/b", srcs) == ""


def test_auto_hint_for_end_to_end(tmp_path: Path):
    hint = auto_hint_for(_repo(tmp_path), "acme/plugin", _FakeClient())
    assert hint and "nonce" in hint


def test_php_stubs_arg(monkeypatch, tmp_path: Path):
    from aegis.ai.tool_bridge import php_stubs_arg
    monkeypatch.delenv("AEGIS_PHP_STUBS", raising=False)
    assert php_stubs_arg() == ""
    stub = tmp_path / "wp.php"; stub.write_text("<?php", encoding="utf-8")
    monkeypatch.setenv("AEGIS_PHP_STUBS", str(stub))
    assert php_stubs_arg() == f"--stubs={stub}"
    monkeypatch.setenv("AEGIS_PHP_STUBS", "/nonexistent/x.php")
    assert php_stubs_arg() == ""       # missing file -> no-op
