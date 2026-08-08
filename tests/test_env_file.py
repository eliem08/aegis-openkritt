"""The .env loader: parses KEY=VALUE, respects real env, strips quotes/comments, never overrides
by default. Uses only a temp .env — never the operator's real one."""

from __future__ import annotations

from aegis.env_file import _parse_line, find_dotenv, load_dotenv


def test_parse_line_variants():
    assert _parse_line("A=1") == ("A", "1")
    assert _parse_line("export B=two") == ("B", "two")
    assert _parse_line('C="has spaces"') == ("C", "has spaces")
    assert _parse_line("D='single'") == ("D", "single")
    assert _parse_line("E=val # trailing") == ("E", "val")
    assert _parse_line("# comment") is None
    assert _parse_line("") is None
    assert _parse_line("nokey") is None


def test_load_sets_new_but_not_existing(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text("HACKERONE_API_TOKEN=fromfile\nEXISTING=fromfile\n", encoding="utf-8")
    monkeypatch.delenv("HACKERONE_API_TOKEN", raising=False)
    monkeypatch.setenv("EXISTING", "fromenv")

    loaded = load_dotenv(env)
    import os
    assert "HACKERONE_API_TOKEN" in loaded
    assert os.environ["HACKERONE_API_TOKEN"] == "fromfile"
    # real env wins by default
    assert "EXISTING" not in loaded
    assert os.environ["EXISTING"] == "fromenv"


def test_override_true_replaces(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text("X=fromfile\n", encoding="utf-8")
    monkeypatch.setenv("X", "fromenv")
    load_dotenv(env, override=True)
    import os
    assert os.environ["X"] == "fromfile"


def test_find_dotenv_walks_up(tmp_path, monkeypatch):
    (tmp_path / ".env").write_text("A=1\n", encoding="utf-8")
    sub = tmp_path / "a" / "b"
    sub.mkdir(parents=True)
    found = find_dotenv(sub)
    assert found is not None and found.name == ".env"


def test_missing_file_is_noop(tmp_path):
    assert load_dotenv(tmp_path / "nope.env") == []
