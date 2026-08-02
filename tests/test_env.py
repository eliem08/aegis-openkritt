import os

from aegis.env import find_dotenv, load_dotenv, parse_env

SAMPLE = """
# a comment
export FOO=bar
BAZ = qux
QUOTED="has spaces"
SINGLE='single'
JSON={"a":1,"b":"c#d"}

# blank line above
EMPTY=
NOEQUALS
"""


def test_parse_env_basic():
    parsed = parse_env(SAMPLE)
    assert parsed["FOO"] == "bar"
    assert parsed["BAZ"] == "qux"
    assert parsed["QUOTED"] == "has spaces"
    assert parsed["SINGLE"] == "single"
    assert parsed["EMPTY"] == ""
    assert "NOEQUALS" not in parsed


def test_parse_env_preserves_hash_in_value():
    # JSON / values containing '#' must survive (no inline-comment stripping).
    parsed = parse_env(SAMPLE)
    assert parsed["JSON"] == '{"a":1,"b":"c#d"}'


def test_load_dotenv_sets_and_respects_existing(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text("NEW_KEY=new_value\nEXISTING=from_file\n", encoding="utf-8")

    monkeypatch.delenv("NEW_KEY", raising=False)
    monkeypatch.setenv("EXISTING", "from_real_env")

    applied = load_dotenv(env_file)
    assert applied["NEW_KEY"] == "new_value"
    assert os.environ["NEW_KEY"] == "new_value"
    # real environment wins by default
    assert os.environ["EXISTING"] == "from_real_env"


def test_load_dotenv_override(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text("EXISTING=from_file\n", encoding="utf-8")
    monkeypatch.setenv("EXISTING", "from_real_env")
    load_dotenv(env_file, override=True)
    assert os.environ["EXISTING"] == "from_file"


def test_load_dotenv_missing_file_is_noop(tmp_path):
    assert load_dotenv(tmp_path / "nope.env", search=False) == {}


def test_load_dotenv_accepts_directory(tmp_path, monkeypatch):
    (tmp_path / ".env").write_text("DIR_KEY=1\n", encoding="utf-8")
    monkeypatch.delenv("DIR_KEY", raising=False)
    load_dotenv(tmp_path, search=False)
    assert os.environ["DIR_KEY"] == "1"


def test_find_dotenv(tmp_path):
    (tmp_path / ".env").write_text("X=1\n", encoding="utf-8")
    sub = tmp_path / "a" / "b"
    sub.mkdir(parents=True)
    found = find_dotenv(sub)
    assert found == tmp_path / ".env"
