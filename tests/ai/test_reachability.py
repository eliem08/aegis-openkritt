"""Reachability heuristic: catch unreachable sinks (dead code / arity mismatch)."""

from __future__ import annotations

from pathlib import Path

from aegis.ai.reachability import check, enclosing_function


def test_enclosing_function_python():
    lines = ["def foo(a, b):", "    x = 1", "    sink(x)"]
    name, params, dl = enclosing_function(lines, 3)
    assert name == "foo" and params == 2 and dl == 1


def test_ruby_bare_call_zero_args_is_arity_mismatch(tmp_path: Path):
    # the real render_inline shape: def needs 1 arg, sole caller passes 0 (bare call)
    (tmp_path / "c.rb").write_text(
        "class C\n"
        "  def act\n"
        "    render_logout_error\n"          # line 3: 0 args
        "  end\n"
        "  def render_logout_error(req)\n"    # line 5: needs 1
        "    render inline: req.errors\n"     # line 6: the sink
        "  end\n"
        "end\n", encoding="utf-8")
    r = check(tmp_path, "c.rb", 6)
    assert r["verdict"] == "arity-mismatch"
    assert r["params"] == 1 and r["arg_counts"] == [0]


def test_matching_arity_is_reachable(tmp_path: Path):
    (tmp_path / "c.rb").write_text(
        "class C\n"
        "  def act\n"
        "    render_logout_error(request)\n"  # passes 1 arg
        "  end\n"
        "  def render_logout_error(req)\n"
        "    render inline: req.errors\n"
        "  end\n"
        "end\n", encoding="utf-8")
    r = check(tmp_path, "c.rb", 6)
    assert r["verdict"] == "reachable"


def test_no_callers(tmp_path: Path):
    (tmp_path / "m.py").write_text(
        "def helper(x):\n"
        "    dangerous(x)\n", encoding="utf-8")
    r = check(tmp_path, "m.py", 2)
    assert r["verdict"] == "no-callers"


def test_entrypoint_not_flagged(tmp_path: Path):
    (tmp_path / "h.go").write_text(
        "func handleRequest(w, r) {\n"
        "    exec(r)\n"
        "}\n", encoding="utf-8")
    r = check(tmp_path, "h.go", 2)
    assert r["verdict"] == "reachable"   # entry point, called by framework
