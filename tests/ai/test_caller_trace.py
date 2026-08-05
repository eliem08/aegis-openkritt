"""Caller-tracing: pull the functions that CALL a flagged function into context."""

from __future__ import annotations

from pathlib import Path

from aegis.ai.caller_trace import caller_slices, find_callers


def _write(tmp_path: Path, name: str, body: str) -> Path:
    (tmp_path / name).write_text(body, encoding="utf-8")
    return tmp_path


def test_find_callers_php(tmp_path: Path):
    _write(tmp_path, "handler.php",
           "<?php\nclass H {\n"
           "  public function save($path){ file_put_contents($path, $_FILES['f']['tmp_name']); }\n"
           "  public function do_upload(){ if(current_user_can('manage')){ $this->save('/safe'); } }\n"
           "}\n")
    callers = find_callers(tmp_path, "save")
    assert callers, "should find the do_upload caller"
    c = callers[0]
    assert c["caller"] == "do_upload"
    assert "current_user_can" in c["snippet"]        # the guard the caller supplies is visible


def test_find_callers_skips_definition(tmp_path: Path):
    _write(tmp_path, "a.py", "def save(p):\n    write(p)\n")   # only the def, no caller
    assert find_callers(tmp_path, "save") == []


def test_caller_slices_for_finding(tmp_path: Path):
    _write(tmp_path, "up.php",
           "<?php\n"
           "function save($path){ file_put_contents($path, $x); }\n"   # line 2 = the sink
           "function caller_a(){ save($_GET['p']); }\n"                 # UNSAFE caller
           "function caller_b(){ save('/fixed'); }\n")
    slices = caller_slices(tmp_path, "up.php", 2, max_callers=4)
    assert slices, "should return caller slices for save()"
    joined = "\n".join(s.content for s in slices)
    assert "caller_a" in joined and "$_GET" in joined    # the unsafe caller is surfaced
    assert all(s.path.startswith("caller::") for s in slices)


def test_no_enclosing_function_returns_empty(tmp_path: Path):
    _write(tmp_path, "x.php", "<?php\n$a = 1;\n")
    assert caller_slices(tmp_path, "x.php", 2) == []
