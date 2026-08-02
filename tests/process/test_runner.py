"""Safe process runner: success/failure, timeout, output caps, cancellation,
process-tree cleanup, secret non-disclosure, checksum, minimal env."""

from __future__ import annotations

import hashlib
import os
import sys
import threading
import time

import pytest

from aegis.process import (
    BinaryVerificationError,
    CancelToken,
    ProcessLimits,
    ProcessOutcome,
    SafeProcessRunner,
    verify_binary,
)

PY = sys.executable


def runner() -> SafeProcessRunner:
    return SafeProcessRunner()


def test_success():
    r = runner().run([PY, "-c", "print('hello')"])
    assert r.ok and r.exit_code == 0 and "hello" in r.lines


def test_nonzero_exit_is_failed():
    r = runner().run([PY, "-c", "import sys; sys.exit(3)"])
    assert r.outcome == ProcessOutcome.FAILED and r.exit_code == 3


def test_wall_timeout():
    r = runner().run([PY, "-c", "import time; time.sleep(30)"],
                     limits=ProcessLimits(wall_seconds=0.5))
    assert r.outcome == ProcessOutcome.TIMED_OUT


def test_idle_timeout():
    code = "import sys, time; sys.stdout.write('one\\n'); sys.stdout.flush(); time.sleep(30)"
    r = runner().run([PY, "-c", code], limits=ProcessLimits(wall_seconds=30, idle_seconds=0.5))
    assert r.outcome == ProcessOutcome.TIMED_OUT
    assert "one" in r.lines


def test_output_byte_flood_terminates():
    code = "import sys\nwhile True:\n sys.stdout.write('x'*1000+'\\n'); sys.stdout.flush()"
    r = runner().run([PY, "-c", code], limits=ProcessLimits(max_stdout_bytes=5000, wall_seconds=10))
    assert r.outcome == ProcessOutcome.OUTPUT_LIMIT and r.truncated


def test_max_events_cap():
    code = "import itertools, sys\nfor i in itertools.count():\n sys.stdout.write(str(i)+'\\n'); sys.stdout.flush()"
    r = runner().run([PY, "-c", code], limits=ProcessLimits(max_events=10, wall_seconds=10))
    assert r.outcome == ProcessOutcome.OUTPUT_LIMIT
    assert len(r.lines) <= 11


def test_line_length_cap():
    r = runner().run([PY, "-c", "print('y'*1000)"], limits=ProcessLimits(max_line_bytes=50))
    assert len(r.lines[0]) == 50


def test_cancellation():
    token = CancelToken()
    holder: dict = {}

    def go():
        holder["r"] = runner().run([PY, "-c", "import time; time.sleep(30)"],
                                   cancel=token, limits=ProcessLimits(wall_seconds=30))

    t = threading.Thread(target=go)
    t.start()
    time.sleep(0.5)
    token.cancel()
    t.join(15)
    assert holder["r"].outcome == ProcessOutcome.CANCELLED


def test_process_tree_is_terminated(tmp_path):
    marker = (tmp_path / "child.log")
    marker.write_text("")
    child_py = tmp_path / "child.py"
    child_py.write_text(
        "import time\n"
        f"while True:\n open(r'{marker.as_posix()}', 'a').write('x')\n time.sleep(0.03)\n"
    )
    parent_py = tmp_path / "parent.py"
    parent_py.write_text(
        "import subprocess, sys, time\n"
        f"subprocess.Popen([sys.executable, r'{child_py.as_posix()}'])\n"
        "time.sleep(30)\n"
    )

    token = CancelToken()
    holder: dict = {}

    def go():
        holder["r"] = runner().run([PY, str(parent_py)], cancel=token, limits=ProcessLimits(wall_seconds=30))

    t = threading.Thread(target=go)
    t.start()
    time.sleep(1.0)
    token.cancel()
    t.join(15)
    assert holder["r"].outcome == ProcessOutcome.CANCELLED

    time.sleep(0.6)  # let any surviving child write
    size1 = marker.stat().st_size
    time.sleep(0.6)
    size2 = marker.stat().st_size
    assert size2 == size1  # child was terminated with the tree (not orphaned)


def test_secret_delivered_by_file_not_argv():
    secret = "s3cr3t-value-42"
    code = (
        "import os, hashlib\n"
        "path = os.environ['AEGIS_SECRET_TOKEN']\n"
        "val = open(path).read()\n"
        "print(hashlib.sha256(val.encode()).hexdigest())\n"
    )
    argv = [PY, "-c", code]
    r = runner().run(argv, secrets={"token": secret})
    assert r.ok
    assert r.lines[0] == hashlib.sha256(secret.encode()).hexdigest()
    assert secret not in " ".join(argv)  # secret never placed in argv


def test_workdir_and_secret_are_cleaned_up():
    r = runner().run([PY, "-c", "import os; print(os.getcwd())"], secrets={"token": "x"})
    workdir = r.lines[0]
    assert not os.path.exists(workdir)  # auto-created workdir (with secret files) removed


def test_minimal_env_does_not_leak_parent_vars(monkeypatch):
    monkeypatch.setenv("SUPER_SECRET_VAR", "leak-me")
    r = runner().run([PY, "-c", "import os; print('SUPER_SECRET_VAR' in os.environ)"])
    assert r.lines[0] == "False"


def test_start_error_for_missing_binary():
    r = runner().run(["this-binary-does-not-exist-xyzzy"])
    assert r.outcome == ProcessOutcome.START_ERROR


def test_verify_binary_checksum(tmp_path):
    p = tmp_path / "bin"
    p.write_bytes(b"hello world")
    good = hashlib.sha256(b"hello world").hexdigest()
    assert verify_binary(str(p), good) == good
    with pytest.raises(BinaryVerificationError):
        verify_binary(str(p), "0" * 64)
