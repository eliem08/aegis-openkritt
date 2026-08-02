"""Session-loss monitoring (Phase 4)."""

from __future__ import annotations

from aegis.monitor import SessionLossMonitor

A, B = "https://api.example.test", "https://app.example.test"


def monitor():
    m = SessionLossMonitor()
    m.capture(A, status=200, body="<html>Welcome alice <a>Logout</a></html>",
              marker_hints=("Logout", "alice"))
    return m


# --- preflight baseline ------------------------------------------------------

def test_baseline_captures_present_markers_only():
    m = SessionLossMonitor()
    base = m.capture(A, status=200, body="hello alice Logout", marker_hints=("Logout", "missing"))
    assert base.authenticated_markers == ("Logout",)   # only markers actually present


# --- healthy session ---------------------------------------------------------

def test_authenticated_response_is_not_lost():
    m = monitor()
    check = m.check(A, status=200, body="<html>Welcome alice <a>Logout</a></html>")
    assert not check.lost and not m.is_lost(A)


# --- loss detection ----------------------------------------------------------

def test_login_redirect_is_session_loss():
    m = monitor()
    check = m.check(A, status=302, location="https://api.example.test/login", body="")
    assert check.lost and "login" in check.reason and m.is_lost(A)


def test_401_is_session_loss():
    m = monitor()
    assert m.check(A, status=401, body="").lost


def test_missing_authenticated_marker_is_session_loss():
    m = monitor()
    check = m.check(A, status=200, body="<html>please create an account</html>")
    assert check.lost and "marker" in check.reason


def test_once_lost_a_session_stays_lost():
    m = monitor()
    m.check(A, status=401)
    later = m.check(A, status=200, body="Welcome alice Logout")   # even if it looks fine again
    assert later.lost


# --- cancellation is per-origin ---------------------------------------------

def test_loss_cancels_only_the_affected_origins_pending_work():
    m = monitor()
    m.capture(B, status=200, body="app dashboard", marker_hints=("dashboard",))
    m.register_pending(A, "task-a1")
    m.register_pending(A, "task-a2")
    m.register_pending(B, "task-b1")

    m.check(A, status=401)
    cancelled = m.on_loss_cancel(A)
    assert cancelled == {"task-a1", "task-a2"}
    # the unrelated origin B is untouched and still healthy
    assert not m.is_lost(B) and m.on_loss_cancel(B) == set()


def test_incomplete_coverage_lists_only_lost_origins():
    m = monitor()
    m.capture(B, status=200, body="ok", marker_hints=())
    m.check(A, status=403)
    m.check(B, status=200, body="ok")
    assert m.incomplete_coverage() == {A}
    assert m.lost_origins()[A]


def test_periodic_check_during_a_long_scan_catches_a_mid_scan_loss():
    m = monitor()
    assert not m.check(A, status=200, body="Welcome alice Logout").lost   # early: fine
    assert m.check(A, status=200, body="Session expired, please sign in").lost  # later: lost
