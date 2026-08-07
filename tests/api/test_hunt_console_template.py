from pathlib import Path


def _template() -> str:
    root = Path(__file__).resolve().parents[2]
    return (root / "src" / "aegis" / "api" / "templates" / "hunt_console.html").read_text(
        encoding="utf-8"
    )


def test_hunt_console_is_self_contained_and_operator_focused():
    html = _template()
    assert "Aegis Jarvis — Mission Control" in html
    assert "Autonomous security research OS" in html
    assert "Human-supervised" in html
    assert "https://" not in html
    assert "http://" not in html


def test_hunt_console_wires_real_backend_controls():
    html = _template()
    for endpoint in (
        "/ui/autohunt-targets",
        "/ui/autohunt-jobs",
        "/ui/autohunt",
        "/ui/program-alerts",
        "/ui/program-monitor",
        "/ui/carpet/scan",
        "/ui/disclosed",
    ):
        assert endpoint in html


def test_hunt_console_keeps_evidence_semantics_visible():
    html = _template()
    for stage in (
        "candidate",
        "source supported",
        "runtime observed",
        "oracle passed",
        "locally reproduced",
        "independently verified",
        "human approved",
        "submission ready",
    ):
        assert stage in html
