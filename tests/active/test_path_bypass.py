"""Path-normalization allowlist-bypass detection (report-corpus driven)."""

from __future__ import annotations

from aegis.active import analyze_path_normalization, normalization_variants


class FakeGate:
    """A gated route (403) with configured leaky normalization variants."""

    def __init__(self, gated: str, leaky: dict[str, int] | None = None):
        self.gated = gated
        self.leaky = dict(leaky or {})

    def __call__(self, path: str) -> int:
        if path in self.leaky:
            return self.leaky[path]
        if path == self.gated:
            return 403
        return 403          # the gate holds on every other (normalized) variant


# --- bypass detection --------------------------------------------------------

def test_dot_segment_bypass_is_detected():
    # /metrics -> 403, /./metrics -> 200 (the IP-allowlist report)
    gate = FakeGate("/metrics", {"/./metrics": 200})
    findings = analyze_path_normalization(gate, "/metrics")
    assert any(f.variant == "/./metrics" and f.confidence >= 0.9 for f in findings)


def test_reaching_the_app_auth_layer_is_a_partial_bypass():
    # /api/admin -> 403 (allowlist), /api/./admin -> 401 (reached the app's auth)
    gate = FakeGate("/api/admin", {"/api/./admin": 401})
    findings = analyze_path_normalization(gate, "/api/admin")
    bypass = [f for f in findings if f.variant == "/api/./admin"]
    assert bypass and 0.5 < bypass[0].confidence < 0.9


def test_a_gate_that_normalizes_first_has_no_bypass():
    gate = FakeGate("/metrics", leaky={})     # every variant still returns 403
    assert analyze_path_normalization(gate, "/metrics") == []


def test_ungated_route_is_not_probed_for_bypass():
    # A route that returns 200 for everyone has no allowlist to bypass.
    gate = FakeGate("/public")
    gate.leaky = {}
    open_probe = lambda p: 200
    assert analyze_path_normalization(open_probe, "/public") == []


def test_absent_variant_is_not_a_bypass():
    gate = FakeGate("/metrics", {"/metrics/": 404})
    assert analyze_path_normalization(gate, "/metrics") == []


# --- variant generation ------------------------------------------------------

def test_variants_include_the_known_bypass_forms():
    v = set(normalization_variants("/metrics"))
    assert {"/metrics/", "/./metrics", "/metrics/.", "/metrics%2f"} <= v
    assert "/metrics" not in v            # never re-probes the baseline itself


def test_nested_path_gets_a_mid_path_dot_segment():
    assert "/api/./admin" in normalization_variants("/api/admin")
