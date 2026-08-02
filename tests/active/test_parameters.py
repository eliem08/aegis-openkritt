"""Clean-room parameter discovery (Phase 3).

Driven against a deterministic fake target rather than a network, so the
algorithm — calibration, batch narrowing, individual verification — is exercised
in isolation: it tolerates dynamic content, rejects unstable targets, finds
seeded parameters with far fewer requests than one-per-name, and drops survivors
that do not reproduce on their own.
"""

from __future__ import annotations

import pytest

from aegis.active import (
    JSON,
    DiscoveryConfig,
    ParameterDiscovery,
    ProbeResponse,
    UnsupportedMethod,
)

BASE_BODY = "<html><body>welcome to the store</body></html>"
HEADERS = {"content-type": "text/html", "server": "nginx", "date": "now"}


class FakeTarget:
    """A synthetic endpoint with hidden parameters and configurable behavior."""

    def __init__(self, *, length_params=(), reflected=(), status_params=(),
                 reflect_if_paired=None, dynamic=False, unstable=False):
        self.length_params = set(length_params)      # shift body length (non-reflected)
        self.reflected = set(reflected)              # echo their value into the body
        self.status_params = set(status_params)      # cause a redirect (status shift)
        self.reflect_if_paired = dict(reflect_if_paired or {})  # echo only if sibling present
        self.dynamic = dynamic                       # body length varies each request
        self.unstable = unstable                     # status flips each request
        self.calls = 0

    def __call__(self, params: dict) -> ProbeResponse:
        self.calls += 1
        body = BASE_BODY
        status = 200
        redirect = ""
        if self.dynamic:
            # Deterministic but genuinely varying: word count and length differ
            # every request (like a CSRF token or timestamp would).
            body += " " + " ".join(f"n{i}" for i in range(self.calls * 7 % 40 + 5))
        if self.unstable:
            status = 200 if self.calls % 2 else 500       # flips -> unstable
        for name, value in params.items():
            if name in self.reflected:
                body += f"<echo>{value}</echo>"
            if name in self.reflect_if_paired and self.reflect_if_paired[name] in params:
                body += f"<echo>{value}</echo>"
            if name in self.length_params:
                body += "PADDING" * 40
            if name in self.status_params:
                status, redirect = 302, "https://api.example.test/login"
        return ProbeResponse(status=status, headers=HEADERS, body=body, redirect_location=redirect)


def junk(n: int, seed="p") -> list[str]:
    return [f"{seed}{i:04d}" for i in range(n)]


# --- calibration -------------------------------------------------------------

def test_clean_target_with_no_params_finds_nothing():
    target = FakeTarget()
    result = ParameterDiscovery(target).discover(junk(30))
    assert result.parameters == [] and result.complete and result.reason == ""


def test_unstable_target_is_rejected_as_incomplete():
    target = FakeTarget(unstable=True, reflected=["debug"])
    result = ParameterDiscovery(target).discover(["debug", *junk(20)])
    assert not result.complete and result.reason == "unstable_target"
    assert result.parameters == []                    # never a clean result
    assert "status" not in result.stable_features


def test_calibration_tolerates_dynamic_content():
    # Body length changes every request, but status/headers are stable and the
    # seeded parameter reflects — so it is still found, and length is disabled.
    target = FakeTarget(dynamic=True, reflected=["callback"])
    result = ParameterDiscovery(target).discover(["callback", *junk(20)])
    assert result.complete and result.names == ["callback"]
    assert "status" in result.stable_features
    assert "length_bucket" not in result.stable_features and "words" not in result.stable_features


# --- detection paths ---------------------------------------------------------

def test_reflected_parameter_is_found_and_flagged():
    target = FakeTarget(reflected=["redirect_to"])
    result = ParameterDiscovery(target).discover([*junk(20), "redirect_to"])
    found = {p.name: p for p in result.parameters}
    assert "redirect_to" in found
    assert found["redirect_to"].reflected and found["redirect_to"].evidence == "reflection"


def test_non_reflected_length_parameter_is_found_by_feature_shift():
    target = FakeTarget(length_params=["verbose"])
    result = ParameterDiscovery(target).discover([*junk(20), "verbose"])
    found = {p.name: p for p in result.parameters}
    assert "verbose" in found and not found["verbose"].reflected
    assert found["verbose"].evidence in ("length_bucket", "words", "lines")


def test_status_changing_parameter_is_found():
    target = FakeTarget(status_params=["admin"])
    result = ParameterDiscovery(target).discover([*junk(20), "admin"])
    found = {p.name: p for p in result.parameters}
    assert "admin" in found and found["admin"].evidence in ("status", "redirect")


# --- batch narrowing efficiency ----------------------------------------------

def test_batch_narrowing_uses_far_fewer_requests_than_one_per_name():
    candidates = [*junk(100), "hidden_a", "hidden_b"]
    target = FakeTarget(length_params=["hidden_a"], reflected=["hidden_b"])
    result = ParameterDiscovery(target).discover(candidates)

    assert set(result.names) == {"hidden_a", "hidden_b"}
    naive = len(candidates)                                   # one request per name
    assert result.requests < naive // 2                       # materially fewer
    assert result.complete


def test_two_parameters_in_the_same_batch_are_both_isolated():
    # Two non-reflected params inside one 25-wide batch force real bisection.
    batch = [f"b{i:02d}" for i in range(25)]
    batch[3], batch[20] = "alpha", "omega"
    target = FakeTarget(length_params=["alpha", "omega"])
    result = ParameterDiscovery(target, DiscoveryConfig(batch_size=25)).discover(batch)
    assert set(result.names) == {"alpha", "omega"}


# --- individual verification -------------------------------------------------

def test_survivor_that_does_not_reproduce_alone_is_dropped():
    # 'ghost' only reflects when 'partner' is also present. It survives the batch
    # but fails individual verification, so it must not be reported. 'real' does
    # reproduce and must be kept.
    target = FakeTarget(reflected=["real"], reflect_if_paired={"ghost": "partner"})
    result = ParameterDiscovery(target).discover(["ghost", "partner", "real", *junk(10)])
    assert "real" in result.names
    assert "ghost" not in result.names                # candidate != verified


# --- caps --------------------------------------------------------------------

def test_candidate_cap_truncates_and_reports_incomplete():
    target = FakeTarget(reflected=["kept"])
    cfg = DiscoveryConfig(max_candidates=10)
    result = ParameterDiscovery(target, cfg).discover(["kept", *junk(50)])
    assert not result.complete and result.reason == "candidate_cap"


def test_request_budget_stops_and_reports_incomplete():
    target = FakeTarget(length_params=["deep"])
    cfg = DiscoveryConfig(max_requests=6, calibration_rounds=4)
    result = ParameterDiscovery(target, cfg).discover(junk(200))
    assert not result.complete and result.reason == "request_budget"
    assert result.requests <= 8                       # stopped promptly


def test_target_that_echoes_everything_is_treated_as_unstable():
    # Every candidate reflects -> more anomalies than the cap allows.
    class EchoAll:
        calls = 0

        def __call__(self, params):
            EchoAll.calls += 1
            echoed = "".join(f"<e>{v}</e>" for v in params.values())
            return ProbeResponse(status=200, headers=HEADERS, body=BASE_BODY + echoed)

    cfg = DiscoveryConfig(max_anomalies=10, batch_size=25)
    result = ParameterDiscovery(EchoAll(), cfg).discover(junk(60))
    assert not result.complete and result.reason == "too_many_anomalies"


# --- capability / authorization ----------------------------------------------

def test_method_not_permitted_is_refused_at_construction():
    with pytest.raises(UnsupportedMethod):
        ParameterDiscovery(FakeTarget(), DiscoveryConfig(method="POST", permitted_methods=("GET",)))


def test_content_type_must_be_authorized():
    with pytest.raises(UnsupportedMethod):
        ParameterDiscovery(FakeTarget(), DiscoveryConfig(
            method="POST", permitted_methods=("POST",), content_type=JSON,
            permitted_content_types=(),
        ))
    # permitted combination constructs fine
    ParameterDiscovery(FakeTarget(), DiscoveryConfig(
        method="POST", permitted_methods=("POST",), content_type=JSON,
        permitted_content_types=(JSON,),
    ))
