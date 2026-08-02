import httpx
import pytest

from aegis.detect import (
    BolaDetector,
    DetectorContext,
    DetectorWorker,
    ExposedFileDetector,
    Identity,
    ObjectRef,
    OpenRedirectDetector,
    default_registry,
)
from aegis.model import AttackSurface, PlannedAction
from aegis.netgate import build_gated_client
from aegis.orchestrator import WorkerContext

PUBLIC = lambda h: ["93.184.216.34"]  # noqa: E731
SCOPE = ["api.example.test"]
USER_A = Identity("user_a", {"Authorization": "Bearer A"})
USER_B = Identity("user_b", {"Authorization": "Bearer B"})


def gated(handler) -> httpx.Client:
    return build_gated_client(SCOPE, inner=httpx.MockTransport(handler), resolver=PUBLIC)


def ctx(handler, **kw) -> DetectorContext:
    kw.setdefault("identities", [USER_A, USER_B])
    kw.setdefault("action", "authenticated_testing")
    return DetectorContext(base_url="https://api.example.test", client=gated(handler), **kw)


# --- BOLA / IDOR ---

def test_bola_detects_cross_account_read():
    def vulnerable(request):
        if request.url.path == "/users/1001":
            return httpx.Response(200, text='{"canary":"CANARY-1"}')  # served to anyone
        return httpx.Response(404)

    det = BolaDetector([ObjectRef("/users/1001", "user_a", "CANARY-1")])
    res = det.run(ctx(vulnerable))
    assert len(res.candidates) == 1
    assert res.candidates[0].cwe == "CWE-639"
    assert res.evidence[0].is_reproducible


def test_bola_no_finding_when_authorized():
    def safe(request):
        if request.url.path == "/users/1001":
            if request.headers.get("authorization") == "Bearer A":
                return httpx.Response(200, text='{"canary":"CANARY-1"}')
            return httpx.Response(403)
        return httpx.Response(404)

    det = BolaDetector([ObjectRef("/users/1001", "user_a", "CANARY-1")])
    assert det.run(ctx(safe)).candidates == []


def test_bola_requires_two_identities():
    det = BolaDetector([ObjectRef("/users/1001", "user_a", "CANARY-1")])
    assert not det.applicable(ctx(lambda r: httpx.Response(404), identities=[USER_A]))


# --- exposed files ---

def test_exposed_git_config_detected():
    def handler(request):
        if request.url.path == "/.git/config":
            return httpx.Response(200, text="[core]\n\trepositoryformatversion = 0\n")
        return httpx.Response(404)

    res = ExposedFileDetector().run(ctx(handler))
    assert len(res.candidates) == 1
    assert res.candidates[0].route == "/.git/config"


def test_no_false_positive_on_spa_200():
    # Everything returns a 200 SPA shell without the signature -> no finding.
    res = ExposedFileDetector().run(ctx(lambda r: httpx.Response(200, text="<html>app</html>")))
    assert res.candidates == []


# --- open redirect ---

def test_open_redirect_detected_without_following():
    def handler(request):
        if request.url.path == "/login" and "aegis-canary.example" in str(request.url):
            return httpx.Response(302, headers={"location": "https://aegis-canary.example/"})
        return httpx.Response(200)

    res = OpenRedirectDetector().run(ctx(handler))
    assert len(res.candidates) == 1
    assert res.candidates[0].cwe == "CWE-601"


def test_no_open_redirect_when_validated():
    def handler(request):
        # server ignores the param / stays same-origin
        return httpx.Response(302, headers={"location": "https://api.example.test/home"})

    assert OpenRedirectDetector().run(ctx(handler)).candidates == []


# --- worker integration ---

def test_detector_worker_produces_findings():
    def vulnerable(request):
        if request.url.path == "/users/1001":
            return httpx.Response(200, text='{"canary":"CANARY-1"}')
        return httpx.Response(404)

    worker = DetectorWorker(
        default_registry(),
        client_factory=lambda target: gated(vulnerable),
        identities=[USER_A, USER_B],
    )
    action = PlannedAction(
        target="api.example.test", action="authenticated_testing", worker="detector",
        params={"objects": [{"url": "/users/1001", "owner": "user_a", "canary": "CANARY-1"}]},
    )
    result = worker.run(action, WorkerContext(engagement_id="e", surface=AttackSurface()))
    assert any(c.cwe == "CWE-639" for c in result.candidates)


def test_per_request_gate_blocks_detector():
    # gate denies every request -> no candidates, no crash
    worker = DetectorWorker(
        default_registry(),
        client_factory=lambda target: gated(lambda r: httpx.Response(200, text='{"canary":"CANARY-1"}')),
        identities=[USER_A, USER_B],
        gate=lambda action, url: False,
    )
    action = PlannedAction(
        target="api.example.test", action="authenticated_testing", worker="detector",
        params={"objects": [{"url": "/users/1001", "owner": "user_a", "canary": "CANARY-1"}]},
    )
    result = worker.run(action, WorkerContext(engagement_id="e", surface=AttackSurface()))
    assert result.candidates == []
