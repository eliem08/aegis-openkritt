"""Guarded browser workflows (Phase 4).

Declarative schema (no arbitrary JS, credential references only), and a worker
that scope-checks every browser request through the real gateway, quarantines
downloads, keeps capabilities disabled, isolates ephemeral contexts, and avoids
logout paths.
"""

from __future__ import annotations

import pytest

from aegis.browser import (
    DISABLED_CAPABILITIES,
    BrowserWorker,
    BrowserWorkflow,
    PageResult,
    StepType,
    WorkflowError,
    WorkflowStep,
    parse_workflow,
)
from aegis.gateway import GatewayConfig, NetworkProfile, ScopedExecutionGateway
from aegis.policy.scope import ScopeGuard

HOST = "app.example.test"
BASE = f"https://{HOST}"
RESOLVER = lambda h: ["93.184.216.34"]


def gateway(scope=(HOST,)):
    return ScopedExecutionGateway(
        GatewayConfig(profile=NetworkProfile.TARGET_OBSERVATION, scope=ScopeGuard(list(scope))),
        resolver=RESOLVER)


class FakeDriver:
    """A fake browser: returns configured page events per navigated URL."""

    def __init__(self, pages=None, body="<html>dashboard CANARY-7</html>"):
        self.pages = pages or {}
        self._body = body
        self.opened = []
        self.closed = []
        self.filled = []

    def open_context(self, context_id, *, disabled, credentials):
        self.opened.append((context_id, disabled, credentials))

    def navigate(self, url):
        return self.pages.get(url, PageResult(status=200, body=self._body))

    def fill(self, selector, value):
        self.filled.append((selector, value))

    def click(self, selector):
        return PageResult(status=200, body=self._body)

    def query(self, selector):
        return True

    def body(self):
        return self._body

    def close_context(self, context_id):
        self.closed.append(context_id)


def nav(url):
    return WorkflowStep(StepType.NAVIGATE, {"url": url})


def workflow(*steps, identity="alice", **kw):
    return BrowserWorkflow(steps=tuple(steps), identity=identity, **kw)


# --- schema validation -------------------------------------------------------

def test_arbitrary_javascript_is_forbidden_by_default():
    with pytest.raises(WorkflowError):
        parse_workflow({"identity": "alice", "steps": [{"type": "eval"}]})


def test_fill_requires_a_credential_reference_not_a_raw_secret():
    bad = workflow(WorkflowStep(StepType.FILL, {"selector": "#pw", "value": "AKIAIOSFODNN7EXAMPLE"}))
    with pytest.raises(WorkflowError):
        bad.validate()
    ok = workflow(WorkflowStep(StepType.FILL, {"selector": "#pw", "credential_ref": "vault://app/pw"}))
    ok.validate()   # references are fine


def test_workflow_must_declare_an_identity():
    with pytest.raises(WorkflowError):
        workflow(nav("/x"), identity="").validate()


def test_non_secret_fill_value_is_allowed():
    workflow(WorkflowStep(StepType.FILL, {"selector": "#q", "value": "shoes"})).validate()


# --- scope checking ----------------------------------------------------------

def test_navigation_is_scope_checked():
    worker = BrowserWorker(gateway(), FakeDriver())
    result = worker.run(workflow(nav("/dashboard")), tenant_id="t", base_url=BASE)
    assert result.outcome == "completed" and result.steps_run == 1


def test_out_of_scope_navigation_is_blocked():
    worker = BrowserWorker(gateway(scope=("other.example.test",)), FakeDriver())
    result = worker.run(workflow(nav("https://app.example.test/x")), tenant_id="t", base_url=BASE)
    assert result.outcome == "failed"
    assert result.blocked and result.blocked[0]["kind"] == "navigation"


def test_out_of_scope_subresources_popups_and_websockets_are_blocked():
    page = PageResult(
        body="ok",
        subresources=["https://cdn.evil.test/x.js", "https://app.example.test/app.js"],
        popups=["https://ads.evil.test/popup"],
        websockets=["wss://socket.evil.test/ws"])
    driver = FakeDriver(pages={f"{BASE}/home": page})
    worker = BrowserWorker(gateway(), driver)
    result = worker.run(workflow(nav("/home")), tenant_id="t", base_url=BASE)

    blocked = {(b["kind"], b["url"]) for b in result.blocked}
    assert ("subresource", "https://cdn.evil.test/x.js") in blocked
    assert ("popup", "https://ads.evil.test/popup") in blocked
    assert ("websocket", "wss://socket.evil.test/ws") in blocked
    # the in-scope subresource is not blocked
    assert not any(b["url"] == "https://app.example.test/app.js" for b in result.blocked)


def test_downloads_are_always_quarantined():
    page = PageResult(body="ok", downloads=["https://app.example.test/report.pdf"])
    worker = BrowserWorker(gateway(), FakeDriver(pages={f"{BASE}/files": page}))
    result = worker.run(workflow(nav("/files")), tenant_id="t", base_url=BASE)
    assert result.quarantined_downloads == ["https://app.example.test/report.pdf"]


# --- capabilities + context isolation ---------------------------------------

def test_dangerous_capabilities_are_disabled_in_the_context():
    driver = FakeDriver()
    BrowserWorker(gateway(), driver).run(workflow(nav("/x")), tenant_id="t", base_url=BASE)
    _cid, disabled, _creds = driver.opened[0]
    for capability in ("clipboard", "filesystem", "camera", "microphone", "geolocation", "extensions"):
        assert capability in disabled
    assert set(DISABLED_CAPABILITIES) <= set(disabled)


def test_contexts_are_ephemeral_and_closed():
    driver = FakeDriver()
    result = BrowserWorker(gateway(), driver).run(workflow(nav("/x")), tenant_id="t", base_url=BASE)
    assert driver.closed == [result.context_id]        # torn down after the run


def test_contexts_are_never_shared_across_tenants_or_identities():
    driver = FakeDriver()
    worker = BrowserWorker(gateway(), driver)
    r1 = worker.run(workflow(nav("/x"), identity="alice"), tenant_id="tenant-a", base_url=BASE)
    r2 = worker.run(workflow(nav("/x"), identity="alice"), tenant_id="tenant-b", base_url=BASE)
    r3 = worker.run(workflow(nav("/x"), identity="bob"), tenant_id="tenant-a", base_url=BASE)
    assert len({r1.context_id, r2.context_id, r3.context_id}) == 3


def test_credential_references_resolve_into_the_context_never_raw():
    class Secrets:
        def get(self, ref):
            return {"password": "hunter2"}

    driver = FakeDriver()
    worker = BrowserWorker(gateway(), driver, secrets=Secrets())
    wf = workflow(WorkflowStep(StepType.FILL, {"selector": "#pw", "credential_ref": "vault://app/pw"}))
    worker.run(wf, tenant_id="t", base_url=BASE)
    # the raw secret never appears in what was typed into the page
    assert all("hunter2" not in str(v) for _sel, v in driver.filled)


# --- logout avoidance --------------------------------------------------------

def test_logout_paths_are_avoided_by_default():
    driver = FakeDriver()
    worker = BrowserWorker(gateway(), driver)
    result = worker.run(workflow(nav("/logout")), tenant_id="t", base_url=BASE)
    assert result.avoided_logout == [f"{BASE}/logout"]


def test_logout_is_visited_when_the_workflow_intends_to_test_it():
    driver = FakeDriver()
    worker = BrowserWorker(gateway(), driver)
    result = worker.run(workflow(nav("/logout"), intends_logout=True), tenant_id="t", base_url=BASE)
    assert result.avoided_logout == []


# --- canary check ------------------------------------------------------------

def test_canary_check_confirms_a_synthetic_marker():
    worker = BrowserWorker(gateway(), FakeDriver(body="page with CANARY-7 present"))
    wf = workflow(nav("/x"), WorkflowStep(StepType.CANARY_CHECK, {"canary": "CANARY-7"}))
    result = worker.run(wf, tenant_id="t", base_url=BASE)
    assert result.canaries == [{"canary": "CANARY-7", "present": True}]


def test_allow_javascript_needs_runtime_authorization():
    wf = BrowserWorkflow(steps=(nav("/x"),), identity="alice", allow_javascript=True)
    worker = BrowserWorker(gateway(), FakeDriver())
    with pytest.raises(WorkflowError):
        worker.run(wf, tenant_id="t", base_url=BASE)                       # not authorized
    worker.run(wf, tenant_id="t", base_url=BASE, authorize_javascript=True)  # ok
