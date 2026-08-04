"""Browser executor (no real browser launched — driver is injected)."""

from __future__ import annotations

import pytest

from aegis.ai.browser_executor import BrowserExecutor, BrowserUnavailable
from aegis.ai.repro_agent import (
    ReproductionAgent, ReproError, ReproPlan, ReproTarget, evaluate_oracle,
)


class _Page:
    def __init__(self, status, dom, console=None, headers=None):
        self.status, self.dom = status, dom
        self.console = console or []
        self.headers = headers or {}


class _Driver:
    def __init__(self, page):
        self._page = page
        self.visited = []

    def visit(self, url, *, method="GET", headers=None, body=""):
        self.visited.append((url, method, headers))
        return self._page


def _plan(**over):
    base = dict(method="GET", path="xss?q=<script>", headers={}, body="",
                rationale="reflect a DOM XSS canary",
                success_check="body_contains", success_value="AEGIS_CANARY_FIRED")
    base.update(over)
    return ReproPlan(**base)


def test_dom_and_console_feed_the_oracle():
    # canary appears only in console (post-JS), not in raw HTTP body — browser catches it
    page = _Page(200, "<html>ok</html>", console=["AEGIS_CANARY_FIRED"])
    ex = BrowserExecutor(driver=_Driver(page))
    resp = ex.send(ReproTarget("http://127.0.0.1:8080"), _plan())
    assert "AEGIS_CANARY_FIRED" in resp.text
    assert evaluate_oracle(_plan(), resp) is True


def test_dom_content_is_returned_as_text():
    page = _Page(200, "<div>AEGIS_CANARY_FIRED in the DOM</div>")
    ex = BrowserExecutor(driver=_Driver(page), capture_console=False)
    resp = ex.send(ReproTarget("http://127.0.0.1:8080"), _plan())
    assert resp.status == 200 and "in the DOM" in resp.text


def test_refuses_non_local():
    ex = BrowserExecutor(driver=_Driver(_Page(200, "")))
    with pytest.raises(ReproError, match="non-local"):
        ex.send(ReproTarget("https://prod.example.com"), _plan())


def test_auth_header_is_applied():
    drv = _Driver(_Page(200, "<html></html>"))
    BrowserExecutor(driver=drv).send(
        ReproTarget("http://127.0.0.1:8080", auth_header="Bearer T"), _plan())
    _, _, headers = drv.visited[0]
    assert headers.get("Authorization") == "Bearer T"


def test_missing_playwright_raises_actionable_error():
    # no driver injected and playwright not installed -> actionable BrowserUnavailable
    ex = BrowserExecutor()
    try:
        import playwright  # noqa: F401
    except Exception:
        with pytest.raises(BrowserUnavailable, match="playwright"):
            ex.send(ReproTarget("http://127.0.0.1:8080"), _plan())


def test_agent_uses_browser_executor_end_to_end():
    class _Client:
        def complete_json(self, messages, **kwargs):
            return {"method": "GET", "path": "xss", "headers": {}, "body": "",
                    "rationale": "fire the canary", "success_check": "body_contains",
                    "success_value": "AEGIS_CANARY_FIRED"}
    page = _Page(200, "<html></html>", console=["AEGIS_CANARY_FIRED"])
    agent = ReproductionAgent(_Client(), BrowserExecutor(driver=_Driver(page)))
    from aegis.ai.agents.contracts import Hypothesis, VerificationProposal
    hyp = Hypothesis(weakness="CWE-79", title="DOM XSS", file_path="a.js", line=1,
                     rationale="r", confidence=0.7, entry_point="GET /xss?q=",
                     attacker="anon", impact="script executes", preconditions="none",
                     gating="none",
                     verification=VerificationProposal(method="harmless_canary",
                                                       expected_observation="canary in DOM",
                                                       maximum_requests=1))
    result = agent.reproduce(hyp, ReproTarget("http://127.0.0.1:8080"))
    assert result.triggered is True
