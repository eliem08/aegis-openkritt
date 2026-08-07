"""Browser-driven executor for the reproduction agent.

Many web bugs — DOM XSS, client-side redirects, anything whose impact is visible only
after JavaScript runs — cannot be proven with a raw HTTP request. The reproduction
literature explicitly recommends a real browser (Playwright/MCP) that intercepts
requests and validates via the DOM. This executor drives a browser and returns a
``ResponseView`` whose ``text`` is the *rendered* DOM plus any captured console output,
so the same deterministic oracle (body_contains a canary, etc.) proves post-JS impact.

Interface-compatible with ``HttpExecutor`` (``send(target, plan) -> ResponseView``), so
the agent uses it unchanged. Playwright is an optional dependency and the browser is
injectable, so tests never launch a browser. Local-only guard enforced here too.
"""

from __future__ import annotations

from .repro_agent import ReproError, ResponseView, is_local_target


class BrowserUnavailable(RuntimeError):
    """Playwright (or the injected driver) is not available."""


class BrowserExecutor:
    """Render the target in a browser and return the resulting DOM + console as text.

    ``driver`` is any object exposing ``visit(url, method, headers, body) -> RenderedPage``
    where RenderedPage has ``.status``, ``.dom`` and ``.console`` (list[str]). When no
    driver is injected, a Playwright-backed one is built lazily; if Playwright is not
    installed, ``send`` raises BrowserUnavailable so the caller can fall back to HTTP.
    """

    def __init__(self, *, driver=None, capture_console: bool = True):
        self._driver = driver
        self._capture_console = capture_console

    def send(self, target, plan) -> ResponseView:
        if not is_local_target(target.base_url):
            raise ReproError("browser executor refuses non-local target")
        driver = self._driver or _build_playwright_driver()
        url = target.base_url.rstrip("/") + "/" + plan.path.lstrip("/")
        headers = dict(plan.headers)
        if target.auth_header:
            headers.setdefault("Authorization", target.auth_header)
        page = driver.visit(url, method=plan.method.upper(), headers=headers,
                            body=plan.body or "")
        console = "\n".join(getattr(page, "console", []) or []) if self._capture_console else ""
        # oracle text = rendered DOM + console, so post-JS impact (DOM XSS canary firing,
        # a redirect target, an exfil marker logged) is visible to body_contains checks
        text = (getattr(page, "dom", "") or "")
        if console:
            text += "\n<!-- console -->\n" + console
        return ResponseView(status=getattr(page, "status", 0), text=text,
                            headers=getattr(page, "headers", {}) or {})


def _build_playwright_driver():
    try:
        from playwright.sync_api import sync_playwright  # noqa: F401
    except Exception as exc:                              # not installed
        raise BrowserUnavailable(
            "playwright is not installed; `pip install playwright && playwright install "
            "chromium`, or inject a driver / use HttpExecutor"
        ) from exc
    return _PlaywrightDriver()


class _PlaywrightDriver:                                   # pragma: no cover - needs a browser
    """Thin real-browser driver. Not exercised in tests (no browser in CI)."""

    def visit(self, url, *, method="GET", headers=None, body=""):
        from playwright.sync_api import sync_playwright

        class _Page:
            status = 0
            dom = ""
            console: list[str] = []
            headers: dict = {}

        page = _Page()
        page.console = []
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            try:
                ctx = browser.new_context(extra_http_headers=headers or {})
                tab = ctx.new_page()
                tab.on("console", lambda m: page.console.append(m.text))
                if method == "GET":
                    resp = tab.goto(url, wait_until="networkidle", timeout=30000)
                else:
                    resp = tab.request.fetch(url, method=method, headers=headers or {},
                                             data=body or None)
                page.status = resp.status if resp else 0
                try:
                    page.dom = tab.content()
                except Exception:
                    page.dom = ""
            finally:
                browser.close()
        return page
