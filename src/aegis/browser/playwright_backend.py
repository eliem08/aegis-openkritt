"""Scope-enforced Playwright backend for registered controlled experiments."""

from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path
from urllib.parse import parse_qs, urljoin, urlsplit

from aegis.report.redact import redact

from .schema import StepType, WorkflowError


class PlaywrightControlledBrowserBackend:
    """Run declarative workflows in an ephemeral, route-intercepted Chromium context."""

    def __init__(self, gateway, *, credential_resolver, artifact_dir: str | Path) -> None:
        self.gateway = gateway
        self.credential_resolver = credential_resolver
        self.artifact_dir = Path(artifact_dir)

    def execute(self, experiment, *, inputs):
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as exc:
            raise RuntimeError("Playwright backend is not installed") from exc
        experiment.workflow.validate()
        self.artifact_dir.mkdir(parents=True, exist_ok=True)
        network = []
        messages = []
        canaries = {}
        with sync_playwright() as runtime:
            browser = runtime.chromium.launch(headless=True)
            context = browser.new_context(
                java_script_enabled=True,
                permissions=[],
                accept_downloads=False,
            )
            page = context.new_page()

            def route_request(route, request):
                decision = self.gateway.authorize(request.method, request.url)
                if not decision.allowed:
                    route.abort("blockedbyclient")
                    return
                network.append(request.url)
                route.continue_()

            page.route("**/*", route_request)
            page.add_init_script("""
                (() => {
                  window.__aegisMessages = [];
                  const original = window.postMessage.bind(window);
                  window.postMessage = (data, targetOrigin, transfer) => {
                    window.__aegisMessages.push({direction:'sent', targetOrigin,
                      sensitive: !!(data && typeof data === 'object' &&
                        ('token' in data || 'code' in data || 'credential' in data))});
                    return original(data, targetOrigin, transfer);
                  };
                  window.addEventListener('message', event => {
                    window.__aegisMessages.push({direction:'received', origin:event.origin,
                      sensitive: !!(event.data && typeof event.data === 'object' &&
                        ('token' in event.data || 'code' in event.data || 'credential' in event.data))});
                  });
                })();
            """)
            status = 0
            try:
                for step in experiment.workflow.steps:
                    params = step.params
                    if step.type is StepType.NAVIGATE:
                        target = self._render(str(params["url"]), inputs)
                        target = urljoin(experiment.base_url.rstrip("/") + "/", target)
                        response = page.goto(target, wait_until="networkidle", timeout=30_000)
                        status = response.status if response else 0
                    elif step.type is StepType.FILL:
                        value = params.get("value", "")
                        if params.get("credential_ref"):
                            value = self.credential_resolver(params["credential_ref"])
                            if isinstance(value, dict):
                                value = value.get(params.get("credential_field", "value"), "")
                        page.locator(params.get("selector", "")).fill(str(value))
                    elif step.type is StepType.CLICK:
                        page.locator(params.get("selector", "")).click()
                        page.wait_for_load_state("networkidle")
                    elif step.type is StepType.ASSERT_ELEMENT:
                        page.locator(params.get("selector", "")).wait_for(state="visible")
                    elif step.type is StepType.WAIT_FOR:
                        page.locator(params.get("selector", "")).wait_for()
                    elif step.type is StepType.CANARY_CHECK:
                        marker = self._render(str(params.get("canary", "")), inputs)
                        canaries[marker] = marker in page.content()
                messages = page.evaluate("window.__aegisMessages || []")
                html = redact(page.content()) or ""
                screenshot = page.screenshot(
                    full_page=True,
                    mask=[page.locator("body")],
                )
                final_url = page.url
                cookies = context.cookies()
                storage_digest = sha256(json.dumps(
                    [(row.get("name"), row.get("domain"), row.get("path")) for row in cookies],
                    sort_keys=True,
                ).encode()).hexdigest()
            finally:
                context.close()
                browser.close()
        html_bytes = html.encode("utf-8")
        html_digest = sha256(html_bytes).hexdigest()
        screenshot_digest = sha256(screenshot).hexdigest()
        html_path = self.artifact_dir / f"{experiment.experiment_id}-{html_digest[:12]}.html"
        shot_path = self.artifact_dir / f"{experiment.experiment_id}-{screenshot_digest[:12]}.png"
        html_path.write_bytes(html_bytes)
        shot_path.write_bytes(screenshot)
        fields = self._extract(
            experiment.field_extractors, final_url, html, messages, canaries,
            storage_digest, inputs,
        )
        from aegis.ai.jarvis.controlled_browser_executor import ControlledBrowserCapture
        return ControlledBrowserCapture(
            status, redact(final_url) or "", html_digest, screenshot_digest,
            (str(html_path), str(shot_path)), fields,
            tuple(f"network:{sha256(url.encode()).hexdigest()}" for url in network),
        )

    @staticmethod
    def _render(value, inputs):
        for key, replacement in inputs.items():
            value = value.replace("{" + key + "}", replacement)
        return value

    @classmethod
    def _extract(cls, extractors, final_url, html, messages, canaries, storage_digest, inputs):
        query = parse_qs(urlsplit(final_url).query)
        fields = {}
        for name, expression in extractors:
            kind, _, value = expression.partition(":")
            value = cls._render(value, inputs)
            if kind == "query":
                fields[name] = (query.get(value) or [""])[0]
            elif kind == "url_startswith":
                fields[name] = final_url.startswith(value)
            elif kind == "body_contains":
                fields[name] = value in html
            elif kind == "canary":
                fields[name] = bool(canaries.get(value))
            elif kind == "session_digest":
                fields[name] = storage_digest
            elif kind == "literal":
                fields[name] = value
            elif kind == "postmessage_sender":
                fields[name] = next((row.get("origin", "") for row in messages
                                     if row.get("direction") == "received"), "")
            elif kind == "postmessage_target":
                fields[name] = next((row.get("targetOrigin", "") for row in messages
                                     if row.get("direction") == "sent"), "")
            elif kind == "postmessage_sensitive":
                fields[name] = any(bool(row.get("sensitive")) for row in messages)
            elif kind == "input_digest":
                fields[name] = sha256(inputs.get(value, "").encode()).hexdigest()
            else:
                raise WorkflowError(f"unknown browser field extractor: {kind}")
        return fields


__all__ = ["PlaywrightControlledBrowserBackend"]
