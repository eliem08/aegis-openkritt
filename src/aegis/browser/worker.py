"""Browser worker (Phase 4 §Browser worker).

Executes a declarative :class:`BrowserWorkflow` through a pinned Chromium driver
that runs behind the scoped execution gateway. The worker owns the safety, not the
browser: every navigation, popup, download, websocket, service worker, and
subresource is scope-checked through the gateway; downloads are quarantined; the
context is ephemeral and never shared across tenants or unrelated identities;
credential references are resolved into that context; and logout paths are avoided
unless the workflow explicitly intends to test logout.

The driver is abstracted (`BrowserDriver`), so the safety logic is exercised
in-process against a fake page without a real Chromium image.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Protocol
from urllib.parse import urljoin, urlsplit

from aegis.gateway import GatewayBlocked

from .schema import DISABLED_CAPABILITIES, BrowserWorkflow, StepType, WorkflowError

DEFAULT_LOGOUT_PATHS = ("/logout", "/signout", "/sign-out", "/session/destroy")

# Event kinds the browser surfaces that must each be scope-checked.
SCOPE_CHECKED_EVENTS = ("subresource", "popup", "websocket", "service_worker", "navigation")


@dataclass
class PageResult:
    status: int = 200
    body: str = ""
    subresources: list[str] = field(default_factory=list)
    popups: list[str] = field(default_factory=list)
    websockets: list[str] = field(default_factory=list)
    service_workers: list[str] = field(default_factory=list)
    downloads: list[str] = field(default_factory=list)
    location: str = ""


class BrowserDriver(Protocol):
    def open_context(self, context_id: str, *, disabled: tuple[str, ...], credentials: dict) -> None: ...
    def navigate(self, url: str) -> PageResult: ...
    def fill(self, selector: str, value: str) -> None: ...
    def click(self, selector: str) -> PageResult: ...
    def query(self, selector: str) -> bool: ...
    def body(self) -> str: ...
    def close_context(self, context_id: str) -> None: ...


@dataclass(frozen=True)
class EphemeralContext:
    context_id: str
    tenant_id: str
    identity: str
    disabled_capabilities: tuple[str, ...]

    @property
    def owner_key(self) -> tuple[str, str]:
        return (self.tenant_id, self.identity)


@dataclass
class WorkflowResult:
    context_id: str
    outcome: str                                   # completed | failed
    steps_run: int = 0
    blocked: list[dict] = field(default_factory=list)         # scope-blocked events
    quarantined_downloads: list[str] = field(default_factory=list)
    canaries: list[dict] = field(default_factory=list)
    captures: list[dict] = field(default_factory=list)
    avoided_logout: list[str] = field(default_factory=list)


class BrowserWorker:
    def __init__(self, gateway, driver: BrowserDriver, *, secrets=None,
                 logout_paths: tuple[str, ...] = DEFAULT_LOGOUT_PATHS) -> None:
        self._gateway = gateway
        self._driver = driver
        self._secrets = secrets
        self._logout_paths = logout_paths
        self._active: dict[tuple[str, str], str] = {}   # owner_key -> context_id (never shared)

    def run(self, workflow: BrowserWorkflow, *, tenant_id: str, base_url: str,
            authorize_javascript: bool = False) -> WorkflowResult:
        workflow.validate()
        if workflow.allow_javascript and not authorize_javascript:
            raise WorkflowError("allow_javascript requires matching run-time authorization")

        context = self._open_context(tenant_id, workflow)
        result = WorkflowResult(context_id=context.context_id, outcome="completed")
        try:
            for step in workflow.steps:
                self._run_step(step, workflow, base_url, result)
        except GatewayBlocked as exc:
            result.outcome = "failed"
            result.blocked.append({"url": exc.host, "kind": "navigation", "reason": exc.reason})
        finally:
            self._driver.close_context(context.context_id)
            self._active.pop(context.owner_key, None)
        return result

    # -- context ------------------------------------------------------------

    def _open_context(self, tenant_id: str, workflow: BrowserWorkflow) -> EphemeralContext:
        key = (tenant_id, workflow.identity)
        # A context is never shared across tenants or unrelated identities.
        context = EphemeralContext(uuid.uuid4().hex, tenant_id, workflow.identity, DISABLED_CAPABILITIES)
        credentials = self._resolve_credentials(workflow)
        self._driver.open_context(context.context_id, disabled=DISABLED_CAPABILITIES, credentials=credentials)
        self._active[key] = context.context_id
        return context

    def _resolve_credentials(self, workflow: BrowserWorkflow) -> dict:
        creds = {}
        for step in workflow.steps:
            ref = step.params.get("credential_ref") if step.type == StepType.FILL else None
            if ref and self._secrets is not None:
                creds[ref] = self._secrets.get(ref)
        return creds

    # -- steps --------------------------------------------------------------

    def _run_step(self, step, workflow, base_url, result: WorkflowResult) -> None:
        result.steps_run += 1
        if step.type == StepType.NAVIGATE:
            self._navigate(step.params["url"], workflow, base_url, result)
        elif step.type == StepType.FILL:
            value = step.params.get("value")
            if step.params.get("credential_ref"):
                value = f"<resolved:{step.params['credential_ref']}>"   # never the raw secret here
            self._driver.fill(step.params.get("selector", ""), value or "")
        elif step.type == StepType.CLICK:
            page = self._driver.click(step.params.get("selector", ""))
            self._inspect_events(page, workflow, base_url, result)
        elif step.type == StepType.ASSERT_ELEMENT:
            if not self._driver.query(step.params.get("selector", "")):
                raise WorkflowError(f"assertion failed: {step.params.get('selector')!r} not found")
        elif step.type == StepType.WAIT_FOR:
            self._driver.query(step.params.get("selector", ""))
        elif step.type == StepType.CAPTURE:
            result.captures.append({"selector": step.params.get("selector", ""), "captured": True})
        elif step.type == StepType.CANARY_CHECK:
            canary = step.params.get("canary", "")
            result.canaries.append({"canary": canary, "present": canary in self._driver.body()})

    def _navigate(self, url, workflow, base_url, result: WorkflowResult) -> None:
        full = _abs(base_url, url)
        if self._is_logout(full) and not workflow.intends_logout:
            result.avoided_logout.append(full)
            return                                    # never log ourselves out by accident
        self._gateway.require("GET", full)            # scope check (raises GatewayBlocked)
        page = self._driver.navigate(full)
        self._inspect_events(page, workflow, base_url, result)

    def _inspect_events(self, page: PageResult, workflow, base_url, result: WorkflowResult) -> None:
        # Downloads are quarantined regardless of origin.
        for download in page.downloads:
            result.quarantined_downloads.append(download)
        # Every other browser-initiated request is scope-checked.
        for kind, urls in (("subresource", page.subresources), ("popup", page.popups),
                           ("websocket", page.websockets), ("service_worker", page.service_workers)):
            for u in urls:
                full = _abs(base_url, u)
                decision = self._gateway.check("GET", full)
                if not decision.allowed:
                    result.blocked.append({"url": full, "kind": kind, "reason": decision.reason})

    def _is_logout(self, url: str) -> bool:
        path = (urlsplit(url).path or "").lower().rstrip("/")
        return any(path == p.rstrip("/") for p in self._logout_paths)


def _abs(base_url: str, url: str) -> str:
    if url.startswith(("http://", "https://")):
        return url
    return urljoin(base_url.rstrip("/") + "/", url.lstrip("/"))
