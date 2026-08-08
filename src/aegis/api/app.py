"""FastAPI application factory for the aegis control plane.

``create_app(config)`` builds a fully self-contained app (state on
``app.state``) so tests can spin up isolated instances. The app is thin: it
wires configuration, the signature verifier, the engagement store, one
middleware for correlation IDs, and the routers. All real policy logic lives in
``aegis.policy``.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse

from aegis import __version__

from .config import ControlPlaneConfig, Role
from .observability import CorrelationIdMiddleware
from .routers import ALL_ROUTERS
from .store import EngagementStore

logger = logging.getLogger("aegis.api")

DESCRIPTION = """
Control plane for the Autonomous Exposure-to-Fix Agent.

It is the authenticated front door to the deterministic policy core: register a
signed **authorization** to open an engagement, then request **decisions** for
proposed actions, grant **approvals**, read the **audit** trail, and fire the
**kill switch**. Every decision is made by code in `aegis.policy`, not by a
model — this API only transports requests to that gate.

**Roles:** `agent` may request decisions and read status; `operator` may also
register/close engagements, grant approvals, and control the kill switch.
""".strip()

_MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def create_app(config: ControlPlaneConfig | None = None) -> FastAPI:
    if config is None:
        # real boot (no explicit config): load a local .env so credentials/config are picked up
        # before reading the environment. Tests that pass an explicit config are unaffected.
        from aegis.env import load_dotenv
        load_dotenv()
    config = config or ControlPlaneConfig.from_env()
    verifier = config.build_verifier()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # auto-start a hunt on boot if AEGIS_AUTOSTART=1 — launching the service becomes the
        # whole pipeline (rank -> hunt -> dashboard), so the operator just watches + submits.
        try:
            from aegis.ai.autostart import maybe_autostart
            maybe_autostart(app)
        except Exception:
            logger.exception("autostart setup failed")
        yield
        repo = getattr(app.state, "repository", None)
        if repo is not None and hasattr(repo, "close"):
            repo.close()  # close DB connections / pool on shutdown

    app = FastAPI(
        title="aegis control plane",
        version=__version__,
        description=DESCRIPTION,
        lifespan=lifespan,
    )
    app.state.config = config
    app.state.verifier = verifier
    app.state.repository = config.build_repository()
    app.state.adapters = _default_adapters()
    from aegis.observ import Telemetry

    app.state.telemetry = Telemetry()      # pseudonymous, redacting facade for hot paths
    from aegis.learn import OutcomeStore, SubmissionLedger

    app.state.outcomes = OutcomeStore(config.learn_db_path)  # learning loop (in-memory unless set)
    app.state.submissions = SubmissionLedger(config.learn_db_path)  # report -> finding links
    app.state.store = EngagementStore(
        verifier=verifier,
        require_signature=config.require_signature,
        max_audit_records=config.max_audit_records,
        max_decisions_cached=config.max_decisions_cached,
        repository=app.state.repository,
    )

    @app.middleware("http")
    async def protect_state_changing_ui(request, call_next):
        """Require an operator API key for every mutating ``/ui/*`` action.

        The UI is an operator cockpit, not an alternate unauthenticated control plane. Read-only
        dashboard GETs remain available, while starting/stopping hunts, scans, refreshes and
        validation jobs use the same bearer-token authentication as the rest of the API.
        """
        if request.url.path.startswith("/ui/") and request.method.upper() in _MUTATING_METHODS:
            from .security import authenticate_authorization_header

            try:
                principal = authenticate_authorization_header(
                    request, request.headers.get("authorization")
                )
            except HTTPException as exc:
                return JSONResponse(
                    status_code=exc.status_code,
                    content={"detail": exc.detail},
                    headers=exc.headers or {},
                )
            if principal.role != Role.OPERATOR:
                return JSONResponse(
                    status_code=403,
                    content={"detail": "operator role required for state-changing UI actions"},
                )
        return await call_next(request)

    app.add_middleware(CorrelationIdMiddleware)
    for router in ALL_ROUTERS:
        app.include_router(router)

    @app.get("/", tags=["system"], summary="Service banner")
    def root() -> dict:
        return {"service": "aegis control plane", "version": __version__, "docs": "/docs"}

    _warn_on_insecure_config(config)
    return app


def _default_adapters() -> dict:
    """The adapter registry available to scans.

    The five Phase 2 discovery adapters are registered alongside the fake one.
    They are constructed with their declared (as yet unpinned) digests, so a scan
    may reference them but they refuse to execute until a release checksum is
    pinned — fail closed rather than run an unverified binary.
    """
    from aegis.adapters import DalfoxAdapter, FakeDiscoveryAdapter, discovery_adapters

    fake = FakeDiscoveryAdapter()
    registry = {fake.manifest.name: fake}
    registry.update(discovery_adapters())
    # Dalfox registers here too; like the discovery adapters it fails closed until
    # a release digest is pinned. (Nuclei needs a signed template manifest, so it
    # is constructed per-engagement, not in this default registry.)
    dalfox = DalfoxAdapter()
    registry[dalfox.manifest.name] = dalfox
    return registry


def _warn_on_insecure_config(config: ControlPlaneConfig) -> None:
    if not config.auth_enabled:
        logger.warning("AUTH DISABLED: every caller is treated as operator. Dev only.")
    elif not config.api_keys:
        logger.warning("auth is enabled but no API keys are configured: all requests will 401.")
    if config.require_signature and not (config.signing_keys or config.signing_public_keys):
        logger.warning(
            "require_signature is on but no signing keys (HMAC or Ed25519) are "
            "configured: authorization registration and every active action will be rejected."
        )
