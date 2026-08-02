"""FastAPI application factory for the aegis control plane.

``create_app(config)`` builds a fully self-contained app (state on
``app.state``) so tests can spin up isolated instances. The app is thin: it
wires configuration, the signature verifier, the engagement store, one
middleware for correlation IDs, and the routers. All real policy logic lives in
``aegis.policy``.
"""

from __future__ import annotations

import logging

from fastapi import FastAPI

from aegis import __version__

from .config import ControlPlaneConfig
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


def create_app(config: ControlPlaneConfig | None = None) -> FastAPI:
    config = config or ControlPlaneConfig.from_env()
    verifier = config.build_verifier()

    app = FastAPI(
        title="aegis control plane",
        version=__version__,
        description=DESCRIPTION,
    )
    app.state.config = config
    app.state.verifier = verifier
    app.state.store = EngagementStore(
        verifier=verifier,
        require_signature=config.require_signature,
        max_audit_records=config.max_audit_records,
        max_decisions_cached=config.max_decisions_cached,
    )

    app.add_middleware(CorrelationIdMiddleware)
    for router in ALL_ROUTERS:
        app.include_router(router)

    @app.get("/", tags=["system"], summary="Service banner")
    def root() -> dict:
        return {"service": "aegis control plane", "version": __version__, "docs": "/docs"}

    _warn_on_insecure_config(config)
    return app


def _warn_on_insecure_config(config: ControlPlaneConfig) -> None:
    if not config.auth_enabled:
        logger.warning("AUTH DISABLED: every caller is treated as operator. Dev only.")
    elif not config.api_keys:
        logger.warning("auth is enabled but no API keys are configured: all requests will 401.")
    if config.require_signature and not config.signing_keys:
        logger.warning(
            "require_signature is on but no signing keys are configured: "
            "authorization registration and every active action will be rejected."
        )
