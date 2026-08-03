"""Production-only FastAPI factory."""

from __future__ import annotations

from aegis.api.app import create_app

from .config import ProductionSettings
from .readiness import require_production_deployment


def create_production_app(settings: ProductionSettings | None = None):
    settings = settings or ProductionSettings.from_env()
    require_production_deployment(settings)
    coordinator = settings.build_coordinator()
    app = create_app(settings.control)
    app.state.coordinator = coordinator
    app.state.production_settings = settings
    return app
