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
    pool = getattr(app.state.repository, "_pool", None)
    if pool is None:
        raise RuntimeError("production learning storage requires the PostgreSQL repository")
    from .postgres_learning import PostgresOutcomeStore, PostgresSubmissionLedger

    app.state.outcomes.close()
    app.state.submissions.close()
    app.state.outcomes = PostgresOutcomeStore(pool)
    app.state.submissions = PostgresSubmissionLedger(pool)
    app.state.coordinator = coordinator
    app.state.production_settings = settings
    return app
