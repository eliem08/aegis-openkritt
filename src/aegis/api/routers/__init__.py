"""API routers, aggregated for registration in ``create_app``."""

from . import approvals, audit, control, decisions, engagements, scans, system

ALL_ROUTERS = [
    system.router,
    engagements.router,
    decisions.router,
    approvals.router,
    control.router,
    audit.router,
    scans.router,
]

__all__ = ["ALL_ROUTERS"]
