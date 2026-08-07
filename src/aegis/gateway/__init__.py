"""Scoped execution gateway — the single outbound-network policy authority (§2, §6).

Every target-facing request is authorised here against a network profile, the
signed scope, DNS pinning, private-IP denial, redirect revalidation, request
budgets, and audit. External tools get no unchecked egress.
"""

from .gateway import (
    GatewayBlocked,
    GatewayConfig,
    GatewayDecision,
    NetworkAuditEvent,
    NetworkProfile,
    ScopedExecutionGateway,
)

__all__ = [
    "GatewayBlocked",
    "GatewayConfig",
    "GatewayDecision",
    "NetworkAuditEvent",
    "NetworkProfile",
    "ScopedExecutionGateway",
]
