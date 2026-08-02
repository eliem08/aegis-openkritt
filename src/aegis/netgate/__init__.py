"""Network-layer scope enforcement for outbound worker traffic (§2, §17).

Every worker that touches the network must do so through a gated client so that
each request — and each redirect hop and resolved IP — is checked against the
signed scope. See :func:`build_gated_client`.
"""

from .scope_transport import (
    ScopeEnforcingTransport,
    ScopeViolation,
    build_gated_client,
    is_blocked_ip,
)

__all__ = [
    "ScopeEnforcingTransport",
    "ScopeViolation",
    "build_gated_client",
    "is_blocked_ip",
]
