"""Private out-of-band application security testing (Phase 4).

A tenant-scoped OAST control plane: authenticated sessions, secret material held
in the secrets service (never handed to the worker), interactions encrypted at
rest and matched to an outstanding authorized probe before they can be evidence,
with everything unmatched/cross-tenant/disabled quarantined.
"""

from .models import (
    DEFAULT_ALLOWED_PROTOCOLS,
    Interaction,
    MatchedInteraction,
    OastRegistration,
    OastSession,
    ProbeToken,
    Protocol,
    QuarantinedInteraction,
    QuarantineReason,
)
from .service import (
    PUBLIC_OAST_SERVERS,
    AuthenticationRequired,
    CrossTenantDenied,
    OastError,
    PrivateOastConfig,
    PrivateOastService,
    PublicOastRejected,
    SecretsService,
    SessionExpired,
    SessionNotFound,
)

__all__ = [
    "Protocol",
    "Interaction",
    "MatchedInteraction",
    "QuarantinedInteraction",
    "QuarantineReason",
    "OastSession",
    "OastRegistration",
    "ProbeToken",
    "DEFAULT_ALLOWED_PROTOCOLS",
    "PrivateOastService",
    "PrivateOastConfig",
    "SecretsService",
    "PUBLIC_OAST_SERVERS",
    "OastError",
    "AuthenticationRequired",
    "PublicOastRejected",
    "SessionNotFound",
    "SessionExpired",
    "CrossTenantDenied",
]
