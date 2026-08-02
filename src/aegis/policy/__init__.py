"""Deterministic policy & authorization core.

This subpackage is the safety layer the Master Operating Prompt calls its
"primary control": authorization gate (§4), consequence tiers (§5), scope
enforcement (§2), rate/spend budgets, kill switch (§8), and the single
composing engine that turns a proposed action into an auditable decision.
"""

from .authorization import (
    Authorization,
    AuthorizationValidator,
    DataHandling,
    Environment,
    RateLimits,
    TestIdentity,
)
from .budget import RateBudget, SpendBudget, TokenBucket
from .consequence import (
    ConsequenceClassifier,
    ConsequenceTier,
    TierPolicy,
)
from .decisions import (
    ActionRequest,
    PolicyDecision,
    Reason,
    ReasonCode,
    Verdict,
)
from .engine import PolicyConfig, PolicyEngine, approval_token_for_tier
from .killswitch import KillSwitch
from .scope import ScopeGuard, ScopeResult, normalize_host
from .signing import (
    Ed25519SignatureVerifier,
    Ed25519Signer,
    HmacSignatureVerifier,
    RejectAllVerifier,
    SignatureVerifier,
    canonical_bytes,
)

__all__ = [
    "Authorization",
    "AuthorizationValidator",
    "DataHandling",
    "Environment",
    "RateLimits",
    "TestIdentity",
    "RateBudget",
    "SpendBudget",
    "TokenBucket",
    "ConsequenceClassifier",
    "ConsequenceTier",
    "TierPolicy",
    "ActionRequest",
    "PolicyDecision",
    "Reason",
    "ReasonCode",
    "Verdict",
    "PolicyConfig",
    "PolicyEngine",
    "approval_token_for_tier",
    "KillSwitch",
    "ScopeGuard",
    "ScopeResult",
    "normalize_host",
    "HmacSignatureVerifier",
    "Ed25519SignatureVerifier",
    "Ed25519Signer",
    "RejectAllVerifier",
    "SignatureVerifier",
    "canonical_bytes",
]
