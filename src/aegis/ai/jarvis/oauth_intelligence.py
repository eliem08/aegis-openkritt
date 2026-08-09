"""OAuth, browser-message, recovery, and session invalidation reasoning."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from hashlib import sha256


class AuthWorkflowOutcome(str, Enum):
    VIOLATION = "violation"
    CONSISTENT = "consistent"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True, slots=True)
class OAuthClientPolicy:
    client_id: str
    redirect_uris: tuple[str, ...]
    require_state: bool = True
    require_nonce: bool = False
    require_pkce: bool = True
    allowed_postmessage_origins: tuple[str, ...] = ()
    evidence: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class OAuthFlowObservation:
    flow_id: str
    policy: OAuthClientPolicy
    supplied_redirect_uri: str
    authorization_accepted: bool
    state_sent_digest: str = ""
    state_returned_digest: str = ""
    nonce_sent_digest: str = ""
    nonce_returned_digest: str = ""
    pkce_challenge_digest: str = ""
    pkce_method: str = ""
    postmessage_sender_origin: str = ""
    postmessage_target_origin: str = ""
    postmessage_sensitive_payload: bool = False
    synthetic_account: bool = False
    authorized: bool = False
    evidence: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class RecoveryObservation:
    observation_id: str
    token_digest: str
    first_use_succeeded: bool
    reuse_succeeded: bool
    old_session_usable_after_reset: bool
    synthetic_account: bool = False
    authorized: bool = False
    evidence: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class SessionInvalidationObservation:
    observation_id: str
    session_digest: str
    event: str
    usable_before: bool
    usable_after: bool
    synthetic_account: bool = False
    authorized: bool = False
    evidence: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class AuthWorkflowVerdict:
    verdict_id: str
    check: str
    outcome: AuthWorkflowOutcome
    reason: str
    confidence: float
    evidence: tuple[str, ...]


class OAuthTrustGraphAgent:
    def analyze_flow(self, row: OAuthFlowObservation) -> tuple[AuthWorkflowVerdict, ...]:
        if not row.authorized or not row.synthetic_account or not row.policy.evidence:
            return (self._verdict(row.flow_id, "prerequisites",
                                  AuthWorkflowOutcome.INCONCLUSIVE,
                                  "flow requires authorized synthetic account and policy evidence",
                                  0.0, row.evidence),)
        checks = []
        redirect_bad = (row.authorization_accepted
                        and row.supplied_redirect_uri not in row.policy.redirect_uris)
        checks.append(self._verdict(
            row.flow_id, "redirect_uri",
            AuthWorkflowOutcome.VIOLATION if redirect_bad else AuthWorkflowOutcome.CONSISTENT,
            "unregistered redirect URI was accepted" if redirect_bad
            else "redirect URI matched explicit registration policy", 0.97,
            (*row.policy.evidence, *row.evidence),
        ))
        if row.policy.require_state:
            state_bad = row.authorization_accepted and (
                not row.state_sent_digest or row.state_sent_digest != row.state_returned_digest
            )
            checks.append(self._verdict(
                row.flow_id, "state",
                AuthWorkflowOutcome.VIOLATION if state_bad else AuthWorkflowOutcome.CONSISTENT,
                "authorization completed without a matching state binding" if state_bad
                else "state was present and bound to the flow", 0.95, row.evidence,
            ))
        if row.policy.require_nonce:
            nonce_bad = row.authorization_accepted and (
                not row.nonce_sent_digest or row.nonce_sent_digest != row.nonce_returned_digest
            )
            checks.append(self._verdict(
                row.flow_id, "nonce",
                AuthWorkflowOutcome.VIOLATION if nonce_bad else AuthWorkflowOutcome.CONSISTENT,
                "OIDC flow completed without a matching nonce" if nonce_bad
                else "nonce was bound to the returned identity token", 0.94, row.evidence,
            ))
        if row.policy.require_pkce:
            pkce_bad = row.authorization_accepted and (
                not row.pkce_challenge_digest or row.pkce_method.casefold() != "s256"
            )
            checks.append(self._verdict(
                row.flow_id, "pkce",
                AuthWorkflowOutcome.VIOLATION if pkce_bad else AuthWorkflowOutcome.CONSISTENT,
                "authorization completed without required S256 PKCE" if pkce_bad
                else "S256 PKCE was present", 0.95, row.evidence,
            ))
        if row.postmessage_sensitive_payload:
            origin_bad = (
                row.postmessage_target_origin == "*"
                or row.postmessage_sender_origin not in row.policy.allowed_postmessage_origins
            )
            checks.append(self._verdict(
                row.flow_id, "postmessage_origin",
                AuthWorkflowOutcome.VIOLATION if origin_bad else AuthWorkflowOutcome.CONSISTENT,
                "sensitive OAuth message crossed an untrusted or wildcard origin" if origin_bad
                else "message sender and target were explicitly trusted", 0.93, row.evidence,
            ))
        return tuple(checks)

    def analyze_recovery(self, row: RecoveryObservation) -> tuple[AuthWorkflowVerdict, ...]:
        if not row.authorized or not row.synthetic_account or not row.token_digest:
            return (self._verdict(row.observation_id, "recovery_prerequisites",
                                  AuthWorkflowOutcome.INCONCLUSIVE,
                                  "recovery checks require an authorized synthetic token", 0.0,
                                  row.evidence),)
        return (
            self._verdict(row.observation_id, "recovery_token_reuse",
                          AuthWorkflowOutcome.VIOLATION if row.reuse_succeeded
                          else AuthWorkflowOutcome.CONSISTENT,
                          "used recovery token remained reusable" if row.reuse_succeeded
                          else "used recovery token was invalidated", 0.97, row.evidence),
            self._verdict(row.observation_id, "reset_session_invalidation",
                          AuthWorkflowOutcome.VIOLATION if row.old_session_usable_after_reset
                          else AuthWorkflowOutcome.CONSISTENT,
                          "old session remained usable after password reset"
                          if row.old_session_usable_after_reset
                          else "old session was invalidated after reset", 0.94, row.evidence),
        )

    def analyze_session(self, row: SessionInvalidationObservation) -> AuthWorkflowVerdict:
        if not row.authorized or not row.synthetic_account or not row.session_digest:
            return self._verdict(row.observation_id, "session_prerequisites",
                                 AuthWorkflowOutcome.INCONCLUSIVE,
                                 "session check requires an authorized synthetic session", 0.0,
                                 row.evidence)
        violation = row.usable_before and row.usable_after
        return self._verdict(
            row.observation_id, "session_invalidation",
            AuthWorkflowOutcome.VIOLATION if violation else AuthWorkflowOutcome.CONSISTENT,
            f"session remained usable after {row.event}" if violation
            else f"session was invalidated after {row.event}", 0.95, row.evidence,
        )

    @staticmethod
    def _verdict(base, check, outcome, reason, confidence, evidence) -> AuthWorkflowVerdict:
        verdict_id = "auth-workflow:" + sha256(f"{base}\x1f{check}".encode()).hexdigest()[:20]
        return AuthWorkflowVerdict(verdict_id, check, outcome, reason, confidence,
                                   tuple(dict.fromkeys(evidence)))


__all__ = [
    "AuthWorkflowOutcome", "AuthWorkflowVerdict", "OAuthClientPolicy",
    "OAuthFlowObservation", "OAuthTrustGraphAgent", "RecoveryObservation",
    "SessionInvalidationObservation",
]
