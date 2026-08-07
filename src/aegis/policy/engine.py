"""The policy engine — one gate, fail closed (Master Prompt §2–§5, §10, §13).

``PolicyEngine.authorize(request)`` composes every guard into a single
:class:`PolicyDecision`. Design rules:

* **Fail closed.** Any error, ambiguity, or missing input resolves to a
  blocking verdict, never to ALLOW.
* **Most-catastrophic first.** The kill switch and authorization validity are
  checked before anything else and short-circuit — you cannot evaluate scope or
  tier meaningfully without a valid grant.
* **Non-mutating.** ``authorize`` never spends budget. Call ``commit`` after an
  allowed action actually runs, so denied/queued actions cost nothing.
* **Defense in depth.** This mirrors the network/proxy scope enforcement; it is
  a second line, not the only one.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime

from .authorization import Authorization, AuthorizationValidator, Environment
from .budget import RateBudget, SpendBudget
from .consequence import ConsequenceClassifier, ConsequenceTier, TierPolicy
from .decisions import (
    INCIDENT_FOR_REASON,
    ActionRequest,
    PolicyDecision,
    Reason,
    ReasonCode,
    Verdict,
)
from .killswitch import KillSwitch
from .scope import ScopeGuard
from .signing import SignatureVerifier

logger = logging.getLogger("aegis.policy")

AuditSink = Callable[[PolicyDecision], None]


def _default_audit(decision: PolicyDecision) -> None:
    logger.info("policy_decision %s", decision.as_dict())


@dataclass
class PolicyConfig:
    """Customer-configurable knobs that never loosen a hard invariant."""

    require_signature: bool = True
    # Tiers whose approval the customer has pre-granted in configuration.
    # Only STATE_CHANGING may be auto-approved this way; SENSITIVE always needs
    # a per-request human token, and PROHIBITED is never executed.
    auto_approve_tiers: frozenset[ConsequenceTier] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        forbidden = self.auto_approve_tiers & {
            ConsequenceTier.SENSITIVE,
            ConsequenceTier.PROHIBITED,
        }
        if forbidden:
            raise ValueError(
                "auto_approve_tiers may not include SENSITIVE or PROHIBITED tiers"
            )


def approval_token_for_tier(tier: ConsequenceTier) -> str:
    return f"tier:{tier.name}"


class PolicyEngine:
    def __init__(
        self,
        *,
        authorization: Authorization | None,
        scope: ScopeGuard | None = None,
        kill_switch: KillSwitch | None = None,
        rate_budget: RateBudget | None = None,
        spend_budget: SpendBudget | None = None,
        classifier: ConsequenceClassifier | None = None,
        verifier: SignatureVerifier | None = None,
        config: PolicyConfig | None = None,
        audit: AuditSink | None = None,
    ) -> None:
        self.authorization = authorization
        self.config = config or PolicyConfig()
        self.classifier = classifier or ConsequenceClassifier()
        self.kill_switch = kill_switch or KillSwitch()
        self._validator = AuthorizationValidator(
            verifier=verifier, require_signature=self.config.require_signature
        )
        self._audit = audit or _default_audit

        # Scope: prefer an explicit allowlist (the network layer's truth). Fall
        # back to the authorization's targets if none is supplied.
        if scope is not None:
            self.scope = scope
        elif authorization is not None:
            self.scope = ScopeGuard.from_authorization(authorization.targets)
        else:
            self.scope = ScopeGuard()

        # Budgets: derive rate limits from the authorization if not supplied.
        if rate_budget is not None:
            self.rate_budget = rate_budget
        elif authorization is not None:
            self.rate_budget = RateBudget(
                authorization.rate_limits.requests_per_second,
                authorization.rate_limits.max_concurrent_sessions,
            )
        else:
            self.rate_budget = None

        if spend_budget is not None:
            self.spend_budget = spend_budget
        elif authorization is not None and authorization.spend_budget is not None:
            self.spend_budget = SpendBudget(authorization.spend_budget)
        else:
            self.spend_budget = None

    # -- public API ---------------------------------------------------------

    def authorize(
        self, request: ActionRequest, now: datetime | None = None, *, record: bool = True
    ) -> PolicyDecision:
        """Evaluate a request and return a decision.

        Set ``record=False`` for a dry-run (e.g. computing which approvals an
        action would require) so the evaluation is not written to the audit
        sink. The evaluation is non-mutating either way.
        """
        now = now or datetime.now(UTC)
        try:
            decision = self._evaluate(request, now)
        except Exception as exc:  # fail closed on any unexpected error
            logger.exception("policy engine error; failing closed")
            decision = self._finalize(
                request,
                tier=None,
                reasons=[
                    Reason(
                        ReasonCode.AUTHORIZATION_MALFORMED,
                        f"internal policy error: {exc!r}",
                        Verdict.ESCALATE,
                    )
                ],
                required_approvals=[],
            )
        if record:
            self._audit(decision)
        return decision

    def commit(
        self,
        decision: PolicyDecision,
        request: ActionRequest | None = None,
        now: datetime | None = None,
    ) -> None:
        """Record budget consumption for an allowed action that actually ran.

        Pass the originating ``request`` to also debit its ``estimated_cost``
        from the spend budget.
        """
        if not decision.allowed:
            raise ValueError("cannot commit a non-allowed decision")
        now = now or datetime.now(UTC)
        if self.rate_budget is not None:
            self.rate_budget.consume_rate(now.timestamp())
        if request is not None and self.spend_budget is not None and request.estimated_cost:
            self.spend_budget.record(request.estimated_cost)

    # -- evaluation ---------------------------------------------------------

    def _evaluate(self, request: ActionRequest, now: datetime) -> PolicyDecision:
        # Gate 1: kill switch — overrides everything (§8, §13).
        if self.kill_switch.is_active:
            state = self.kill_switch.state
            return self._finalize(
                request,
                tier=None,
                reasons=[
                    Reason(
                        ReasonCode.KILL_SWITCH_ACTIVE,
                        f"kill switch active: {state.reason}",
                        Verdict.DENY,
                    )
                ],
                required_approvals=[],
            )

        # Gate 2: authorization validity — missing/expired/forged => stop (§4, §10).
        auth = self.authorization
        auth_reasons = self._validator.validate(auth, now)
        if auth_reasons:
            return self._finalize(request, tier=None, reasons=auth_reasons, required_approvals=[])

        assert auth is not None  # validate() guarantees a non-None auth here

        reasons: list[Reason] = []
        required_approvals: list[str] = []

        # Gate 3: scope — the target must be in BOTH the network allowlist mirror
        # and the authorization's targets. Anything else is a SCOPE_ESCAPE (§2).
        scope_result = self.scope.evaluate(request.target)
        host = scope_result.host or request.target
        in_auth_targets = auth.covers_target(host)
        if not scope_result.in_scope or not in_auth_targets:
            reasons.append(
                Reason(
                    ReasonCode.TARGET_OUT_OF_SCOPE,
                    f"target {request.target!r} ({host}) is not in the approved allowlist",
                    Verdict.DENY,
                )
            )
            # Out-of-scope is terminal; no point classifying the action.
            return self._finalize(request, tier=None, reasons=reasons, required_approvals=[])

        # Classify the consequence tier (never downgraded below the mapping).
        tier = self.classifier.classify(request.action, request.tier_hint)
        if not self.classifier.is_known(request.action):
            reasons.append(
                Reason(
                    ReasonCode.UNKNOWN_ACTION,
                    f"action {request.action!r} is unknown; treated as {tier.label}",
                    Verdict.REQUIRE_APPROVAL,
                )
            )

        # Gate 4: prohibition — prohibited action OR prohibited tier => never (§5).
        if auth.prohibits(request.action) or tier == ConsequenceTier.PROHIBITED:
            reasons.append(
                Reason(
                    ReasonCode.ACTION_PROHIBITED,
                    f"action {request.action!r} is prohibited and will never execute",
                    Verdict.DENY,
                )
            )
            return self._finalize(request, tier=tier, reasons=reasons, required_approvals=[])

        # Gate 5: the action must be explicitly permitted (§4). Passive recon
        # still needs e.g. "passive_discovery" listed in permitted_actions.
        if not auth.permits(request.action):
            reasons.append(
                Reason(
                    ReasonCode.ACTION_NOT_PERMITTED,
                    f"action {request.action!r} is not in permitted_actions",
                    Verdict.DENY,
                )
            )
            return self._finalize(request, tier=tier, reasons=reasons, required_approvals=[])

        # Gate 6: environment — production access needs approved-production (§4).
        if request.touches_production and auth.environment != Environment.APPROVED_PRODUCTION:
            reasons.append(
                Reason(
                    ReasonCode.ENVIRONMENT_MISMATCH,
                    "action touches production but environment is not approved-production",
                    Verdict.ESCALATE,
                )
            )

        # Gate 7: approvals — derive the tokens this action needs, then check
        # whether they were supplied on the request.
        needed = self._required_approvals(auth, request.action, tier)
        missing = sorted(needed - set(request.approvals))
        if missing:
            required_approvals.extend(missing)
            reasons.append(
                Reason(
                    ReasonCode.APPROVAL_REQUIRED,
                    f"action requires approval: {', '.join(missing)}",
                    Verdict.REQUIRE_APPROVAL,
                )
            )

        # Gate 8: budget — rate, concurrency, spend (non-mutating checks).
        if self.rate_budget is not None:
            if not self.rate_budget.check_rate(now.timestamp()):
                reasons.append(
                    Reason(
                        ReasonCode.RATE_BUDGET_EXCEEDED,
                        "request-per-second budget exhausted",
                        Verdict.DENY,
                    )
                )
            if not self.rate_budget.has_session_capacity():
                reasons.append(
                    Reason(
                        ReasonCode.CONCURRENCY_EXCEEDED,
                        "no concurrent-session capacity remaining",
                        Verdict.DENY,
                    )
                )
        if self.spend_budget is not None and not self.spend_budget.check(request.estimated_cost):
            reasons.append(
                Reason(
                    ReasonCode.SPEND_BUDGET_EXCEEDED,
                    "spend budget would be exceeded",
                    Verdict.DENY,
                )
            )

        if not reasons:
            reasons.append(Reason(ReasonCode.OK, "all policy gates passed", Verdict.ALLOW))

        return self._finalize(request, tier=tier, reasons=reasons, required_approvals=required_approvals)

    def _required_approvals(
        self, auth: Authorization, action: str, tier: ConsequenceTier
    ) -> set[str]:
        needed: set[str] = set()
        # Per-action approvals declared in the authorization (§4).
        if auth.requires_approval(action):
            needed.add(action)
        # Tier-driven approvals (§5).
        policy = self.classifier.policy_for(tier)
        if policy == TierPolicy.HUMAN_APPROVAL:
            needed.add(approval_token_for_tier(tier))
        elif policy == TierPolicy.CUSTOMER_CONFIGURABLE_APPROVAL:
            if tier not in self.config.auto_approve_tiers:
                needed.add(approval_token_for_tier(tier))
        return needed

    def _finalize(
        self,
        request: ActionRequest,
        *,
        tier: ConsequenceTier | None,
        reasons: list[Reason],
        required_approvals: list[str],
    ) -> PolicyDecision:
        verdict = max((r.verdict for r in reasons), key=lambda v: v.severity, default=Verdict.ALLOW)
        incidents = sorted(
            {
                INCIDENT_FOR_REASON[r.code]
                for r in reasons
                if r.code in INCIDENT_FOR_REASON and r.verdict.is_blocking
            }
        )
        return PolicyDecision(
            verdict=verdict,
            tier=tier,
            reasons=reasons,
            required_approvals=required_approvals,
            incidents=incidents,
            request_id=request.request_id,
            authorization_id=self.authorization.authorization_id if self.authorization else None,
            target=request.target,
            action=request.action,
        )
