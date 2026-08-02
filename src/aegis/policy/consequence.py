"""Consequence tiers and action classification (Master Prompt §5).

Every planned action is classified into exactly one consequence tier *before*
it executes. Tiers are ordered by severity so that "when in doubt, assume the
higher tier" reduces to ``max(...)``.

This module is deliberately pure and dependency-free: it encodes policy, not
state. The engine (``aegis.policy.engine``) composes it with authorization,
scope, budget and the kill switch to produce a single decision.
"""

from __future__ import annotations

from enum import Enum, IntEnum


class ConsequenceTier(IntEnum):
    """Ordered severity tiers. Higher value == more dangerous.

    Ordering matters: ``max(tier_a, tier_b)`` implements the invariant
    "when in doubt about which tier applies, assume the higher tier."
    """

    PASSIVE = 1
    NON_INVASIVE_ACTIVE = 2
    STATE_CHANGING = 3
    SENSITIVE = 4
    PROHIBITED = 5

    @property
    def label(self) -> str:
        return _TIER_LABELS[self]


_TIER_LABELS: dict[ConsequenceTier, str] = {
    ConsequenceTier.PASSIVE: "passive",
    ConsequenceTier.NON_INVASIVE_ACTIVE: "non-invasive active",
    ConsequenceTier.STATE_CHANGING: "state-changing proof",
    ConsequenceTier.SENSITIVE: "sensitive proof",
    ConsequenceTier.PROHIBITED: "prohibited",
}


class TierPolicy(str, Enum):
    """Default approval policy attached to each tier (§5 table)."""

    AUTO_ALLOW = "auto_allow"
    AUTO_ALLOW_WITHIN_BUDGET = "auto_allow_within_budget"
    CUSTOMER_CONFIGURABLE_APPROVAL = "customer_configurable_approval"
    HUMAN_APPROVAL = "human_approval"
    NEVER = "never"


DEFAULT_TIER_POLICY: dict[ConsequenceTier, TierPolicy] = {
    ConsequenceTier.PASSIVE: TierPolicy.AUTO_ALLOW,
    ConsequenceTier.NON_INVASIVE_ACTIVE: TierPolicy.AUTO_ALLOW_WITHIN_BUDGET,
    ConsequenceTier.STATE_CHANGING: TierPolicy.CUSTOMER_CONFIGURABLE_APPROVAL,
    ConsequenceTier.SENSITIVE: TierPolicy.HUMAN_APPROVAL,
    ConsequenceTier.PROHIBITED: TierPolicy.NEVER,
}


# Canonical action vocabulary. These mirror the strings used in the
# authorization object's ``permitted_actions`` / ``prohibited_actions`` /
# ``approval_required_for`` lists (§4) so the two layers speak one language.
#
# Unknown / unmapped actions are intentionally NOT added here: the classifier
# treats anything it does not recognise as SENSITIVE (fail-closed), forcing an
# explicit human decision rather than silently guessing a low tier.
DEFAULT_ACTION_TIERS: dict[str, ConsequenceTier] = {
    # passive / OSINT
    "passive_discovery": ConsequenceTier.PASSIVE,
    "tech_fingerprint": ConsequenceTier.PASSIVE,
    "spec_ingestion": ConsequenceTier.PASSIVE,
    "source_analysis": ConsequenceTier.PASSIVE,
    # non-invasive active
    "authenticated_testing": ConsequenceTier.NON_INVASIVE_ACTIVE,
    "safe_reflection_test": ConsequenceTier.NON_INVASIVE_ACTIVE,
    "authz_comparison": ConsequenceTier.NON_INVASIVE_ACTIVE,
    "synthetic_data_access": ConsequenceTier.NON_INVASIVE_ACTIVE,
    "benign_request_mutation": ConsequenceTier.NON_INVASIVE_ACTIVE,
    # state-changing proof
    "safe_state_change": ConsequenceTier.STATE_CHANGING,
    "create_test_object": ConsequenceTier.STATE_CHANGING,
    "upload_benign_marker": ConsequenceTier.STATE_CHANGING,
    # sensitive proof
    "cross_tenant_proof": ConsequenceTier.SENSITIVE,
    "server_side_request_forgery": ConsequenceTier.SENSITIVE,
    "privilege_escalation": ConsequenceTier.SENSITIVE,
    "invoke_internal_function": ConsequenceTier.SENSITIVE,
    # prohibited — never executed
    "denial_of_service": ConsequenceTier.PROHIBITED,
    "persistence": ConsequenceTier.PROHIBITED,
    "production_data_exfiltration": ConsequenceTier.PROHIBITED,
    "third_party_targeting": ConsequenceTier.PROHIBITED,
    "credential_bruteforce": ConsequenceTier.PROHIBITED,
    "lateral_movement": ConsequenceTier.PROHIBITED,
    "log_tampering": ConsequenceTier.PROHIBITED,
}

# The tier assigned to actions with no known mapping. Fail closed: unknown
# capability is assumed dangerous enough to demand human sign-off.
UNKNOWN_ACTION_TIER = ConsequenceTier.SENSITIVE


class ConsequenceClassifier:
    """Maps an action name to a consequence tier, never downgrading.

    The final tier is the maximum of:
      * the classifier's own mapping (or ``UNKNOWN_ACTION_TIER`` if unknown),
      * an optional caller-supplied ``hint`` (a planner's self-assessment).

    A caller can never talk the classifier *down* to a gentler tier — only the
    more severe of the two views wins.
    """

    def __init__(
        self,
        action_tiers: dict[str, ConsequenceTier] | None = None,
        unknown_tier: ConsequenceTier = UNKNOWN_ACTION_TIER,
    ) -> None:
        self._action_tiers = dict(DEFAULT_ACTION_TIERS if action_tiers is None else action_tiers)
        self._unknown_tier = unknown_tier

    def is_known(self, action: str) -> bool:
        return action in self._action_tiers

    def classify(
        self,
        action: str,
        hint: ConsequenceTier | None = None,
    ) -> ConsequenceTier:
        base = self._action_tiers.get(action, self._unknown_tier)
        if hint is None:
            return base
        return max(base, hint)

    def policy_for(self, tier: ConsequenceTier) -> TierPolicy:
        return DEFAULT_TIER_POLICY[tier]
